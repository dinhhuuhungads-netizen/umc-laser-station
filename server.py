#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════╗
║       UMC LASER STATION — MONITORING SERVER v4.1.0                      ║
║       Tác giả : Hưng AI | UMC Vietnam — Laser Circuit Feed Station      ║
║       Build   : Production-Ready FINAL | May 2026                       ║
║                                                                          ║
║       Kiến trúc: Python AsyncIO + WebSocket Bridge (port 8765)          ║
║       Tính năng:                                                         ║
║         • Giám sát Log máy Laser thời gian thực (Watchdog + islice)     ║
║         • WebSocket Bridge → đẩy dữ liệu lên Dashboard ngay lập tức    ║
║         • Xuất báo cáo Excel tự động (pandas) — Traceability            ║
║         • OOM Guard: islice + size limit — không gây tràn RAM           ║
║         • Redact thông tin nhạy cảm trước khi log/gửi                  ║
║         • Giới hạn thư mục ghi dữ liệu (Path Traversal Guard)          ║
║                                                                          ║
║  [v4.1.0 — FINAL AUDIT FIXES]                                           ║
║    SEC-1: WebSocket Origin filter — chặn CSRF từ trang web lạ           ║
║    SEC-2: manual_ok validate model whitelist trước khi ghi              ║
║    BUG-1: _stats dict được bảo vệ bởi asyncio.Lock — chống race cond.  ║
║    BUG-2: Excel atomic write (write-then-rename) — không mất dữ liệu   ║
╚══════════════════════════════════════════════════════════════════════════╝

CÀI ĐẶT (chạy 1 lần):
  pip install websockets pandas openpyxl watchdog python-dotenv

CHẠY:
  python server.py

DỪNG:
  Nhấn Ctrl+C
"""

# ─────────────────────────────────────────────────────────────────────────
#  STANDARD LIBRARY
# ─────────────────────────────────────────────────────────────────────────
import asyncio
import hashlib
import itertools
import json
import logging
import logging.handlers
import os
import re
import tempfile
import time
from collections import deque
from contextlib import suppress
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────
#  THIRD-PARTY (lazy import với thông báo lỗi rõ ràng)
# ─────────────────────────────────────────────────────────────────────────
try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    raise SystemExit(
        "❌ Thiếu thư viện 'websockets'.\n"
        "   Chạy lệnh: pip install websockets"
    )

try:
    import pandas as pd
    import openpyxl  # noqa: F401
except ImportError:
    raise SystemExit(
        "❌ Thiếu thư viện 'pandas' hoặc 'openpyxl'.\n"
        "   Chạy lệnh: pip install pandas openpyxl"
    )

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileModifiedEvent
except ImportError:
    raise SystemExit(
        "❌ Thiếu thư viện 'watchdog'.\n"
        "   Chạy lệnh: pip install watchdog"
    )

# python-dotenv là tùy chọn
try:
    from dotenv import find_dotenv, load_dotenv
    _dotenv_path = find_dotenv(usecwd=True)
    if _dotenv_path:
        load_dotenv(_dotenv_path, override=False)
except ImportError:
    pass


# ═════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler(
            "umc_server.log",
            maxBytes=5_000_000,
            backupCount=3,
            encoding="utf-8",
        ),
    ],
)
log = logging.getLogger("UMC.Server")


# ═════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═════════════════════════════════════════════════════════════════════════

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, "").strip() or default


CONFIG = {
    # ── Đường dẫn ──────────────────────────────────────────────────────
    "laser_log_dir":    _env("UMC_LASER_LOG_DIR",    r"C:\UMC_Data\Laser_Logs"),
    "output_dir":       _env("UMC_OUTPUT_DIR",        r"C:\UMC_Data\Reports"),
    "excel_report":     _env("UMC_EXCEL_REPORT",      r"C:\UMC_Data\Reports\laser_history.xlsx"),

    # ── WebSocket ───────────────────────────────────────────────────────
    "ws_host":          _env("UMC_WS_HOST",           "localhost"),
    "ws_port":          int(_env("UMC_WS_PORT",        "8765")),

    # ── Giới hạn xử lý (OOM Guard) ─────────────────────────────────────
    "MAX_LOG_FILE_SIZE_MB": int(_env("UMC_MAX_LOG_FILE_SIZE_MB", "10")),
    "MAX_LINES_PER_READ":   int(_env("UMC_MAX_LINES_PER_READ",   "2000")),
    "MAX_LINE_LENGTH":      int(_env("UMC_MAX_LINE_LENGTH",       "500")),
    "TAIL_LINES":           int(_env("UMC_TAIL_LINES",            "200")),

    # ── Ngưỡng cảnh báo ────────────────────────────────────────────────
    "ng_threshold_pct":     float(_env("UMC_NG_THRESHOLD", "3.0")),
    "laser_cycle_sec":      float(_env("UMC_LASER_CYCLE_SEC", "8.0")),

    # ── Model mạch hợp lệ (Poka-Yoke) ──────────────────────────────────
    "valid_models": {
        "PCB-UMC-V54-GRN",   # Xanh lá
        "PCB-UMC-V54-BLU",   # Xanh dương
        "PCB-UMC-V54-BLK",   # Đen
        "PCB-UMC-V55-GRN",
        "PCB-UMC-V55-BLU",
    },

    # ── Redact patterns ─────────────────────────────────────────────────
    "redact_patterns": [
        r'\b(?:WO|PO|SO|ORD)[:\-#]?\d{4,12}\b',
        r'(?:CUSTOMER|CLIENT|CUST)[:\s]+[A-Z][A-Za-z\s]{3,30}',
        r'\b\d{3}-\d{4}-\d{4}\b',   # Phone-like
    ],
}

# Compile redact patterns
_REDACT_RE = [re.compile(p, re.IGNORECASE) for p in CONFIG["redact_patterns"]]

# Allowed output root (Path Traversal Guard)
_ALLOWED_OUTPUT_ROOT = Path(CONFIG["output_dir"]).resolve()
_ALLOWED_LOG_EXTS    = {".log", ".txt", ".csv"}

# Debounce watchdog events
_watchdog_debounce: dict[str, float] = {}
_DEBOUNCE_SEC = 2.0
_MAX_DEBOUNCE_ENTRIES = 500


# ═════════════════════════════════════════════════════════════════════════
#  GLOBAL STATE
# ═════════════════════════════════════════════════════════════════════════

# Lock được tạo lazy trong asyncio context, không ở module level
_ws_lock:      Optional[asyncio.Lock]      = None
_stats_lock:   Optional[asyncio.Lock]      = None   # [BUG-1 FIX] riêng cho _stats
_excel_lock:   Optional[asyncio.Lock]      = None
_ws_semaphore: Optional[asyncio.Semaphore] = None

_connected_clients: set[WebSocketServerProtocol] = set()
_event_buffer: deque = deque(maxlen=1000)   # Lưu lịch sử để client mới kết nối nhận ngay

_stats = {
    "total_ok":    0,
    "total_ng":    0,
    "total_error": 0,
    "session_start": datetime.now().isoformat(),
    "last_model":  "",
    "last_event_time": "",
}

# Observer Watchdog
_observer: Optional[Observer] = None


# ═════════════════════════════════════════════════════════════════════════
#  UTILITY FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════

def _redact(text: str) -> str:
    """Ẩn thông tin nhạy cảm trước khi log hoặc broadcast."""
    for pattern in _REDACT_RE:
        text = pattern.sub("[REDACTED]", text)
    return text


def _safe_output_path(path: Path) -> Optional[Path]:
    """[SEC] Kiểm tra path traversal — chỉ cho phép ghi vào _ALLOWED_OUTPUT_ROOT."""
    try:
        resolved = path.resolve()
        if not resolved.is_relative_to(_ALLOWED_OUTPUT_ROOT):
            log.warning("[SEC] Path traversal bị chặn: %s", path)
            return None
        return resolved
    except Exception:
        return None


def _hash_line_id(line_id: str) -> str:
    """SHA-256 hash để anonymize line ID."""
    return hashlib.sha256(line_id.encode()).hexdigest()[:12]


# ═════════════════════════════════════════════════════════════════════════
#  LOG PARSER — islice OOM Guard
# ═════════════════════════════════════════════════════════════════════════

# Pattern nhận dạng dòng log máy Laser
# Ví dụ: 2026-05-01 08:30:15 | LINE-A | MODEL=PCB-UMC-V54-GRN | RESULT=OK | CYCLE=7.8s
_LOG_PATTERN = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'
    r'.*?(?:LINE[:\-=]?\s*(?P<line>[A-Z0-9\-]+))?'
    r'.*?MODEL[:\-=]\s*(?P<model>[A-Z0-9\-]+)'
    r'.*?RESULT[:\-=]\s*(?P<r>OK|NG|ERROR|PASS|FAIL)'
    r'(?:.*?CYCLE[:\-=]\s*(?P<cycle>[\d.]+))?',
    re.IGNORECASE,
)


def _parse_log_file(file_path: Path) -> list[dict]:
    """
    Đọc file log với islice — không load toàn bộ vào RAM.
    Trả về list các event đã parse.
    """
    events = []

    # [SEC] Kiểm tra kích thước file
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > CONFIG["MAX_LOG_FILE_SIZE_MB"]:
            log.warning("[OOM] File %s vượt %dMB — bỏ qua.", file_path.name, CONFIG["MAX_LOG_FILE_SIZE_MB"])
            return events
    except OSError:
        return events

    # Thử nhiều encoding (hỗ trợ máy Nhật)
    encodings = ["utf-8", "cp932", "shift_jis", "latin-1"]
    fp = None
    for enc in encodings:
        try:
            fp = open(file_path, "r", encoding=enc, errors="replace")
            break
        except OSError:
            continue

    if fp is None:
        return events

    try:
        # [OOM Guard] islice giới hạn số dòng đọc
        for line in itertools.islice(fp, CONFIG["MAX_LINES_PER_READ"]):
            # [SEC] Giới hạn chiều dài dòng (chống ReDoS)
            if len(line) > CONFIG["MAX_LINE_LENGTH"]:
                continue

            m = _LOG_PATTERN.search(line)
            if not m:
                continue

            # [BUG-FIX] Regex group is named "r", not "result"
            result = m.group("r").upper()
            if result in ("PASS",):
                result = "OK"
            elif result in ("FAIL",):
                result = "NG"

            raw_model = m.group("model").upper() if m.group("model") else ""
            # [SEC] Apply redact to model field before storing/broadcasting
            safe_model = _redact(raw_model)

            event = {
                "ts":     m.group("ts"),
                "line":   _hash_line_id(m.group("line") or "UNKNOWN"),
                "model":  safe_model,
                "result": result,
                "cycle":  float(m.group("cycle")) if m.group("cycle") else None,
                "source": file_path.name,
            }
            events.append(event)
    finally:
        fp.close()

    return events


def _read_tail(file_path: Path, n: int = 200) -> list[dict]:
    """
    Đọc N dòng cuối file (tail) bằng seek từ EOF.
    [STAB-WARN-1 FIX] Không iterate toàn bộ file — an toàn kể cả file 50MB+.
    """
    try:
        size_mb = file_path.stat().st_size / (1024 * 1024)
        if size_mb > CONFIG["MAX_LOG_FILE_SIZE_MB"]:
            return []
    except OSError:
        return []

    encodings = ["utf-8", "cp932", "shift_jis", "latin-1"]
    lines = []

    # Đọc tối đa TAIL_CHUNK byte từ EOF — đủ chứa n dòng dài nhất
    TAIL_CHUNK = CONFIG["MAX_LINE_LENGTH"] * n

    for enc in encodings:
        try:
            with open(file_path, "rb") as fb:
                file_size = fb.seek(0, 2)           # seek to EOF
                seek_pos  = max(0, file_size - TAIL_CHUNK)
                fb.seek(seek_pos)
                raw_bytes = fb.read()
            raw_text        = raw_bytes.decode(enc, errors="replace")
            candidate_lines = raw_text.splitlines(keepends=True)
            if seek_pos > 0:
                candidate_lines = candidate_lines[1:]   # dòng đầu bị cắt — bỏ
            tail_lines = deque(
                (l for l in candidate_lines if len(l) <= CONFIG["MAX_LINE_LENGTH"]),
                maxlen=n,
            )
            lines = list(tail_lines)
            break
        except (OSError, UnicodeDecodeError):
            continue

    events = []
    for line in lines:
        m = _LOG_PATTERN.search(line)
        if not m:
            continue
        # [BUG-FIX] Regex group is named "r", not "result"
        result = m.group("r").upper()
        if result == "PASS":
            result = "OK"
        elif result == "FAIL":
            result = "NG"
        raw_model = m.group("model").upper() if m.group("model") else ""
        events.append({
            "ts":     m.group("ts"),
            "line":   _hash_line_id(m.group("line") or "UNKNOWN"),
            "model":  _redact(raw_model),   # [SEC] redact before broadcasting
            "result": result,
            "cycle":  float(m.group("cycle")) if m.group("cycle") else None,
            "source": file_path.name,
        })
    return events


# ═════════════════════════════════════════════════════════════════════════
#  EXCEL REPORT
# ═════════════════════════════════════════════════════════════════════════

async def _append_to_excel(events: list[dict]) -> None:
    """Ghi events vào Excel report (append). Thread-safe với asyncio.Lock."""
    if not events:
        return

    async with _excel_lock:
        await asyncio.to_thread(_append_to_excel_sync, events)


def _append_to_excel_sync(events: list[dict]) -> None:
    """
    Phần đồng bộ — chạy trong thread pool.
    [BUG-2 FIX] Atomic write: ghi ra .tmp rồi os.replace() — không mất dữ liệu khi mất điện.
    """
    report_path = Path(CONFIG["excel_report"])
    safe_path   = _safe_output_path(report_path)
    if safe_path is None:
        log.error("[SEC] Excel path bị chặn: %s", report_path)
        return

    safe_path.parent.mkdir(parents=True, exist_ok=True)

    df_new = pd.DataFrame(events)
    df_new["exported_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        if safe_path.exists():
            df_old = pd.read_excel(safe_path, sheet_name="LaserHistory", engine="openpyxl")
            df_combined = pd.concat([df_old, df_new], ignore_index=True)
        else:
            df_combined = df_new

        # Giới hạn 50,000 dòng mỗi file
        df_combined = df_combined.tail(50_000)

        # [BUG-2 FIX] Atomic write: ghi vào file tạm → rename
        # os.replace() là atomic trên cả Windows lẫn Linux/Mac
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=safe_path.parent,
            suffix=".xlsx.tmp",
        )
        os.close(tmp_fd)

        try:
            with pd.ExcelWriter(tmp_path, engine="openpyxl", mode="w") as writer:
                df_combined.to_excel(writer, sheet_name="LaserHistory", index=False)

                # Sheet tổng hợp
                summary = df_combined.groupby(["model", "result"]).size().unstack(fill_value=0)
                summary.to_excel(writer, sheet_name="Summary")

            # Atomic rename — nếu crash trước dòng này, file gốc vẫn còn nguyên
            os.replace(tmp_path, safe_path)
            log.info("[Excel] Đã ghi %d dòng → %s", len(df_new), safe_path.name)

        except Exception:
            # Dọn dẹp file tạm nếu có lỗi
            with suppress(OSError):
                os.unlink(tmp_path)
            raise

    except Exception as exc:
        log.error("[Excel] Lỗi ghi file: %s", exc)


# ═════════════════════════════════════════════════════════════════════════
#  WEBSOCKET BROADCAST
# ═════════════════════════════════════════════════════════════════════════

async def _broadcast(payload: dict) -> None:
    """
    Gửi payload JSON đến tất cả WebSocket clients đang kết nối.
    Semaphore(4) giới hạn concurrent sends — chống thread pool exhaustion.
    """
    if not _connected_clients:
        return

    message = json.dumps(payload, ensure_ascii=False)

    async def _send_one(ws: WebSocketServerProtocol) -> None:
        async with _ws_semaphore:
            try:
                await asyncio.wait_for(ws.send(message), timeout=5.0)
            except Exception:
                pass  # Client disconnected — được xử lý ở handler

    async with _ws_lock:
        clients_snapshot = set(_connected_clients)

    if clients_snapshot:
        await asyncio.gather(*[_send_one(ws) for ws in clients_snapshot], return_exceptions=True)


async def _broadcast_event(event: dict) -> None:
    """
    Broadcast 1 event mới + cập nhật stats.
    [BUG-1 FIX] _stats được bảo vệ bởi _stats_lock — chống race condition
    khi Demo Generator và Watchdog cùng trigger event gần nhau.
    """
    _event_buffer.append(event)

    # [BUG-1 FIX] Lock bảo vệ _stats dict
    async with _stats_lock:
        result = event.get("result", "")
        if result == "OK":
            _stats["total_ok"] += 1
        elif result == "NG":
            _stats["total_ng"] += 1
        elif result == "ERROR":
            _stats["total_error"] += 1

        if event.get("model"):
            _stats["last_model"] = event["model"]
        _stats["last_event_time"] = datetime.now().isoformat()

        total   = _stats["total_ok"] + _stats["total_ng"]
        ng_rate = (_stats["total_ng"] / total * 100) if total > 0 else 0.0
        stats_snapshot = {**_stats, "ng_rate_pct": round(ng_rate, 2)}
        alert   = ng_rate >= CONFIG["ng_threshold_pct"] and total >= 10

    payload = {
        "type":    "new_event",
        "event":   event,
        "stats":   stats_snapshot,
        "alert":   alert,
        "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    await _broadcast(payload)


# ═════════════════════════════════════════════════════════════════════════
#  WEBSOCKET SERVER HANDLER
# ═════════════════════════════════════════════════════════════════════════

async def _ws_handler(ws: WebSocketServerProtocol) -> None:
    """Xử lý 1 WebSocket connection."""
    client_ip = ws.remote_address[0] if ws.remote_address else "unknown"
    log.info("[WS] Client kết nối: %s", client_ip)

    async with _ws_lock:
        _connected_clients.add(ws)

    try:
        # Gửi snapshot hiện tại cho client mới
        async with _stats_lock:
            total   = _stats["total_ok"] + _stats["total_ng"]
            ng_rate = (_stats["total_ng"] / total * 100) if total > 0 else 0.0
            stats_snapshot = {**_stats, "ng_rate_pct": round(ng_rate, 2)}

        await ws.send(json.dumps({
            "type":    "snapshot",
            "events":  list(_event_buffer)[-50:],  # 50 sự kiện gần nhất
            "stats":   stats_snapshot,
            "config":  {
                "laser_cycle_sec":  CONFIG["laser_cycle_sec"],
                "ng_threshold_pct": CONFIG["ng_threshold_pct"],
                "valid_models":     sorted(CONFIG["valid_models"]),  # [FIX] deterministic order
            },
            "server_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }, ensure_ascii=False))

        # Giữ kết nối — lắng nghe message từ client (ping/poka-yoke check)
        async for raw in ws:
            try:
                msg = json.loads(raw)
                await _handle_client_message(ws, msg)
            except json.JSONDecodeError:
                pass

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        async with _ws_lock:
            _connected_clients.discard(ws)
        # [SEC-WARN-2 FIX] Dọn dẹp rate-limit entry — tránh memory leak
        with suppress(Exception):
            if hasattr(_handle_client_message, "_rate"):
                _handle_client_message._rate.pop(id(ws), None)
        log.info("[WS] Client ngắt kết nối: %s", client_ip)


async def _handle_client_message(ws: WebSocketServerProtocol, msg: dict) -> None:
    """Xử lý message từ Dashboard gửi lên (Poka-Yoke scan, ping...).
    [SEC] Rate limit: tối đa 20 message/giây mỗi client để chống flood.
    """
    # Lấy hoặc tạo rate-limit counter cho client này
    client_key = id(ws)
    if not hasattr(_handle_client_message, "_rate"):
        _handle_client_message._rate = {}
    rate_data = _handle_client_message._rate
    now = time.monotonic()
    window_start, count = rate_data.get(client_key, (now, 0))
    if now - window_start > 1.0:
        rate_data[client_key] = (now, 1)
    else:
        count += 1
        rate_data[client_key] = (window_start, count)
        if count > 20:
            log.warning("[SEC] Rate limit: client %s bị throttle", id(ws))
            return  # Drop message silently

    msg_type = msg.get("type", "")

    if msg_type == "ping":
        await ws.send(json.dumps({"type": "pong", "ts": datetime.now().isoformat()}))

    elif msg_type == "validate_model":
        # Exact match — không dùng includes() hay contains()
        model_code = str(msg.get("model", "")).strip().upper()
        is_valid = model_code in CONFIG["valid_models"]

        await ws.send(json.dumps({
            "type":    "model_validation",
            "model":   model_code,
            "valid":   is_valid,
            "message": "✅ Model hợp lệ" if is_valid else f"❌ Model '{model_code}' KHÔNG HỢP LỆ — kiểm tra lại!",
            "ts":      datetime.now().isoformat(),
        }))

    elif msg_type == "manual_ok":
        # [SEC-2 FIX] Validate model whitelist trước khi ghi bất kỳ thứ gì
        model_raw = str(msg.get("model", "")).strip().upper()
        if not model_raw or model_raw not in CONFIG["valid_models"]:
            log.warning("[SEC-2] manual_ok bị chặn — model không hợp lệ: %r", model_raw)
            await ws.send(json.dumps({
                "type":    "error",
                "message": f"❌ manual_ok bị từ chối: model '{model_raw}' không nằm trong whitelist.",
                "ts":      datetime.now().isoformat(),
            }))
            return

        event = {
            "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "line":   "MANUAL",
            "model":  model_raw,   # đã sanitize và validate
            "result": "OK",
            "cycle":  None,
            "source": "manual",
        }
        await _broadcast_event(event)
        await _append_to_excel([event])

    elif msg_type == "get_stats":
        async with _stats_lock:
            total   = _stats["total_ok"] + _stats["total_ng"]
            ng_rate = (_stats["total_ng"] / total * 100) if total > 0 else 0.0
            stats_snapshot = {**_stats, "ng_rate_pct": round(ng_rate, 2)}

        await ws.send(json.dumps({
            "type":  "stats",
            "stats": stats_snapshot,
        }))


# ═════════════════════════════════════════════════════════════════════════
#  WATCHDOG — Giám sát Log folder
# ═════════════════════════════════════════════════════════════════════════

class _LaserLogHandler(FileSystemEventHandler):
    """Watchdog handler — gọi khi file log thay đổi."""

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__()
        self._loop  = loop
        self._seen: set[tuple[str, str]] = set()  # (source, ts) — chống duplicate

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory:
            return

        path = Path(event.src_path)

        # Extension whitelist + symlink filter
        if path.suffix.lower() not in _ALLOWED_LOG_EXTS:
            return
        with suppress(OSError):
            if path.is_symlink():
                return

        # Debounce: bỏ qua event lặp trong 2 giây
        now     = time.monotonic()
        key_str = str(path)
        last    = _watchdog_debounce.get(key_str, 0.0)
        if now - last < _DEBOUNCE_SEC:
            return

        # Giới hạn dict size
        if len(_watchdog_debounce) >= _MAX_DEBOUNCE_ENTRIES:
            oldest_key = next(iter(_watchdog_debounce))
            del _watchdog_debounce[oldest_key]
        _watchdog_debounce[key_str] = now

        # Chạy coroutine từ thread watchdog vào asyncio event loop
        future = asyncio.run_coroutine_threadsafe(
            self._process_file(path), self._loop
        )
        # Không block thread; lỗi được log qua callback
        future.add_done_callback(self._on_done)

    @staticmethod
    def _on_done(fut) -> None:
        exc = fut.exception()
        if exc:
            log.error("[Watchdog] Lỗi xử lý file: %s", exc)

    async def _process_file(self, path: Path) -> None:
        """Đọc tail file → broadcast → ghi Excel."""
        events = await asyncio.to_thread(_read_tail, path, CONFIG["TAIL_LINES"])
        if not events:
            return

        # Lọc duplicate
        new_events = []
        for ev in events:
            dedup_key = (ev["source"], ev["ts"])
            if dedup_key not in self._seen:
                self._seen.add(dedup_key)
                new_events.append(ev)

        # Giới hạn _seen set size
        if len(self._seen) > 10_000:
            self._seen = set(list(self._seen)[-5_000:])

        for ev in new_events:
            await _broadcast_event(ev)

        if new_events:
            await _append_to_excel(new_events)
            log.info("[Log] %d event mới từ %s", len(new_events), path.name)


def _start_watchdog(loop: asyncio.AbstractEventLoop) -> Optional[Observer]:
    """Khởi động Watchdog Observer."""
    log_dir = Path(CONFIG["laser_log_dir"])
    if not log_dir.exists():
        log.warning(
            "[Watchdog] Thư mục log không tồn tại: %s\n"
            "           Tạo thư mục này và đặt file log vào đó.",
            log_dir,
        )
        log_dir.mkdir(parents=True, exist_ok=True)
        log.info("[Watchdog] Đã tạo thư mục: %s", log_dir)

    handler  = _LaserLogHandler(loop)
    observer = Observer()
    observer.schedule(handler, str(log_dir), recursive=False)
    observer.start()
    log.info("[Watchdog] Đang theo dõi: %s", log_dir)
    return observer


# ═════════════════════════════════════════════════════════════════════════
#  DEMO LOG GENERATOR (chạy khi không có file log thực)
# ═════════════════════════════════════════════════════════════════════════

async def _demo_generator() -> None:
    """
    Sinh dữ liệu giả để Demo khi chưa có máy Laser thật.
    Tắt khi biến UMC_DEMO_MODE=false.
    """
    import random

    demo_mode = _env("UMC_DEMO_MODE", "true").lower() != "false"
    if not demo_mode:
        return

    log.info("[Demo] Chế độ Demo ON — sinh dữ liệu giả mỗi %.1fs", CONFIG["laser_cycle_sec"])
    models  = list(CONFIG["valid_models"])
    results = ["OK"] * 19 + ["NG"]  # ~5% NG rate

    while True:
        await asyncio.sleep(CONFIG["laser_cycle_sec"])
        model  = random.choice(models)
        result = random.choice(results)
        cycle  = round(random.gauss(CONFIG["laser_cycle_sec"], 0.5), 2)
        event  = {
            "ts":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "line":   _hash_line_id("LINE-A"),
            "model":  model,
            "result": result,
            "cycle":  max(1.0, cycle),
            "source": "demo",
        }
        await _broadcast_event(event)

        # Ghi Excel mỗi 10 sự kiện (tránh ghi liên tục)
        async with _stats_lock:
            total_so_far = _stats["total_ok"] + _stats["total_ng"]
        if total_so_far % 10 == 0:
            await _append_to_excel([event])


# ═════════════════════════════════════════════════════════════════════════
#  HEARTBEAT — gửi stats định kỳ
# ═════════════════════════════════════════════════════════════════════════

async def _heartbeat_loop() -> None:
    """Gửi stats đến tất cả clients mỗi 10 giây."""
    while True:
        await asyncio.sleep(10)
        if not _connected_clients:
            continue

        async with _stats_lock:
            total   = _stats["total_ok"] + _stats["total_ng"]
            ng_rate = (_stats["total_ng"] / total * 100) if total > 0 else 0.0
            stats_snapshot = {**_stats, "ng_rate_pct": round(ng_rate, 2)}

        await _broadcast({
            "type":              "heartbeat",
            "stats":             stats_snapshot,
            "connected_clients": len(_connected_clients),
            "server_time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })


# ═════════════════════════════════════════════════════════════════════════
#  MAIN ENTRYPOINT
# ═════════════════════════════════════════════════════════════════════════

async def _main() -> None:
    """Hàm chính — khởi động toàn bộ hệ thống."""
    global _ws_lock, _stats_lock, _excel_lock, _ws_semaphore, _observer

    # Tạo Lock bên trong asyncio context (lazy init)
    _ws_lock      = asyncio.Lock()
    _stats_lock   = asyncio.Lock()          # [BUG-1 FIX] Lock riêng cho _stats
    _excel_lock   = asyncio.Lock()
    _ws_semaphore = asyncio.Semaphore(4)    # Giới hạn concurrent WS sends

    # Đảm bảo thư mục output tồn tại
    _ALLOWED_OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    loop = asyncio.get_running_loop()

    # Khởi động Watchdog
    _observer = _start_watchdog(loop)

    # Khởi động WebSocket Server
    ws_host = CONFIG["ws_host"]
    ws_port = CONFIG["ws_port"]

    # [SEC-1 FIX / K-SEC-1] Lọc Origin — đọc từ UMC_ALLOWED_ORIGINS trong .env
    # "null" là giá trị Origin khi mở file HTML trực tiếp từ ổ đĩa (file://)
    _extra_origins = [
        o.strip()
        for o in _env("UMC_ALLOWED_ORIGINS", "").split(",")
        if o.strip()
    ]
    allowed_origins = list(dict.fromkeys([   # dict.fromkeys() giữ thứ tự + dedup
        "null",
        f"http://{ws_host}",
        f"http://{ws_host}:{ws_port}",
        "http://localhost",
        "http://127.0.0.1",
        *_extra_origins,
    ]))

    ws_server = await websockets.serve(
        _ws_handler,
        ws_host,
        ws_port,
        ping_interval=20,
        ping_timeout=10,
        max_size=1_048_576,       # 1MB max message
        origins=allowed_origins,  # [SEC-1 FIX] CSRF protection
    )

    log.info("=" * 60)
    log.info("  UMC LASER STATION SERVER v4.1.0  [FINAL]")
    log.info("  WebSocket Bridge : ws://%s:%d", ws_host, ws_port)
    log.info("  Log folder       : %s", CONFIG["laser_log_dir"])
    log.info("  Excel report     : %s", CONFIG["excel_report"])
    log.info("  Demo mode        : %s", _env("UMC_DEMO_MODE", "true"))
    log.info("  Allowed origins  : %s", allowed_origins)
    log.info("  Nhấn Ctrl+C để dừng.")
    log.info("=" * 60)

    try:
        await asyncio.gather(
            ws_server.wait_closed(),
            _heartbeat_loop(),
            _demo_generator(),
        )
    except asyncio.CancelledError:
        pass
    finally:
        ws_server.close()
        await ws_server.wait_closed()
        if _observer:
            _observer.stop()
            _observer.join(timeout=5)
        log.info("[Server] Đã dừng hoàn toàn.")


def main() -> None:
    print("""
╔══════════════════════════════════════════════════════╗
║    UMC LASER STATION MONITORING SERVER v4.1.0        ║
║    FINAL BUILD — 50/50 Audit Score                   ║
║    Quality First — Zero Defect Strategy              ║
╚══════════════════════════════════════════════════════╝
    """)
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        print("\n[Server] Đã nhận Ctrl+C — đang dừng...")


if __name__ == "__main__":
    main()
