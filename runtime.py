"""共享运行时：版本、配置、常量和日志。"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path

from client_profiles import CLI_USER_AGENT, CLI_VERSION
from safe_logging import format_log_body, sanitize_log_text

APP_VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
BACKEND = "https://copilot.tencent.com"
DEFAULT_DOMAIN = "www.codebuddy.cn"
CBC_VERSION = CLI_VERSION
USER_AGENT = CLI_USER_AGENT

STICKY_TTL = 30 * 60
STICKY_MAX = 512
CRED_COOLDOWN = 300
MODEL_COOLDOWN = 600
MODEL_COOLDOWN_MAX = 86400
CRED_REFRESH_MARGIN = 600
CRED_KEEPALIVE_S = 24 * 3600
CRED_KEEPALIVE_RETRY_S = 3600
CHECKIN_FIRST_DELAY = 30
HOUSEKEEP_INTERVAL = 3600

DEFAULT_MODELS = [
    "hy4-preview", "hy4-preview-x",
    "hy3", "hy3-x",
    "deepseek-v4-pro", "deepseek-v4-flash", "deepseek-v4.1-flash", "deepseek-v3-2-volc",
    "glm-5.3", "glm-5.3-flash", "glm-5.2", "glm-5.1", "glm-5.0", "glm-5.0-turbo",
    "glm-5v-turbo", "glm-4.7", "glm-4.6", "glm-4.6v",
    "minimax-m3", "minimax-m2.7", "minimax-m2.5",
    "kimi-k3-1", "kimi-k2.7", "kimi-k2.6", "kimi-k2.5", "kimi-k2-thinking",
    "hunyuan-chat", "default",
    "auto",
]

PASSTHROUGH_BODY_KEYS = {
    "model", "messages", "tools", "tool_choice", "temperature",
    "max_tokens", "max_completion_tokens", "top_p", "stream",
    "stream_options", "stop", "presence_penalty", "frequency_penalty",
    "n", "response_format", "seed", "user", "reasoning_effort", "prompt_cache_key",
    "verbosity", "reasoning_summary",
}

CONFIG: dict = {"api_key": "", "cred": None, "log_path": None, "ledger": None,
                "models_remote": None,
                "models_intl": None,
                "model_cache": None,
                "model_catalogs": {},
                "account_catalogs": None,
                "auto_trial": False, "trial_ledger": None,
                "model_guard": True,
                "max_images": 16, "image_policy": "truncate",
                "max_request_bytes": 32 * 1024 * 1024, "log_body_limit": 65536,
                "usage_daily": None,
                "credit_price_cny": None, "credit_price_usd": None, "usd_rate": None,
                "desensitize": False, "no_compact": False}

_LOG_LOCK = threading.Lock()
LOG_MAX_BYTES = 50 * 1024 * 1024
LOG_BACKUPS = 2


def _log(msg: str):
    """写入脱敏有界日志，在同一把锁内检查大小与轮转。"""
    path = CONFIG.get("log_path")
    if not path:
        return
    budget = min(max(1024, CONFIG.get("log_body_limit", 65536) + 256), max(0, LOG_MAX_BYTES - 256))
    msg = sanitize_log_text(msg, budget)
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n"
    try:
        with _LOG_LOCK:
            try:
                size = os.path.getsize(path)
            except FileNotFoundError:
                size = 0
            rotated = size > 0 and size + len(line.encode("utf-8")) > LOG_MAX_BYTES
            if rotated:
                for i in range(LOG_BACKUPS - 1, 0, -1):
                    old = f"{path}.{i}"
                    if os.path.exists(old):
                        os.replace(old, f"{path}.{i + 1}")
                os.replace(path, f"{path}.1")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as stream:
                if rotated:
                    stream.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] ==== 日志轮转 ====\n")
                stream.write(line)
    except OSError:
        pass


def _log_json(label: str, value):
    if CONFIG.get("log_path") and CONFIG.get("log_body_limit", 65536):
        _log(f"{label}\n{format_log_body(value, CONFIG.get('log_body_limit', 65536))}")


def _log_text_body(label: str, text: str):
    if CONFIG.get("log_path") and CONFIG.get("log_body_limit", 65536):
        _log(f"{label}\n{sanitize_log_text(text, CONFIG.get('log_body_limit', 65536))}")


def _truncate(s: str, n: int = 80) -> str:
    s = str(s).replace("\n", " ").strip()
    return s[:n] + ("…" if len(s) > n else "")


def _network_error_text(error: Exception) -> str:
    return sanitize_log_text(f"{type(error).__name__}: {str(error).strip() or 'upstream transport failed'}", 512)
