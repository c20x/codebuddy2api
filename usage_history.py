"""本机请求流水：只记元数据，不写 token 或正文。"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

MAX_ITEMS = 200


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value):
    try:
        if value is None or value == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


def estimate_credits(tokens, multiplier):
    """官方目录倍率为每千 token 的 credits；无倍率或 token 时无法估算。"""
    tokens = _safe_int(tokens)
    multiplier = _safe_float(multiplier)
    if tokens is None or multiplier is None:
        return None
    return round(tokens / 1000 * multiplier, 4)


class UsageHistory:
    def __init__(self, path: Path | None = None, max_items: int = MAX_ITEMS):
        self.path = Path(path) if path else None
        self.max_items = max_items
        self._lock = threading.Lock()
        self._items: list[dict] = []
        self._pending: dict[str, dict] = {}
        self._load()

    def _load(self):
        if self.path is None:
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            items = data.get("items") if isinstance(data, dict) else data
            if isinstance(items, list):
                self._items = [item for item in items if isinstance(item, dict)][-self.max_items:]
        except Exception:
            self._items = []

    def _save(self):
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            payload = json.dumps({"version": 1, "items": self._items}, ensure_ascii=False)
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except OSError:
            pass

    def tag(self, rid: str, **fields):
        if not rid:
            return
        with self._lock:
            pending = self._pending.setdefault(rid, {"id": rid})
            pending.update({key: value for key, value in fields.items() if value is not None})

    def begin(self, rid: str, **fields):
        self.tag(rid, **fields)

    def finish(self, rid: str, *, ok: bool, t0: float = 0, model: str | None = None,
               result: dict | None = None, status: int | None = None, error: str = ""):
        if not rid:
            return
        usage = (result or {}).get("usage") or {}
        choice = ((result or {}).get("choices") or [{}])[0] or {}
        item = {
            "id": rid,
            "at": time.time(),
            "ok": bool(ok),
            "status": 200 if ok else (status or 502),
            "elapsed_s": round(max(time.time() - t0, 0), 2) if t0 else None,
            "model": model,
            "tokens": _safe_int(usage.get("total_tokens")),
            "prompt_tokens": _safe_int(usage.get("prompt_tokens")),
            "completion_tokens": _safe_int(usage.get("completion_tokens")),
            "credits": _safe_float(usage.get("credits") or usage.get("total_credits")),
            "finish_reason": choice.get("finish_reason"),
            "error": (error or "")[:200],
        }
        with self._lock:
            pending = self._pending.pop(rid, {})
            record = {**pending, **{key: value for key, value in item.items() if value not in (None, "")}}
            record["id"] = rid
            record["ok"] = bool(ok)
            record["status"] = item["status"]
            if record.get("credits") is None:
                estimated = estimate_credits(record.get("tokens"), record.get("multiplier"))
                if estimated is not None:
                    record["credits"] = estimated
                    record["credits_estimated"] = True
            self._items.append(record)
            self._items = self._items[-self.max_items:]
            if len(self._pending) > self.max_items:
                extra = list(self._pending)[:-self.max_items]
                for key in extra:
                    self._pending.pop(key, None)
            self._save()

    def snapshot(self, limit: int = 80) -> list[dict]:
        with self._lock:
            items = list(reversed(self._items[-max(1, min(limit, self.max_items)):]))
        return items
