"""单凭据管理器与多账号调度池。"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
import uuid
from collections import OrderedDict
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

from auth_store import (
    _credential_account, _credential_identity, find_auth_files,
)
from client_profiles import credential_headers
from credential_io import atomic_write_credential, credential_file_lock
from runtime import (
    CONFIG, CRED_COOLDOWN, CRED_KEEPALIVE_RETRY_S, CRED_KEEPALIVE_S,
    CRED_REFRESH_MARGIN, MODEL_COOLDOWN, MODEL_COOLDOWN_MAX, STICKY_MAX,
    STICKY_TTL,
)
import runtime
from site_routing import (
    profile_for_auth, profile_for_headers, profile_product, profile_region,
    profile_site, refresh_url_for_auth,
)

from model_table import (
    _in_region, _model_free as catalog_model_free, _model_profiles,
    _models_for_profile, _publish_model_cache, _upstream_model, _usable_models,
    invalidate_model_table,
)

class CredentialManager:
    """从 auth 文件读取凭据；token 临近过期时自动刷新并回写。"""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._cached: dict | None = None
        self._mtime = None
        self._generation = 0

    def _read_raw(self) -> dict:
        with open(self.path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _file_version(self):
        st = self.path.stat()
        return st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size

    def _load_if_stale(self):
        """原子替换或外部更新后重读，并使旧请求持有的凭据代次失效。"""
        mt = self._file_version()
        if self._cached is None or mt != self._mtime:
            self._cached = self._read_raw()
            self._mtime = mt
            self._generation += 1

    def _session(self) -> dict:
        self._load_if_stale()
        if self._cached is None:
            raise RuntimeError(f"无法读取 auth 文件：{self.path}")
        return self._cached

    def _is_expired(self) -> bool:
        s = self._session()
        expires_at = (s.get("auth") or {}).get("expiresAt") or 0
        # 提前 60s 判定过期
        return time.time() * 1000 >= (expires_at - 60_000)

    def _refresh_needed(self, margin_s, keepalive_s):
        summary = self.summary()
        now = time.time()
        exp = (summary.get("token_expires_at") or 0) / 1000
        last = (summary.get("last_refresh_time") or 0) / 1000
        return bool(summary.get("token_expired") or (exp and exp - now < margin_s)
                    or (keepalive_s > 0 and (last <= 0 or now - last >= keepalive_s)))

    def _refresh(self, margin_s=60, keepalive_s=0):
        with self._lock:
            if not self._refresh_needed(margin_s, keepalive_s):
                return False
            with credential_file_lock(self.path.parent, self.path.name):
                if not self._refresh_needed(margin_s, keepalive_s):
                    return False
                self._refresh_locked()
                return True

    def _refresh_locked(self):
        """与导入共享文件锁，避免刷新旧会话覆盖刚保存的新登录态。"""
        s = self._session()
        auth = s.get("auth") or {}
        headers = self._build_headers_from(auth, _credential_account(s))
        headers["X-Refresh-Token"] = auth.get("refreshToken", "")
        headers["X-Auth-Refresh-Source"] = "plugin"
        url = refresh_url_for_auth(auth)
        try:
            with httpx.Client(timeout=15) as c:
                r = c.post(url, headers=headers, json={})
            data = r.json()
        except Exception as e:
            raise RuntimeError(f"刷新 token 网络失败：{e}")
        if data.get("code") != 0 or not data.get("data"):
            raise RuntimeError(f"刷新 token 失败：{data.get('msg', data)}")
        new_auth = dict(data["data"])
        if not isinstance(new_auth.get("accessToken"), str) or not new_auth["accessToken"]:
            raise RuntimeError("刷新接口未返回有效的 accessToken")
        new_auth["domain"] = new_auth.get("domain") or auth.get("domain")
        new_auth["refreshToken"] = new_auth.get("refreshToken") or auth.get("refreshToken")
        new_auth["lastRefreshTime"] = int(time.time() * 1000)
        if not new_auth.get("expiresAt") and new_auth.get("expiresIn"):
            new_auth["expiresAt"] = int(time.time() * 1000) + new_auth["expiresIn"] * 1000
        if not new_auth.get("refreshExpiresAt") and new_auth.get("refreshExpiresIn"):
            new_auth["refreshExpiresAt"] = int(time.time() * 1000) + new_auth["refreshExpiresIn"] * 1000
        updated = dict(s, auth=new_auth)
        atomic_write_credential(self.path.parent, self.path.name,
                                json.dumps(updated, ensure_ascii=False, indent=2).encode("utf-8"))
        self._cached = updated
        self._mtime = self._file_version()
        self._generation += 1

    def _build_headers_from(self, auth: dict, account: dict) -> dict:
        return credential_headers(auth, account)

    def get_headers(self) -> dict:
        """返回带最新 token 的后端请求 header；必要时先刷新。"""
        with self._lock:
            if self._is_expired():
                self._refresh()
            s = self._session()
            return self._build_headers_from(s.get("auth") or {}, _credential_account(s))

    def refresh_if_due(self, margin_s: int, keepalive_s: int) -> bool:
        """后台和前台使用同一个刷新临界区与条件复查。"""
        return self._refresh(margin_s, keepalive_s)

    def invalidate(self):
        """显式导入后重新读取磁盘，但保留管理器与刷新锁。"""
        with self._lock:
            self._cached = None
            self._mtime = None
            self._generation += 1


    def summary(self) -> dict:
        with self._lock:
            s = self._session()
            auth = s.get("auth") or {}
            acct = _credential_account(s)
            profile = profile_for_auth(auth)
            return {
                "uid": str(acct.get("uid") or "") or None,
                "account_key": _credential_identity(s),
                "site": profile_site(profile),
                "profile": profile, "region": profile_region(profile), "product": profile_product(profile),
                "nickname": acct.get("nickname"),
                "enterpriseName": acct.get("enterpriseName"),
                "token_expires_at": auth.get("expiresAt", 0),
                "token_expired": self._is_expired(),
                "last_refresh_time": auth.get("lastRefreshTime") or 0,
            }


STICKY_TTL = 30 * 60        # 会话黏绑闲置解绑秒数
STICKY_MAX = 512            # 黏绑表容量上限
CRED_COOLDOWN = 300         # 凭证熔断冷却秒数
MODEL_COOLDOWN = 600        # 模型级冷却兜底秒数（429 错误体无重置时间时）
MODEL_COOLDOWN_MAX = 86400  # 模型级冷却上限秒数
CRED_REFRESH_MARGIN = 600   # 主动刷新提前量秒数
CRED_KEEPALIVE_S = 24 * 3600   # 每日保活：距上次刷新超过该值即主动刷新，防 refresh token 闲置过期
CRED_KEEPALIVE_RETRY_S = 3600  # 保活刷新失败后的重试间隔（与临期刷新失败解耦）


def _msg_text(m: dict) -> str:
    c = m.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def session_key(payload: dict) -> str | None:
    """会话身份：system + 首条 user 消息哈希。同一会话各轮稳定，跨会话不同。"""
    msgs = payload.get("messages")
    if not msgs:
        inp = payload.get("input")  # Responses API
        if isinstance(inp, str):
            msgs = [{"role": "user", "content": inp}]
        elif isinstance(inp, list):
            msgs = inp
    msgs = msgs or []
    if not msgs:
        return None
    system = ""
    for m in msgs:
        if m.get("role") in ("system", "developer"):
            system += _msg_text(m)
        else:
            break
    first_user = next((_msg_text(m) for m in msgs if m.get("role") == "user"), "")
    if not system and not first_user:
        return None
    return hashlib.sha256((system + "\x00" + first_user).encode("utf-8", "replace")).hexdigest()[:32]


def _parse_reset_time(raw: bytes) -> float | None:
    """从 429 错误体解析配额重置时间（如 '将在 2026-08-29 22:32:31 UTC+8 重置'），返回 epoch 秒。"""
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        return None
    m = re.search(r"(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s*UTC\s*([+-]?\d+)", text)
    if not m:
        return None
    try:
        dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        tz = timezone(timedelta(hours=int(m.group(3))))
        return dt.replace(tzinfo=tz).timestamp()
    except ValueError:
        return None




def _dynamic_request_headers(skey: str | None) -> dict:
    """每次请求生成与官方客户端同构的追踪/请求 ID 头；会话 ID 随 session_key 稳定。"""
    rid = secrets.token_hex(16)   # X-Request-ID == X-Conversation-Message-ID
    crid = secrets.token_hex(16)  # X-Conversation-Request-ID == X-Root-Request-ID == trace id
    span, parent = secrets.token_hex(8), secrets.token_hex(8)
    if skey:
        conv = str(uuid.UUID(hex=hashlib.sha256(skey.encode()).hexdigest()[:32]))
    else:
        conv = str(uuid.uuid4())
    return {
        "X-Conversation-ID": conv,
        "X-Request-ID": rid,
        "X-Conversation-Message-ID": rid,
        "X-Conversation-Request-ID": crid,
        "X-Root-Request-ID": crid,
        "X-Trace-ID": crid,
        "traceparent": f"00-{crid}-{span}-01",
        "b3": f"{crid}-{span}-1-{parent}",
        "X-B3-TraceId": crid,
        "X-B3-SpanId": span,
        "X-B3-ParentSpanId": parent,
        "X-B3-Sampled": "1",
    }


class CredentialPool:
    """多凭证池：目录发现 + 热加载、黏性会话绑定、健康熔断、主动刷新。"""

    def __init__(self, paths: list[Path] | None = None, scan: bool = False):
        self._lock = threading.RLock()
        self._entries: list[dict] = []   # {id, cm, fail_until}
        self._sticky: "OrderedDict[str, tuple[str, float]]" = OrderedDict()
        self._model_fail: dict[tuple[str, str], float] = {}  # (cred_id, model) -> 冷却截止 epoch（429 模型级冷却）
        self._rr = {None: 0, "cn": 0, "intl": 0}
        self._ledger = None              # CreditLedger：pick 时按积分最早过期时间优先调度
        self._scan = scan                # True 时 pick 前自动扫描目录增删凭证
        self._ignored_duplicates: set[str] = set()
        self._sync_pending: set[str] = set()
        self._syncing: set[str] = set()
        self._sync_event = threading.Event()
        self._sync_retry: dict[str, float] = {}
        self._sync_attempts: dict[str, int] = {}
        self.reload(paths or [])
        if self._scan:
            self._rescan()             # 启动即发现一轮，/health 不等首个请求

    def reload(self, paths: list[Path], *, reset: bool = True):
        """只在文件实际更新或显式导入时重置认证状态，并通知目录刷新。"""
        with self._lock:
            by_id = {entry["id"]: entry for entry in self._entries}
            have_uids = {entry["account_key"]: entry["id"]
                         for entry in self._entries if entry.get("uid")}
            for path in paths:
                cid = str(Path(path).resolve())
                if not os.path.exists(cid):
                    continue
                entry = by_id.get(cid)
                if entry is not None:
                    if reset:
                        entry["cm"].invalidate()
                    try:
                        summary = entry["cm"].summary()
                    except Exception:
                        continue  # 单个损坏文件不能阻止其他凭据被发现
                    generation = entry["cm"]._generation
                    identity = summary["account_key"]
                    changed = reset or generation != entry.get("generation")
                    if changed:
                        old_identity = entry.get("account_key")
                        if old_identity != identity:
                            self._model_fail = {key: until for key, until in self._model_fail.items() if key[0] != cid}
                            self._sticky = OrderedDict((key, value) for key, value in self._sticky.items() if value[0] != cid)
                        if entry.get("uid"):
                            have_uids.pop(old_identity, None)
                        entry.update(uid=summary.get("uid"), profile=summary["profile"], site=summary["site"],
                                     account_key=identity, generation=generation, catalog_dirty=True)
                        self._bind_entry(entry)
                        if reset or old_identity != identity:
                            entry.update(fail_until=0.0, keepalive_after=0.0)
                        if entry.get("uid"):
                            have_uids[identity] = cid
                        self._queue_sync(cid)
                    continue
                manager = CredentialManager(Path(cid))
                try:
                    summary = manager.summary()
                except Exception:
                    summary = {}
                uid = summary.get("uid")
                profile = summary.get("profile", "cn-cli")
                identity_key = summary.get("account_key")
                if uid and identity_key in have_uids:
                    if cid not in self._ignored_duplicates:
                        runtime._log(f"[cred] 忽略重复账号凭据: {Path(cid).name}（同产品账号与 {Path(have_uids[identity_key]).name} 重复）")
                        self._ignored_duplicates.add(cid)
                    continue
                entry = {"id": cid, "cm": manager, "fail_until": 0.0 if summary else time.time() + CRED_COOLDOWN, "uid": uid,
                         "site": summary.get("site"), "profile": profile, "generation": manager._generation,
                         "account_key": identity_key, "catalog_dirty": True}
                self._bind_entry(entry)
                self._entries.append(entry)
                by_id[cid] = entry
                self._ignored_duplicates.discard(cid)
                if uid:
                    have_uids[identity_key] = cid
                self._queue_sync(cid)

    def _queue_sync(self, cid):
        self._sync_pending.add(cid)
        self._sync_retry.pop(cid, None)
        self._sync_attempts.pop(cid, None)
        self._sync_event.set()
        if CONFIG.get("cred_pool") is self:
            _publish_model_cache()
        else:
            invalidate_model_table()

    def begin_sync(self, *, all_entries=False):
        """消费待刷队列；事件和队列在同一把锁下清除，避免丢失唤醒。"""
        with self._lock:
            due = {cid for cid, deadline in self._sync_retry.items() if deadline <= time.monotonic()}
            self._sync_pending.update(due)
            ids = {entry["id"] for entry in self._entries} if all_entries else set(self._sync_pending)
            self._sync_pending.difference_update(ids)
            if not self._sync_pending:
                self._sync_event.clear()
            self._syncing.update(ids)
            return ids

    def end_sync(self, ids, failed=()):
        with self._lock:
            self._syncing.difference_update(ids)
            present = {entry["id"] for entry in self._entries}
            for cid in ids:
                if cid in failed and cid in present and cid not in self._sync_pending:
                    attempt = min(self._sync_attempts.get(cid, 0) + 1, 5)
                    self._sync_attempts[cid] = attempt
                    self._sync_retry[cid] = time.monotonic() + min(60 * 2 ** (attempt - 1), 900)
                else:
                    self._sync_retry.pop(cid, None)
                    self._sync_attempts.pop(cid, None)

    def sync_pending(self, region=None):
        with self._lock:
            pending = self._sync_pending | self._syncing | self._sync_retry.keys()
            return bool(pending) if region is None else any(
                entry["id"] in pending and (profile := self._entry_profile(entry))
                and profile_region(profile) == region for entry in self._entries)

    def sync_wait(self, periodic_delay):
        with self._lock:
            retry_delay = min(self._sync_retry.values(), default=float("inf")) - time.monotonic()
        return max(0, min(periodic_delay, retry_delay))

    def apply_if_current(self, cm, generation, update):
        """过期请求的额度或目录结果不能覆盖新登录态的缓存。"""
        with self._lock, cm._lock:
            entry = next((entry for entry in self._entries if entry["cm"] is cm), None)
            if entry is None:
                return False
            if not self._lease_matches(cm, generation):
                self._queue_sync(entry["id"])
                return False
            self.reload([cm.path], reset=False)
            update()
            return True

    def prune(self):
        """移除已不存在文件的凭据，并清理其黏绑。"""
        with self._lock:
            self._ignored_duplicates = {p for p in self._ignored_duplicates if os.path.exists(p)}
            before = len(self._entries)
            removed = [e for e in self._entries if not os.path.exists(e["id"])]
            for entry in removed:
                if self._ledger is not None:
                    self._ledger.remove(entry["id"])
            self._entries = [e for e in self._entries if e not in removed]
            if len(self._entries) != before:
                ids = {e["id"] for e in self._entries}
                self._sync_pending.intersection_update(ids)
                self._syncing.intersection_update(ids)
                self._sync_retry = {cid: deadline for cid, deadline in self._sync_retry.items() if cid in ids}
                self._sync_attempts = {cid: count for cid, count in self._sync_attempts.items() if cid in ids}
                invalidate_model_table()
                self._sticky = OrderedDict((k, v) for k, v in self._sticky.items() if v[0] in ids)
                self._model_fail = {k: v for k, v in self._model_fail.items() if k[0] in ids}
                if CONFIG.get("cred_pool") is self:
                    _publish_model_cache()


    def find_by_uid(self, uid: str, identity: str | None = None) -> Optional[str]:
        """按账号 uid 查池内凭据 id（用于导入冲突检测）。"""
        with self._lock:
            for e in self._entries:
                if e.get("uid") == uid and (identity is None or e.get("account_key") == identity):
                    return e["id"]
        return None

    def set_ledger(self, ledger):
        """挂接 CreditLedger 后，pick 按积分最早过期时间优先选凭证。"""
        with self._lock:
            self._ledger = ledger
            self.reload([Path(entry["id"]) for entry in self._entries], reset=False)
            for entry in self._entries:
                self._bind_entry(entry)

    def _bind_entry(self, entry):
        if self._ledger is not None:
            if entry.get("account_key"):
                self._ledger.bind_identity(entry["id"], entry["account_key"])
            else:
                self._ledger.remove(entry["id"])

    def entries(self) -> list[dict]:
        """池内凭证条目快照（供签到/积分调度遍历）。"""
        with self._lock:
            return [dict(e) for e in self._entries]

    def _expiry_rank(self, e: dict) -> tuple:
        """快过期优先排序键：(无数据排后, 最早过期时间升序)。"""
        exp = self._ledger.soonest_expiry_of(e["id"]) if self._ledger else None
        return (exp is None, exp or 0.0)
    def _rescan(self):
        self.prune()
        paths = find_auth_files() if self._scan else [Path(entry["id"]) for entry in self.entries()]
        self.reload(paths, reset=False)

    def _healthy(self, e: dict) -> bool:
        return time.time() >= e["fail_until"]

    @staticmethod
    def _entry_profile(entry):
        try:
            return entry["cm"].summary().get("profile", "cn-cli")
        except Exception:
            return None

    @classmethod
    def _entry_site(cls, entry):
        profile = cls._entry_profile(entry)
        return profile_site(profile) if profile else None

    def _zero_balance(self, entry, profile) -> bool:
        """该账号已确认余额为 0：只能使用目录声明的零倍率模型。"""
        balance = (self._ledger.entry(entry["id"]).get("credits") or {}) if self._ledger else {}
        if not balance:
            return False
        try:
            return (bool(balance.get("intl")) == (profile_region(profile) == "intl")
                    and float(balance.get("credits") or 0) <= 0)
        except (TypeError, ValueError):
            return False

    def _has_credit(self, entry, profile):
        balance = (self._ledger.entry(entry["id"]).get("credits") or {}) if self._ledger else {}
        if not balance:
            return profile_region(profile) == "cn"
        try:
            return (bool(balance.get("intl")) == (profile_region(profile) == "intl")
                    and float(balance.get("credits") or 0) > 0)
        except (TypeError, ValueError):
            return False

    def _eligible(self, entry, model, *, region=None, profile=None):
        actual = self._entry_profile(entry)
        profile = profile or actual
        if not profile or profile != actual or not _in_region(profile, region):
            return False
        configured = {candidate for item in self._entries if (candidate := self._entry_profile(item))
                      and _in_region(candidate, region)}
        if profile not in _model_profiles(model, region, configured):
            return False
        if CONFIG.get("account_catalogs") is not None or CONFIG.get("model_cache") is not None:
            try:
                identity = entry["cm"].summary()["account_key"]
            except Exception:
                return False
            if identity != entry.get("account_key"):
                return False
            account = (CONFIG.get("account_catalogs") or {}).get(identity) or {}
            models = account.get("models")
            if account.get("profile") != profile or models is None:
                return False
            usable = _usable_models(models)
            supported = any(item["id"] == _upstream_model(model, profile) for item in usable)
            cli_auto = model == "auto" and profile == "cn-cli" and bool(usable)
            # 关闭 guard 仅允许单产品的明确表外透传，不能把 A 的已知能力借给 B。
            declared = any(item["id"] == _upstream_model(model, profile)
                           for item in _models_for_profile(profile, configured))
            passthrough = (model != "auto" and not declared and not CONFIG.get("model_guard")
                           and len(configured) == 1)
            if model and not (supported or cli_auto or passthrough):
                return False
        # 零余额账号退出付费模型轮询，只保留自身目录声明为 x0.00 的模型。
        return (not model or self._has_credit(entry, profile)
                or self._model_free(entry, model, profile=profile))

    def _model_free(self, entry, model: str | None, *, profile=None) -> bool:
        """该凭证的账号目录是否把此模型声明为零计费（x0.00）。"""
        if not model or model == "auto":
            return False
        profile = profile or self._entry_profile(entry)
        if not profile:
            return False
        accounts = CONFIG.get("account_catalogs")
        if accounts is not None or CONFIG.get("model_cache") is not None:
            account = (accounts or {}).get(entry.get("account_key")) or {}
            if account.get("profile") != profile:
                return False
            return catalog_model_free(account.get("models"), model, profile)
        return catalog_model_free(_models_for_profile(profile), model, profile)

    def _model_healthy(self, e: dict, model: str | None) -> bool:
        """该凭证对指定模型未处于 429 冷却期；model 为空时不做模型级检查。"""
        if not model:
            return True
        routed_model = _upstream_model(model, self._entry_profile(e))
        return time.time() >= self._model_fail.get((e["id"], routed_model), 0.0)

    def _evict_sticky(self):
        now = time.time()
        while self._sticky:
            k, (_, ts) = next(iter(self._sticky.items()))
            if now - ts > STICKY_TTL or len(self._sticky) > STICKY_MAX:
                self._sticky.pop(k)
            else:
                break

    def _candidates(self, model: str | None, *, region=None) -> list[dict]:
        """可用凭证按（零计费优先, 快过期积分优先）排序；同级由调用方轮询。"""
        healthy = [entry for entry in self._entries if self._healthy(entry)
                   and self._eligible(entry, model, region=region) and self._model_healthy(entry, model)]
        if not healthy:
            return []
        # 目录倍率 x0.00 的同名模型排最前，其次快过期积分优先；无数据排最后。
        healthy.sort(key=lambda entry: (not self._model_free(entry, model), *self._expiry_rank(entry)))
        return healthy

    def pick(self, skey: str | None, model: str | None = None, *, region=None) -> CredentialManager | None:
        """按黏绑选凭证；未绑定/已失效则轮询取健康凭证并绑定。

        model 非空时跳过该模型 429 冷却中的凭证（黏性会话自动换绑）；
        全部凭证对该模型冷却时返回 None，由上层快速失败，不再打上游。
        候选优先零计费账号；黏绑账号被更好的来源替代时自动重绑。
        """
        self._rescan()  # 锁外扫描，reload/prune 各自取锁，避免死锁
        with self._lock:
            self._evict_sticky()
            candidates = self._candidates(model, region=region)
            if not candidates:
                if skey:
                    self._sticky.pop(skey, None)
                return None
            best = candidates[0]
            free = self._model_free(best, model)
            top = [e for e in candidates if self._model_free(e, model) == free
                   and self._expiry_rank(e) == self._expiry_rank(best)]
            if skey and skey in self._sticky:
                cid, _ = self._sticky[skey]
                sticky = next((e for e in top if e["id"] == cid), None)
                if sticky is not None:
                    self._sticky[skey] = (cid, time.time())
                    self._sticky.move_to_end(skey)
                    return sticky["cm"]
            e = top[self._rr[region] % len(top)]
            self._rr[region] += 1
            if skey:
                self._sticky[skey] = (e["id"], time.time())
            return e["cm"]

    def headers_for(self, skey: str | None, model: str | None = None, *, region=None, with_generation=False):
        """在发送前复核凭据代次和站点，避免重载竞态导致跨站调用。"""
        for _ in range(max(1, len(self._entries))):
            cm = self.pick(skey, model, region=region)
            if cm is None:
                return None
            reason = None
            with cm._lock:
                try:
                    headers = cm.get_headers()
                    profile = profile_for_headers(headers)
                    generation = cm._generation
                except Exception as error:
                    generation, reason = cm._generation, str(error)
            if reason is not None:
                self.cooldown(cm, reason=reason, generation=generation)
                continue
            with self._lock:
                self.reload([cm.path], reset=False)
                entry = next((entry for entry in self._entries if entry["cm"] is cm), None)
                if (entry is not None and cm._generation == generation and self._healthy(entry)
                        and self._eligible(entry, model, region=region, profile=profile) and self._model_healthy(entry, model)):
                    return ((cm, generation) if with_generation else cm), headers
        return None

    @staticmethod
    def _lease_matches(cm, generation):
        if generation is None:
            return True
        try:
            cm._load_if_stale()
        except (OSError, ValueError):
            return generation == cm._generation
        return generation == cm._generation

    def cooldown(self, cm: CredentialManager, reason: str = "", *, generation=None):
        with self._lock, (cm._lock if generation is not None else nullcontext()):
            if not self._lease_matches(cm, generation):
                return
            for e in self._entries:
                if e["cm"] is cm:
                    e["fail_until"] = time.time() + CRED_COOLDOWN
        runtime._log(f"[cred] 凭证熔断 {CRED_COOLDOWN}s: {Path(cm.path).name} {reason}")

    def note_status(self, cm: CredentialManager | None, status: int,
                    model: str | None = None, raw: bytes = b"", *, generation=None):
        """401/403 熔断整个凭证；429 只冷却 (凭证,模型) 至配额重置时间，其他模型/凭证不受影响。"""
        if cm is None:
            return
        if status in (401, 403):
            self.cooldown(cm, reason=f"backend HTTP {status}", generation=generation)
            return
        if status != 429 or not model:
            return
        now = time.time()
        until = _parse_reset_time(raw) or now + MODEL_COOLDOWN
        until = min(until, now + MODEL_COOLDOWN_MAX)
        with self._lock, (cm._lock if generation is not None else nullcontext()):
            if not self._lease_matches(cm, generation):
                return
            self._model_fail = {k: v for k, v in self._model_fail.items() if v > now}
            for e in self._entries:
                if e["cm"] is cm:
                    routed_model = _upstream_model(model, self._entry_profile(e))
                    self._model_fail[(e["id"], routed_model)] = until
        runtime._log(f"[cred] 模型冷却 {model} @ {Path(cm.path).name} 至 "
             f"{time.strftime('%m-%d %H:%M:%S', time.localtime(until))} (HTTP 429)")

    def model_cooldown_until(self, model: str | None, *, region=None) -> float | None:
        """该模型在所有健康凭证上都在冷却时返回最早恢复时间；否则 None。"""
        if not model:
            return None
        with self._lock:
            now = time.time()
            pool = [entry for entry in self._entries if self._healthy(entry)
                    and self._eligible(entry, model, region=region)]
            if not pool:
                return None
            untils = [self._model_fail.get((entry["id"], _upstream_model(model, self._entry_profile(entry))), 0.0)
                      for entry in pool]
            if any(now >= u for u in untils):
                return None
            return min(untils)

    def refresh_due(self, margin_s: int = CRED_REFRESH_MARGIN, keepalive_s: int = CRED_KEEPALIVE_S):
        """按到期与保活条件刷新，失败退避只作用于发起操作时的凭据代次。"""
        with self._lock:
            entries = list(self._entries)
        now = time.time()
        for entry in entries:
            if now < entry.get("fail_until", 0.0):
                continue
            cm = entry["cm"]
            failure = None
            refreshed = keepalive_due = False
            with cm._lock:
                try:
                    summary = cm.summary()
                    exp = (summary.get("token_expires_at") or 0) / 1000
                    last = (summary.get("last_refresh_time") or 0) / 1000
                    expiry_due = bool(summary.get("token_expired") or (exp and exp - now < margin_s))
                    keepalive_due = (not expiry_due and keepalive_s > 0
                                     and now >= entry.get("keepalive_after", 0.0)
                                     and (last <= 0 or now - last >= keepalive_s))
                    if not (expiry_due or keepalive_due):
                        continue
                    refreshed = cm.refresh_if_due(margin_s, keepalive_s if keepalive_due else 0)
                    entry["keepalive_after"] = 0.0
                except Exception as error:
                    failure = (str(error), cm._generation)
                    if keepalive_due:
                        entry["keepalive_after"] = now + CRED_KEEPALIVE_RETRY_S
            if failure:
                self.cooldown(cm, reason=failure[0], generation=failure[1])
            elif refreshed:
                runtime._log(f"[cred] {'每日保活刷新' if keepalive_due else '已主动刷新'}并回写: {Path(entry['id']).name}")

    def remove_file(self, name: str) -> bool:
        """删除与刷新共用锁，避免删除后被在途刷新重新创建。"""
        with self._lock:
            entry = next((x for x in self._entries if os.path.basename(x["id"]) == name), None)
            if entry is None:
                return False
            cm = entry["cm"]
            try:
                with cm._lock, credential_file_lock(cm.path.parent, cm.path.name):
                    os.unlink(entry["id"])
                    cm.invalidate()
            except FileNotFoundError:
                pass
            except OSError:
                return False
            self.prune()
            return True

    def first(self) -> CredentialManager | None:
        with self._lock:
            return self._entries[0]["cm"] if self._entries else None

    def snapshot(self) -> list[dict]:
        with self._lock:
            now = time.time()
            out = []
            for e in self._entries:
                s: dict = {"auth_file": e["id"], "healthy": self._healthy(e),
                           "model_cooldowns": {m: time.strftime("%m-%d %H:%M:%S", time.localtime(u))
                                               for (cid, m), u in self._model_fail.items()
                                               if cid == e["id"] and u > now},
                           "sticky_sessions": sum(1 for _, (cid, ts) in self._sticky.items()
                                                  if cid == e["id"] and now - ts <= STICKY_TTL)}
                try:
                    s.update(e["cm"].summary())
                except Exception:
                    s["error"] = "凭据读取失败"
                out.append(s)
            return out


def _refresher_loop(pool: CredentialPool):
    """后台主动刷新：过期前刷新并回写，凭证不因闲置而失效。"""
    while True:
        time.sleep(60)
        try:
            pool.refresh_due()
        except Exception as e:
            runtime._log(f"[cred] 刷新线程异常: {e}")
