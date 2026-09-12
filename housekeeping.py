"""积分、签到、模型目录与用量的后台同步。"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import trial_rewards
from client_profiles import account_key, catalog_cache_key
import runtime
from runtime import (
    CHECKIN_FIRST_DELAY, CONFIG, HOUSEKEEP_INTERVAL, _network_error_text,
)
from model_table import _publish_model_cache
from site_routing import INTERNATIONAL, profile_for_headers, site_for_headers

try:
    import credits as credits_mod
except ImportError:
    credits_mod = None

_HOUSEKEEP_LOCK = threading.Lock()

def _bearer_token(headers: dict) -> str:
    return (headers.get("Authorization") or "").removeprefix("Bearer ").strip()


def _sync_error(pool, ledger, entry, generation, phase, error):
    message = f"{phase}: {_network_error_text(error)}"
    pool.apply_if_current(entry["cm"], generation, lambda: ledger.note_error(entry["id"], message))
    runtime._log(f"[{phase}] {Path(entry['id']).name} 同步失败（保留旧数据）: {message}")


def _sync_trial(headers):
    """可选福利领取与余额同步分离，持久化故障不阻断普通请求。"""
    ledger = CONFIG.get("trial_ledger")
    if not CONFIG.get("auto_trial") or ledger is None:
        return
    profile, uid = profile_for_headers(headers), headers.get("X-User-Id", "")
    if profile != "intl-work" or not uid:
        return
    key = account_key(profile, uid, headers.get("X-Enterprise-Id", ""))
    try:
        previous = ledger.summary(key).get("attempted_at")
        result = trial_rewards.attempt_trial(ledger, key, headers)
        if ledger.summary(key).get("attempted_at") != previous:
            runtime._log(f"[trial] 领取检查 | ok={result['ok']} | already={result['already']} | code={result['code']} | status={result['status']}")
    except Exception as error:
        runtime._log(f"[trial] 领取失败（不影响余额同步）: {_network_error_text(error)}")


def _sync_credits(pool, ledger, entry, *, checkin, failed):
    cm, cid = entry["cm"], entry["id"]
    generation = None
    try:
        with cm._lock:
            try:
                headers = cm.get_headers()
            finally:
                generation = cm._generation
        site = site_for_headers(headers)
        token, uid, domain = _bearer_token(headers), headers.get("X-User-Id", ""), headers.get("X-Domain", "")
        day = time.strftime("%Y-%m-%d")
        if checkin and not ledger.checkin_done(cid, day):
            try:
                result = credits_mod.daily_checkin(token, uid=uid, domain=domain)
                if not pool.apply_if_current(cm, generation, lambda: ledger.mark_checkin(
                        cid, day, result["ok"], result.get("code"), result.get("message", ""))):
                    failed.add(cid)
                    return None
                runtime._log(f"[checkin] {Path(cid).name}: ok={result['ok']} already={result.get('already')} code={result.get('code')}")
            except Exception as error:
                _sync_error(pool, ledger, entry, generation, "checkin", error)
        _sync_trial(headers)
        balance = credits_mod.fetch_credits(token, uid=uid, domain=domain)
        if bool(balance.get("intl")) != (site == INTERNATIONAL):
            raise ValueError("积分响应与凭据站点不一致")
        if not pool.apply_if_current(cm, generation, lambda: ledger.update_credits(cid, balance)):
            failed.add(cid)
            return None
        runtime._log(f"[credits] {Path(cid).name}: 站点 {site}，余额 {balance['credits']}")
        profile = profile_for_headers(headers)
        return entry, generation, headers, profile
    except Exception as error:
        failed.add(cid)
        _sync_error(pool, ledger, entry, generation, "credits", error)
        return None

def _sync_model_catalogs(pool, ledger, refs, failed):
    cache = CONFIG.get("model_cache")
    if cache is None:
        return
    for entry, generation, headers, profile in refs.values():
        identity = account_key(profile, headers.get("X-User-Id"), headers.get("X-Enterprise-Id"))
        key = catalog_cache_key(profile, identity)
        if cache.fresh(key) and not entry.get("catalog_dirty"):
            continue
        try:
            models = credits_mod.fetch_model_catalog(
                _bearer_token(headers), domain=headers.get("X-Domain", ""),
                uid=headers.get("X-User-Id", ""), enterprise_id=headers.get("X-Enterprise-Id", ""))
            def publish():
                cache.put(key, models)
                for current in pool._entries:
                    if current["cm"] is entry["cm"]:
                        current["catalog_dirty"] = False
            if pool.apply_if_current(entry["cm"], generation, publish):
                runtime._log(f"[models] {profile} 模型表已刷新: {len(models)} 个")
            else:
                failed.add(entry["id"])
        except Exception as error:
            failed.add(entry["id"])
            _sync_error(pool, ledger, entry, generation, "models", error)
    _publish_model_cache()


def _sync_usage(pool):
    """历史用量仅在定时/手动维护时同步，入库唤醒不额外拉取历史。"""
    by_day, groups = {}, {}
    used, count, any_success = 0.0, 0, False
    for entry in pool.entries():
        try:
            cm = entry["cm"]
            with cm._lock:
                headers = cm.get_headers()
                generation = cm._generation
            site = site_for_headers(headers)
            usage = credits_mod.fetch_request_usage(_bearer_token(headers), uid=headers.get("X-User-Id", ""),
                                                    domain=headers.get("X-Domain", ""))
            def merge():
                nonlocal used, count, any_success
                any_success = True
                group = groups.setdefault(site, {"by_day": {}, "total_credits": 0.0, "requests": 0})
                for day, models in usage["by_day"].items():
                    total_day = by_day.setdefault(day, {})
                    site_day = group["by_day"].setdefault(day, {})
                    for model, credit in models.items():
                        total_day[model] = round(total_day.get(model, 0.0) + credit, 6)
                        site_day[model] = round(site_day.get(model, 0.0) + credit, 6)
                group["total_credits"] += usage["total_credits"]
                group["requests"] += usage["requests"]
                used += usage["total_credits"]
                count += usage["requests"]
            pool.apply_if_current(cm, generation, merge)
        except Exception as error:
            runtime._log(f"[usage] {Path(entry['id']).name} 明细拉取失败: {_network_error_text(error)}")
    if any_success:
        for group in groups.values():
            group["total_credits"] = round(group["total_credits"], 2)
        CONFIG["usage_daily"] = {"by_day": by_day, "groups": groups, "total_credits": round(used, 2),
                                 "requests": count, "fetched_at": time.time()}
        runtime._log(f"[usage] 明细已同步: {count} 请求 / {used:.2f} credits")


def _housekeep_once(pool: CredentialPool, ledger, *, pending_only=False):
    """串行维护并提交同代次结果；新凭据只触发额度和目录查询。"""
    if credits_mod is None:
        return
    with _HOUSEKEEP_LOCK:
        pool._rescan()
        ids = pool.begin_sync(all_entries=not pending_only)
        failed = set()
        try:
            refs = {}
            for entry in pool.entries():
                if entry["id"] not in ids:
                    continue
                result = _sync_credits(pool, ledger, entry, checkin=not pending_only, failed=failed)
                if result is not None:
                    refs[entry["id"]] = result
            _sync_model_catalogs(pool, ledger, refs, failed)
            if not pending_only:
                _sync_usage(pool)
        except Exception:
            failed.update(ids)
            raise
        finally:
            pool.end_sync(ids, failed)


def _housekeeper_loop(pool: CredentialPool, ledger) -> None:
    """新凭据事件即时唤醒；失败退避重试，整轮维护仍按小时进行。"""
    next_full = time.monotonic() + CHECKIN_FIRST_DELAY
    while True:
        pool._sync_event.wait(pool.sync_wait(next_full - time.monotonic()))
        full_due = time.monotonic() >= next_full
        try:
            _housekeep_once(pool, ledger, pending_only=not full_due)
        except Exception as error:
            runtime._log(f"[housekeeper] 循环异常: {_network_error_text(error)}")
        if full_due:
            next_full = time.monotonic() + HOUSEKEEP_INTERVAL
