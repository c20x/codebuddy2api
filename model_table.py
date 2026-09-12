"""按账号隔离的模型目录、倍率与本地拦截。"""

from __future__ import annotations

import re
from contextlib import nullcontext

from fastapi import HTTPException

from client_profiles import catalog_cache_key
from runtime import CONFIG, DEFAULT_MODELS
from site_routing import PROFILE_ENDPOINTS, profile_region

_MODEL_TABLE_TTL = 60.0
_model_table_cache: dict = {}

def _publish_model_cache():
    """只发布账号绑定的产品版本缓存；旧 root/profile 表没有可验证的所有者。"""
    cache = CONFIG.get("model_cache")
    if cache is not None:
        pool = CONFIG.get("cred_pool")
        with pool._lock if pool is not None else nullcontext():
            accounts = {}
            for entry in pool.entries() if pool is not None else []:
                identity, profile = entry.get("account_key"), entry.get("profile")
                if not identity or not profile:
                    continue
                key = catalog_cache_key(profile, identity)
                accounts[identity] = {"profile": profile,
                                      "models": cache.models(key) if cache.age(key) is not None else None}
            CONFIG["account_catalogs"] = accounts
            catalogs = {profile: None for profile in PROFILE_ENDPOINTS}
            for account in accounts.values():
                if account["models"] is not None:
                    models = catalogs[account["profile"]]
                    if models is None:
                        models = catalogs[account["profile"]] = []
                    models.extend(account["models"])
            CONFIG["model_catalogs"] = catalogs
            CONFIG["models_remote"], CONFIG["models_intl"] = catalogs["cn-cli"], catalogs["intl-cli"]
    invalidate_model_table()


def invalidate_model_table() -> None:
    """模型表变更后作废快照缓存。"""
    global _model_table_cache
    _model_table_cache = {}


def _catalog_for(profile: str):
    accounts = CONFIG.get("account_catalogs")
    if accounts is not None or CONFIG.get("model_cache") is not None:
        pool = CONFIG.get("cred_pool")
        models = None
        for entry in pool.entries() if pool is not None else []:
            if entry.get("profile") != profile:
                continue
            account = (accounts or {}).get(entry.get("account_key")) or {}
            if account.get("profile") == profile and account.get("models") is not None:
                if models is None:
                    models = []
                models.extend(account["models"])
        return models
    catalogs = CONFIG.get("model_catalogs") or {}
    if profile in catalogs:
        return catalogs[profile]
    legacy = {"cn-cli": "models_remote", "intl-cli": "models_intl"}
    return CONFIG.get(legacy[profile]) if profile in legacy else None


def _in_region(profile: str, region: str | None) -> bool:
    return region is None or profile_region(profile) == region


def _configured_profiles(region: str | None) -> set[str]:
    pool = CONFIG.get("cred_pool")
    if pool is not None:
        return {profile for entry in pool.entries() if (profile := pool._entry_profile(entry))
                and _in_region(profile, region)}
    cm = CONFIG.get("cred")
    if cm is not None:
        profile = cm.summary()["profile"]
        return {profile} if _in_region(profile, region) else set()
    known = {profile for profile in PROFILE_ENDPOINTS
             if _in_region(profile, region) and _catalog_for(profile) is not None}
    return known or ({"intl-cli"} if region == "intl" else {"cn-cli"})


def _usable_models(models):
    return [model for model in models or [] if model.get("id") and model.get("supportsToolCall")
            and not model.get("disabled")]


def _models_for_profile(profile: str, configured=None) -> list[dict]:
    models = _catalog_for(profile)
    if models is None:
        # 只有旧式国内 CLI 单产品部署保留静态兜底，不把未知表借给 WorkBuddy。
        configured = _configured_profiles(profile_region(profile)) if configured is None else configured
        return ([{"id": name, "supportsToolCall": True} for name in DEFAULT_MODELS]
                if CONFIG.get("model_cache") is None and CONFIG.get("account_catalogs") is None
                and profile == "cn-cli" and configured <= {"cn-cli"} else [])
    return _usable_models(models)


def _upstream_model(model: str | None, profile: str) -> str | None:
    return "default-model" if model == "auto" and profile_region(profile) == "intl" else model


def _free_multiplier(credits) -> bool:
    """目录 credits 倍率是否为 0（官方对当前账号声明的零计费标记）。"""
    if not isinstance(credits, str):
        return False
    match = re.fullmatch(r"x\s*0(?:\.0+)?\s*(?:credits?)?", credits.strip(), re.IGNORECASE)
    return match is not None


def _multiplier_value(credits):
    """解析官方倍率字符串为数值；无倍率或格式未知返回 None。"""
    if not isinstance(credits, str):
        return None
    match = re.fullmatch(r"x\s*([0-9]+(?:\.[0-9]+)?)\s*(?:credits?)?", credits.strip(), re.IGNORECASE)
    if match is None:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def _model_free(models, model: str | None, profile: str) -> bool:
    """该账号目录是否把此模型声明为 x0.00；名单里没有该模型时不算免费。"""
    if not model:
        return False
    routed = _upstream_model(model, profile)
    return any(item.get("id") == routed and _free_multiplier(item.get("credits"))
               for item in models or [])


def _model_profiles(model: str | None, region: str | None = None, configured=None) -> set[str]:
    configured = _configured_profiles(region) if configured is None else configured
    profiles = {profile for profile in PROFILE_ENDPOINTS if _in_region(profile, region)}
    if not model:
        return profiles
    supported = {profile for profile in profiles
                 if any(item["id"] == _upstream_model(model, profile)
                        for item in _models_for_profile(profile, configured))}
    if model == "auto" and region == "cn":
        # WorkBuddy 有真实 Auto 时固定用它；只有 CLI 的旧部署保留 auto，不混轮询两种默认策略。
        if "cn-work" in configured and "cn-work" in supported:
            return {"cn-work"}
        if "cn-cli" in configured and _models_for_profile("cn-cli", configured):
            return {"cn-cli"}
    if model == "auto" and region is None and "cn-cli" in configured and _models_for_profile("cn-cli", configured):
        supported.add("cn-cli")
    if model != "auto" and not supported and not CONFIG.get("model_guard") and len(configured) == 1:
        return configured
    return supported


def _catalog_pending(region: str | None = None) -> bool:
    pool = CONFIG.get("cred_pool")
    if CONFIG.get("model_cache") is None and CONFIG.get("account_catalogs") is None:
        return False
    if pool is not None and pool.sync_pending(region):
        return True
    return not any(_catalog_for(profile) is not None for profile in _configured_profiles(region))


def _profile_has_credits(profile: str) -> bool:
    pool = CONFIG.get("cred_pool")
    if pool is None:
        if profile_region(profile) == "cn":
            return True
        ledger = CONFIG.get("ledger")
        return bool(ledger and any((entry.get("credits") or {}).get("intl")
                                   and float((entry.get("credits") or {}).get("credits") or 0) > 0
                                   for entry in ledger.snapshot().values()))
    return any(pool._entry_profile(entry) == profile and pool._has_credit(entry, profile)
               for entry in pool.entries())


def current_models(region: str | None = None) -> list[str]:
    """合并账号可用的模型；客户端不用按地域改变请求地址。"""
    pool = CONFIG.get("cred_pool")
    if pool is not None:
        pool._rescan()
    with pool._lock if pool is not None else nullcontext():
        configured = _configured_profiles(region)
        out, has_auto = [], False
        auto_profiles = _model_profiles("auto", region, configured)
        if pool is not None and (CONFIG.get("account_catalogs") is not None or CONFIG.get("model_cache") is not None):
            accounts = CONFIG.get("account_catalogs") or {}
            for entry in pool.entries():
                profile = entry.get("profile")
                if not profile or not _in_region(profile, region):
                    continue
                # 零余额账号退出付费模型：不发布付费项，仅保留自身声明的零倍率模型。
                zero = pool._zero_balance(entry, profile)
                if not zero and not pool._has_credit(entry, profile):
                    continue
                account = accounts.get(entry.get("account_key")) or {}
                if account.get("profile") != profile:
                    continue
                models = _usable_models(account.get("models"))
                if zero:
                    models = [model for model in models if _free_multiplier(model.get("credits"))]
                out.extend(model["id"] for model in models)
                if profile in auto_profiles and models:
                    has_auto |= profile == "cn-cli" or any(model["id"] == _upstream_model("auto", profile) for model in models)
        else:
            for profile in sorted(configured):
                entries = ([entry for entry in pool.entries() if pool._entry_profile(entry) == profile]
                           if pool is not None else [])
                # 该产品全部账号余额归零时，只发布自身目录声明的零倍率模型。
                zero_only = bool(entries) and all(pool._zero_balance(entry, profile) for entry in entries)
                if _profile_has_credits(profile) or zero_only:
                    models = _models_for_profile(profile, configured)
                    if zero_only:
                        models = [model for model in models if _free_multiplier(model.get("credits"))]
                    out.extend(model["id"] for model in models)
                    has_auto |= bool(models) and profile in auto_profiles
        if has_auto:
            out.append("auto")
        return list(dict.fromkeys(out))


def current_model_details(region: str | None = None) -> list[dict]:
    """模型表（含倍率）：{id, credits, credits_by_profile}；credits 取各来源最小值。"""
    pool = CONFIG.get("cred_pool")
    if pool is not None:
        pool._rescan()
    details: dict[str, dict] = {}
    for name in current_models(region):
        details[name] = {"id": name, "credits": None, "credits_by_profile": {}}
    if pool is None:
        return list(details.values())
    with pool._lock:
        def record(profile: str, item: dict, *, zero: bool) -> None:
            name = item.get("id")
            if name not in details:
                return
            if zero and not _free_multiplier(item.get("credits")):
                return  # 零余额账号不参与付费模型的倍率展示
            value = _multiplier_value(item.get("credits"))
            if value is None:
                return
            details[name]["credits_by_profile"][profile] = value
            best = details[name]["credits"]
            details[name]["credits"] = value if best is None else min(best, value)

        if CONFIG.get("account_catalogs") is not None or CONFIG.get("model_cache") is not None:
            accounts = CONFIG.get("account_catalogs") or {}
            for entry in pool.entries():
                profile = entry.get("profile")
                if not profile or not _in_region(profile, region):
                    continue
                zero = pool._zero_balance(entry, profile)
                if not zero and not pool._has_credit(entry, profile):
                    continue
                account = accounts.get(entry.get("account_key")) or {}
                if account.get("profile") != profile:
                    continue
                for item in _usable_models(account.get("models")):
                    record(profile, item, zero=zero)
        else:
            configured = _configured_profiles(region)
            for profile in sorted(configured):
                entries = [entry for entry in pool.entries() if pool._entry_profile(entry) == profile]
                zero_only = bool(entries) and all(pool._zero_balance(entry, profile) for entry in entries)
                if not (_profile_has_credits(profile) or zero_only):
                    continue
                for item in _models_for_profile(profile, configured):
                    record(profile, item, zero=zero_only)
    return list(details.values())


def guard_model(name: str, *, region=None) -> None:
    """表外模型本地拒绝；自动路由只考虑各账号明确支持的模型。"""
    if not isinstance(name, str) or not name.strip():
        raise HTTPException(status_code=400, detail={"error": {
            "message": "model must be a non-empty string", "type": "invalid_request_error", "param": "model"}})
    if not CONFIG.get("model_guard"):
        return
    pool = CONFIG.get("cred_pool")
    if pool is not None:
        pool._rescan()
    if _model_profiles(name, region):
        return
    if _catalog_pending(region):
        raise HTTPException(status_code=503, headers={"Retry-After": "3"}, detail={"error": {
            "message": "模型目录正在同步，请稍后重试", "type": "service_unavailable", "code": "catalog_syncing"}})
    raise HTTPException(status_code=404, detail={"error": {
        "message": f"The model '{name}' is not supported by this gateway. See GET /v1/models.",
        "type": "invalid_request_error", "param": "model", "code": "model_not_found"}})

