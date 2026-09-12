#!/usr/bin/env python3
"""
codebuddy2api — 把 CodeBuddy / WorkBuddy 的订阅暴露成标准 OpenAI 兼容 API。

模块划分：
  runtime.py            版本 / CONFIG / 日志
  auth_store.py         凭据目录与种子导入
  credential_runtime.py 单凭据与多账号池
  model_table.py        模型目录与本地拦截
  housekeeping.py       积分 / 签到 / 目录后台同步
  chat_proxy.py         上游转发与 SSE
  protocol_api.py       Chat / Responses / Anthropic 路由
  usage_history.py      本机请求流水
  webui.py / webui.html 本机账号池管理页
  converter.py          入口、管理接口、login / serve
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from contextlib import nullcontext
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
import uvicorn

import auth_oauth
import trial_rewards
from credential_io import (
    CredentialFileError, atomic_write_credential, credential_file_lock, read_import_file,
)

from runtime import (
    APP_VERSION, BACKEND, CBC_VERSION, CONFIG, DEFAULT_DOMAIN, DEFAULT_MODELS,
    LOG_BACKUPS, LOG_MAX_BYTES, PASSTHROUGH_BODY_KEYS, USER_AGENT, _log, _log_json,
    _log_text_body, _network_error_text, _truncate,
)
from auth_store import (
    _cred_identity, _cred_uid, _credential_account, _credential_identity,
    auth_dirs, find_auth_file, find_auth_files, managed_auth_dir, seed_credentials,
)
from credential_runtime import (
    CredentialManager, CredentialPool, _dynamic_request_headers, _parse_reset_time,
    _refresher_loop, session_key,
)
from model_table import (
    _catalog_pending, _free_multiplier, _in_region, _model_profiles, _publish_model_cache,
    _upstream_model, current_model_details, current_models, guard_model,
    invalidate_model_table,
)
from housekeeping import _housekeep_once, _housekeeper_loop, _sync_credits
from usage_history import UsageHistory
from chat_proxy import (
    _check_auth, _chat_result_to_sse_lines, _collect_stream, _cred_for,
    _guard_request_size, _merge_chat_sse_text, _note_cred_status, _prepare_chat_body,
    _prepare_payload, _route_chat,
)
from protocol_api import (
    chat_completions, count_tokens, create_message, create_response, list_models,
    register as register_protocol_routes,
)
from webui import register as register_webui
from client_profiles import CLI_USER_AGENT, CLI_VERSION, account_key, catalog_cache_key, credential_headers
from site_routing import (
    DOMESTIC, INTERNATIONAL, PROFILE_ENDPOINTS, chat_url_for_headers, profile_for_auth,
    profile_for_headers, profile_product, profile_region, profile_site, refresh_url_for_auth,
    site_for_auth, site_for_headers,
)

try:
    import credits as credits_mod
except ImportError:
    credits_mod = None

app = FastAPI(title="codebuddy2api", version=APP_VERSION)
register_protocol_routes(app)
register_webui(app)

_OAUTH = auth_oauth.OAuthManager(user_agent=USER_AGENT)

@app.get("/health")
def health():
    """公开存活检查，不访问或暴露凭证池。"""
    return {"status": "ok"}


@app.get("/admin/credentials")
def admin_list_credentials(authorization: Optional[str] = Header(default=None),
                           x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """凭证池状态：账号、过期时间、健康度、黏绑会话数。"""
    _check_auth(authorization, x_api_key)
    pool = CONFIG.get("cred_pool")
    return {"credentials": pool.snapshot() if pool else []}


class CredentialConflictError(CredentialFileError):
    """同一账号已由其他凭据文件持有。"""


def _store_credential(directory: Path, name: str, content: bytes, uid: str, *, replace_identity=True) -> Path:
    """导入和登录共用的写入临界区，与后台刷新及独立 CLI 协调。"""
    pool = CONFIG.get("cred_pool")
    identity = _credential_identity(json.loads(content))
    target = directory.resolve() / name
    with pool._lock if pool is not None else nullcontext():
        cm = None
        if pool is not None:
            pool._rescan()
            holder = pool.find_by_uid(uid, identity)
            if holder and holder != str(target):
                raise CredentialConflictError("该账号已在凭证池中")
            entry = next((entry for entry in pool._entries if entry["id"] == str(target)), None)
            cm = entry["cm"] if entry else None
        elif CONFIG.get("cred") is not None and CONFIG["cred"].path.resolve() == target:
            cm = CONFIG["cred"]
        with cm._lock if cm is not None else nullcontext():
            with credential_file_lock(directory, name):
                if not replace_identity and target.exists() and _cred_identity(target) != identity:
                    raise CredentialConflictError("OAuth 不可覆盖其他产品或账号的凭据")
                target = atomic_write_credential(directory, name, content)
                if pool is not None:
                    pool.reload([target])
                elif cm is not None:
                    cm.invalidate()
    return target


@app.post("/admin/credentials")
async def admin_add_credential(request: Request,
                               authorization: Optional[str] = Header(default=None),
                               x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """从允许目录导入已校验的凭据，原子更新并热加入池。"""
    _check_auth(authorization, x_api_key)
    try:
        body = await request.json()
    except (ValueError, UnicodeError):
        raise HTTPException(status_code=400, detail={"error": {"message": "请求体必须是 JSON 对象", "type": "invalid_request_error"}}) from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail={"error": {"message": "请求体必须是 JSON 对象", "type": "invalid_request_error"}})
    dst_dir = managed_auth_dir().resolve()
    import_dir = Path(os.environ.get("CODEBUDDY_IMPORT_DIR") or dst_dir / "imports")
    try:
        name, content = read_import_file(import_dir, body.get("path"))
        cred_data = json.loads(content.decode("utf-8"))
        src_uid, verr = auth_oauth.validate_cred_data(cred_data)
        if verr:
            raise CredentialFileError("凭据格式或站点校验失败")
        if (not isinstance(cred_data.get("account") or {}, dict)
                or not isinstance(cred_data["auth"].get("expiresAt", 0), (int, float))):
            raise CredentialFileError("凭据账号或过期时间格式无效")
    except CredentialFileError:
        raise HTTPException(status_code=400, detail={"error": {"message": "凭据文件不符合导入要求", "type": "invalid_request_error"}}) from None
    except (ValueError, UnicodeError, RecursionError):
        raise HTTPException(status_code=400, detail={"error": {"message": "凭据必须是有效的 UTF-8 JSON 对象", "type": "invalid_request_error"}}) from None
    except OSError:
        raise HTTPException(status_code=400, detail={"error": {"message": "导入目录或文件不可读", "type": "invalid_request_error"}}) from None
    try:
        dst = _store_credential(dst_dir, name, content, src_uid)
    except CredentialConflictError:
        raise HTTPException(status_code=409, detail={"error": {"message": "该账号已在池中，请使用同文件名更新或先移除旧凭据", "type": "invalid_request_error"}}) from None
    except CredentialFileError:
        raise HTTPException(status_code=400, detail={"error": {"message": "凭据文件名或保存目标不符合要求", "type": "invalid_request_error"}}) from None
    except OSError:
        raise HTTPException(status_code=500, detail={"error": {"message": "凭据保存失败", "type": "server_error"}}) from None
    return {"imported": str(dst)}


@app.delete("/admin/credentials/{name}")
def admin_del_credential(name: str,
                         authorization: Optional[str] = Header(default=None),
                         x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """按文件名移除池内凭据（会删除该 *.info 文件）。"""
    _check_auth(authorization, x_api_key)
    pool = CONFIG.get("cred_pool")
    if pool is None or not pool.remove_file(os.path.basename(name)):
        raise HTTPException(status_code=404, detail={"error": {"message": f"凭据不在池中: {name}", "type": "invalid_request_error"}})
    return {"removed": os.path.basename(name)}



def _save_oauth_credential(cred: dict) -> Path:
    """按产品/账号/租户更新；另一产品同 UID 的文件不可被 OAuth 覆盖。"""
    uid, error = auth_oauth.validate_cred_data(cred)
    if error:
        raise CredentialFileError("凭据格式或站点校验失败")
    dst_dir = managed_auth_dir()
    identity = _credential_identity(cred)
    profile = profile_for_auth(cred["auth"])
    target = next((f for f in sorted(dst_dir.glob("*.info")) if _cred_identity(f) == identity), None)
    existing = None
    if target is not None:
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    name = target.name if target is not None else f"{uid}.info"
    if target is None and (dst_dir / name).exists():
        name = f"{uid}-{profile}.info"
        if (dst_dir / name).exists():
            name = f"{uid}-{profile}-{identity}.info"
        if (dst_dir / name).exists():
            raise CredentialConflictError("OAuth 保存目标已被其他身份占用")
    cred = auth_oauth.merge_existing_accounts(cred, existing)
    return _store_credential(
        dst_dir, name, json.dumps(cred, ensure_ascii=False, indent=2).encode("utf-8"), uid,
        replace_identity=False)


@app.post("/admin/oauth/start")
def admin_oauth_start(site: str = "cn",
                      authorization: Optional[str] = Header(default=None),
                      x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """无感登录第一步：申请 OAuth state + 授权链接（浏览器扫码即可，无需桌面端）。site=cn|intl。"""
    _check_auth(authorization, x_api_key)
    try:
        return _OAUTH.start(site=site)
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"error": {"message": str(e), "type": "invalid_request_error"}})
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": {"message": f"发起失败: {e}", "type": "upstream_error"}})


@app.get("/admin/oauth/poll")
def admin_oauth_poll(login_id: str = "",
                     authorization: Optional[str] = Header(default=None),
                     x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """无感登录第二步：轮询授权结果；完成后自动入库并热加入凭证池（同 uid 覆盖更新）。"""
    _check_auth(authorization, x_api_key)
    try:
        r = _OAUTH.poll(login_id)
    except Exception as e:
        raise HTTPException(status_code=502, detail={"error": {"message": f"轮询失败: {e}", "type": "upstream_error"}})
    if not r.get("done"):
        return {"done": False}
    cred = r.get("cred")
    if r.get("error") or not cred:
        return {"done": True, "error": r.get("error") or "登录失败"}
    uid = r["uid"]
    try:
        target = _save_oauth_credential(cred)
    except CredentialFileError:
        return {"done": True, "error": "凭据格式、站点或保存目标不符合要求"}
    except OSError:
        raise HTTPException(status_code=500, detail={"error": {"message": "凭据保存失败", "type": "server_error"}}) from None
    _log(f"[oauth] 无感登录已入库: {r.get('nickname') or uid} ({uid}) -> {target.name}")
    return {"done": True, "uid": uid, "nickname": r.get("nickname") or "", "imported": str(target)}

@app.get("/admin/credits")
def admin_credits(authorization: Optional[str] = Header(default=None),
                  x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """各凭证积分余额/分段过期时间/今日签到状态（CreditLedger 缓存快照）。"""
    _check_auth(authorization, x_api_key)
    ledger = CONFIG.get("ledger")
    return {"credits": ledger.snapshot() if ledger else {}}


@app.post("/admin/checkin")
def admin_checkin(authorization: Optional[str] = Header(default=None),
                  x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """手动触发一轮签到 + 积分刷新（签到按日幂等，已签则只刷积分）。"""
    _check_auth(authorization, x_api_key)
    pool, ledger = CONFIG.get("cred_pool"), CONFIG.get("ledger")
    if pool is None or ledger is None:
        raise HTTPException(status_code=503, detail={"error": {"message": "签到调度未启用", "type": "invalid_request_error"}})
    _housekeep_once(pool, ledger, sync_usage=True)
    snap = ledger.snapshot()
    results = []
    for entry in pool.snapshot():
        info = snap.get(entry["auth_file"]) or {}
        checkin = info.get("checkin") or {}
        results.append({
            "nickname": entry.get("nickname") or entry.get("uid"),
            "profile": entry.get("profile"),
            "ok": bool(checkin.get("ok")),
            "code": checkin.get("code"),
            "message": checkin.get("message") or "",
            "date": checkin.get("date"),
        })
    return {"credits": snap, "results": results}


@app.get("/admin/usage")
def admin_usage(authorization: Optional[str] = Header(default=None),
                x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """本机最近请求流水 + 官方按日用量缓存。"""
    _check_auth(authorization, x_api_key)
    history = CONFIG.get("usage_history")
    cache = CONFIG.get("usage_daily") or {}
    days = []
    for day in sorted(cache.get("by_day") or {}, reverse=True):
        models = cache["by_day"][day] or {}
        credits = round(sum(float(value or 0) for value in models.values()), 4)
        days.append({"date": day, "credits": credits, "models": models})
    return {
        "requests": history.snapshot() if history else [],
        "official": {
            "fetched_at": cache.get("fetched_at"),
            "requests": cache.get("requests") or 0,
            "total_credits": cache.get("total_credits") or 0,
            "days": days,
        },
    }


# ---------------------------------------------------------------------------
# OpenAI 兼容余额端点：Credits 按订阅摊算口径折算为美元
# ---------------------------------------------------------------------------

def _billing_totals() -> dict:
    """余额快照：国内/国际分组折算（两站积分独立且单价不同）。

    已用量优先取官方明细的实际扣减，明细缺失时回退「总额度 − 剩余」。"""
    empty_grp = {"remaining": 0.0, "used_by_quota": 0.0, "soonest_expiry": None}
    ledger = CONFIG.get("ledger")
    snap = ledger.snapshot() if ledger else {}
    price_cny = CONFIG.get("credit_price_cny") or (credits_mod.CREDIT_PRICE_CNY if credits_mod else 0.014)
    price_usd = CONFIG.get("credit_price_usd") or (credits_mod.CREDIT_PRICE_USD if credits_mod else 0.03)
    rate = CONFIG.get("usd_rate") or (credits_mod.USD_RATE_CNY if credits_mod else 7.15)
    agg = (credits_mod.aggregate_credits(snap) if credits_mod else
           {"remaining": 0.0, "used_by_quota": 0.0, "soonest_expiry": None,
            "groups": {"domestic": dict(empty_grp), "international": dict(empty_grp)}})
    cache = CONFIG.get("usage_daily") or {}
    detail = bool(cache.get("fetched_at"))
    detail_groups = cache.get("groups") or {}
    per_usd = {"domestic": price_cny / rate, "international": price_usd}
    remaining = used = rem_usd = used_usd = rem_cny = 0.0
    groups_out: dict = {}
    for grp, g in (agg.get("groups") or {}).items():
        r = float(g.get("remaining") or 0)
        gd = detail_groups.get(grp)
        u = (float(gd.get("total_credits") or 0) if (detail and gd)
             else float(g.get("used_by_quota") or 0))  # 该组无明细则回退额度差
        unit = per_usd.get(grp, 0.0)
        remaining += r
        used += u
        rem_usd += r * unit
        used_usd += u * unit
        rem_cny += r * (unit * rate if grp == "international" else price_cny)
        groups_out[grp] = {"credits_remaining": round(r, 2), "credits_used": round(u, 2),
                           "balance_usd": round(r * unit, 4),
                           "price_usd_per_credit": round(unit, 6)}
    return {"remaining": round(remaining, 2), "used": round(used, 2),
            "quota": round(remaining + used, 2),
            "remaining_usd": round(rem_usd, 4), "used_usd": round(used_usd, 4),
            "quota_usd": round(rem_usd + used_usd, 4),
            "remaining_cny": round(rem_cny, 4),
            "soonest_expiry": agg.get("soonest_expiry"),
            "price_cny": price_cny, "price_usd": price_usd, "rate": rate,
            "used_source": "official_usage_detail" if detail else "quota_delta",
            "groups": groups_out, "by_day": cache.get("by_day") or {}}


@app.get("/v1/dashboard/billing/subscription")
def billing_subscription(authorization: Optional[str] = Header(default=None),
                         x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """OpenAI 订阅端点外观：hard_limit_usd 为总额度折算，故余额 = hard_limit_usd − usage/100。"""
    _check_auth(authorization, x_api_key)
    t = _billing_totals()
    limit = t["quota_usd"]
    return {
        "object": "billing_subscription",
        "has_payment_method": True, "canceled": False, "canceled_at": None, "delinquent": None,
        # access_until 取池内最早积分过期时间：过期即额度归零的保守表达
        "access_until": int(t["soonest_expiry"] or (time.time() + 30 * 86400)),
        "soft_limit": int(limit * 100), "hard_limit": int(limit * 100),
        "soft_limit_usd": limit, "hard_limit_usd": limit, "system_hard_limit_usd": limit,
        "plan": {"title": f"CodeBuddy Credits (CN {t['price_cny']:g} CNY/credit · "
                                        f"INTL {t['price_usd']:g} USD/credit)"},
        # 扩展字段：直接给出总计金额与各站拆分，未知字段的客户端会忽略
        "codebuddy_credits_remaining": t["remaining"],
        "codebuddy_credits_used": t["used"],
        "codebuddy_balance_usd": t["remaining_usd"],
        "codebuddy_balance_cny": t["remaining_cny"],
        "codebuddy_sites": t["groups"],
    }


@app.get("/v1/dashboard/billing/usage")
def billing_usage(start_date: Optional[str] = None, end_date: Optional[str] = None,
                  authorization: Optional[str] = Header(default=None),
                  x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """OpenAI 用量端点：total_usage 单位美分；daily_costs 为官方明细按天×模型聚合（最近 30 天）。"""
    _check_auth(authorization, x_api_key)
    t = _billing_totals()
    # 每 Credit 美分单价：按各站实际用量加权（保证 Σdaily 与 total_usage 一致）
    cents_per_credit = ((t["used_usd"] * 100 / t["used"]) if t["used"]
                        else t["price_cny"] / t["rate"] * 100)
    daily = []
    for day in sorted(t["by_day"]):
        if start_date and day < start_date:
            continue
        if end_date and day > end_date:
            continue
        items = [{"name": m, "cost": round(c * cents_per_credit, 4)}
                 for m, c in sorted(t["by_day"][day].items()) if c > 0]
        try:
            ts = int(time.mktime(time.strptime(day, "%Y-%m-%d")))
        except ValueError:
            ts = 0
        daily.append({"timestamp": ts, "line_items": items})
    if start_date or end_date:  # 指定区间时按区间明细求和
        total_cents = round(sum(sum(i["cost"] for i in d["line_items"]) for d in daily), 2)
    else:                      # 全量口径与 subscription 构成余额恒等式
        total_cents = round(t["used_usd"] * 100, 2)
    return {"object": "list", "total_usage": total_cents, "daily_costs": daily}


def preflight() -> bool:
    files = find_auth_files()
    sys.stderr.write("==== 预检 ====\n")
    sys.stderr.write(f"平台      : {sys.platform}\n")
    sys.stderr.write(f"Python    : {sys.version.split()[0]}\n")
    sys.stderr.write(f"后端      : {BACKEND} (直连，原生 function calling)\n")
    sys.stderr.write(f"自管目录  : {managed_auth_dir()}\n")
    sys.stderr.write(f"登录文件  : {len(files)} 个\n")
    if not os.environ.get("CODEBUDDY_AUTH_DIR"):
        sys.stderr.write(f"种子来源  : {', '.join(str(d) for d in auth_dirs())}\n")
    ok = True
    if not files:
        sys.stderr.write("\n[警告] 未找到登录文件。请运行 python3 converter.py login 扫码添加账号，或用 --auth-file 指定。\n")
        ok = False
    for af in files:
        try:
            cm = CredentialManager(af)
            info = cm.summary()
            sys.stderr.write(f"账号      : {info.get('nickname')} / {info.get('enterpriseName')}  ({af.name})\n")
            sys.stderr.write(f"token过期 : {'是(将自动刷新)' if info['token_expired'] else '否'}\n")
        except Exception as e:
            sys.stderr.write(f"[警告] 读取凭据失败 {af.name}：{e}\n")
            ok = False
    sys.stderr.write("================\n")
    return ok


def login(site: str = "cn", open_browser: bool = True) -> int:
    """独立完成扫码与入库；凭据只写入自管目录，不经过本地 HTTP 接口。"""
    import webbrowser

    try:
        started = _OAUTH.start(site=site)
        uri = started["verification_uri"]
        print(f"请打开以下链接扫码登录：\n{uri}", flush=True)
        if open_browser:
            try:
                opened = webbrowser.open(uri)
            except webbrowser.Error:
                opened = False
            if not opened:
                print("无法自动打开浏览器，请手动打开上面的链接。", flush=True)
        print("正在等待扫码授权；网页显示登录成功后，请继续等待终端确认入库。\n"
              "按 Ctrl+C 取消。", flush=True)
        while True:
            result = _OAUTH.poll(started["login_id"])
            if result.get("done"):
                if result.get("error") or not result.get("cred"):
                    print(f"登录失败：{result.get('error') or '未获取到凭据'}", file=sys.stderr)
                    return 1
                target = _save_oauth_credential(result["cred"])
                print(f"登录成功，账号已保存至：{target}\n"
                      "使用同一凭据目录的服务会在下次请求时自动加载（默认目录扫描模式）。",
                      flush=True)
                return 0
            time.sleep(1.5)
    except KeyboardInterrupt:
        print("\n已取消登录。", file=sys.stderr)
        return 130
    except CredentialFileError as e:
        print(f"登录失败：{e}", file=sys.stderr)
        return 1
    except OSError:
        print("登录失败：无法保存凭据，请检查凭据目录的写入权限。", file=sys.stderr)
        return 1
    except (httpx.HTTPError, ValueError, RuntimeError):
        # 上游异常可能包含授权 URL 或响应正文，不向终端转储。
        print("登录失败：登录接口请求失败或响应无效，请检查网络后重试。", file=sys.stderr)
        return 1


def _nonnegative_int(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("必须为非负整数")
    return number


def _positive_int(value):
    number = _nonnegative_int(value)
    if number == 0:
        raise argparse.ArgumentTypeError("必须为正整数")
    return number


def _boolean_arg(value):
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in ("true", "1", "yes", "on"):
        return True
    if normalized in ("false", "0", "no", "off"):
        return False
    raise argparse.ArgumentTypeError("必须为 true 或 false")


def main():
    ap = argparse.ArgumentParser(description="CodeBuddy -> OpenAI 兼容转换器（直连后端）")
    ap.add_argument("command", nargs="?", choices=("serve", "login"), default="serve",
                    help="serve 启动服务（默认）；login 扫码登录、自动轮询并保存账号")
    ap.add_argument("--site", choices=tuple(auth_oauth.SITE_HOSTS), default="cn",
                    help="login 使用的站点：cn 国内站（默认），intl 国际站")
    ap.add_argument("--no-browser", action="store_true",
                    help="login 仅显示授权链接，不自动打开浏览器（服务器/容器环境）")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--api-key", default=os.environ.get("CODEBUDDY2API_KEY", ""),
                    help="可选：要求客户端携带的 API key（默认不校验）")
    ap.add_argument("--log", default=None, metavar="PATH",
                    help="开启日志并写到该文件（如 --log converter.log 或 --log /tmp/cb.log）。"
                         "不传则不记日志。")
    ap.add_argument("--desensitize", action="store_true",
                    help="启用脱敏：对 system 消息里的合规模板敏感词（DoS/exploit/credential 等）"
                         "插入零宽空格，缓解被后端内容审核误拦。默认关闭。")
    ap.add_argument("--no-compact", action="store_true",
                    help="配合 --desensitize 使用：跳过 system/harness 压缩，仅做零宽脱敏。"
                         "保留原始 system prompt 完整内容（如 Claude Code 的行为指令），"
                         "但审核误拦风险略高于默认压缩模式。")
    ap.add_argument("--skip-check", action="store_true", help="跳过启动预检")
    ap.add_argument("--auth-file", action="append", default=[], metavar="PATH",
                    help="凭据文件（可重复传入组成凭证池；默认自动扫描 auth 目录全部 *.info）")
    ap.add_argument("--credit-price-cny", type=float, default=None, metavar="PRICE",
                    help="积分折算单价（元/Credit），默认 0.014（旗舰版连续包月 700元/5万积分摊算）")
    ap.add_argument("--usd-rate", type=float, default=None, metavar="RATE",
                    help="人民币→美元汇率，影响 /v1/dashboard/billing 端点金额")
    ap.add_argument("--credit-price-usd", type=float, default=None, metavar="PRICE",
                    help="国际站积分折算单价（美元/Credit），默认 0.03（Pro 加量包 $15/500 积分）")
    ap.add_argument("--model-catalog-ttl", type=int, default=6 * 3600, metavar="SECONDS",
                    help="云端模型表缓存有效期，默认 21600 秒（6 小时）；TTL 内不再打 /v3/config")
    ap.add_argument("--no-model-guard", action="store_true",
                    help="关闭表外模型本地拦截；默认拦截，避免无效请求打到上游并触发扣费")
    ap.add_argument("--max-images", type=_nonnegative_int, metavar="N",
                    default=os.environ.get("CODEBUDDY2API_MAX_IMAGES", "16"),
                    help="单请求图片上限，默认 16；0 表示不允许图片")
    ap.add_argument("--image-policy", choices=("truncate", "error"),
                    default=os.environ.get("CODEBUDDY2API_IMAGE_POLICY", "truncate"),
                    help="超额图片策略：truncate 保留最新图片（默认），error 返回 413")
    ap.add_argument("--max-request-bytes", type=_positive_int, metavar="BYTES",
                    default=os.environ.get("CODEBUDDY2API_MAX_REQUEST_BYTES", str(32 * 1024 * 1024)),
                    help="图片处理与适配后请求体的字节上限，默认 32 MiB")
    ap.add_argument("--log-body-limit", type=_nonnegative_int, metavar="BYTES",
                    default=os.environ.get("CODEBUDDY2API_LOG_BODY_LIMIT", "65536"),
                    help="每条正文日志的预览字节上限，默认 64 KiB；0 只记录摘要")
    ap.add_argument("--auto-trial", type=_boolean_arg, nargs="?", const=True,
                    default=os.environ.get("CODEBUDDY2API_AUTO_TRIAL", "false"),
                    help="自动领取国际 WorkBuddy 一次性体验积分，默认关闭")
    args = ap.parse_args()
    if args.image_policy not in ("truncate", "error"):
        ap.error("CODEBUDDY2API_IMAGE_POLICY 必须为 truncate 或 error")
    if args.command == "login":
        return login(site=args.site, open_browser=not args.no_browser)

    for key in ("max_images", "image_policy", "max_request_bytes", "log_body_limit", "auto_trial"):
        CONFIG[key] = getattr(args, key)
    CONFIG["api_key"] = args.api_key
    CONFIG["trial_ledger"] = (trial_rewards.TrialLedger(managed_auth_dir() / "trial-ledger.json")
                              if args.auto_trial else None)
    CONFIG["desensitize"] = args.desensitize
    CONFIG["no_compact"] = args.no_compact
    CONFIG["credit_price_cny"] = args.credit_price_cny or None
    CONFIG["usd_rate"] = args.usd_rate or None
    CONFIG["credit_price_usd"] = args.credit_price_usd or None
    CONFIG["model_guard"] = not args.no_model_guard
    # --log 直接指定文件路径即开启；不传则不记
    CONFIG["log_path"] = args.log if args.log else os.environ.get("CODEBUDDY2API_LOG")
    files = [Path(p) for p in args.auth_file]
    if not files:
        seed_credentials()  # 自管模式：启动时把桌面端缺失凭据复制进 auth/
    CONFIG["cred_pool"] = CredentialPool(files, scan=not files)
    CONFIG["cred"] = CONFIG["cred_pool"].first()
    CONFIG["usage_history"] = UsageHistory(managed_auth_dir() / "usage-history.json")
    CONFIG["account_catalogs"] = {}  # 在任何维护线程/预检启动前关闭静态兜底。
    if credits_mod is not None:
        ledger = credits_mod.CreditLedger(managed_auth_dir() / "credits-ledger.json")
        CONFIG["ledger"] = ledger
        CONFIG["model_cache"] = credits_mod.ModelCatalogCache(
            managed_auth_dir() / "model-catalog.json", ttl=args.model_catalog_ttl)
        CONFIG["cred_pool"].set_ledger(ledger)  # 先验证持久余额所属身份，再发布目录（包括空表）。
    _publish_model_cache()
    threading.Thread(target=_refresher_loop, args=(CONFIG["cred_pool"],),
                     daemon=True, name="cred-refresher").start()
    if credits_mod is not None:
        threading.Thread(target=_housekeeper_loop, args=(CONFIG["cred_pool"], ledger),
                         daemon=True, name="cred-housekeeper").start()

    if not args.skip_check:
        preflight()

    sys.stderr.write(f"\n✅ 监听 http://{args.host}:{args.port}（直连后端，原生 function calling）\n")
    sys.stderr.write(f"   管理界面: http://{args.host}:{args.port}/\n")
    sys.stderr.write("   GET  /v1/models\n")
    sys.stderr.write("   POST /v1/chat/completions   (原生 tools/tool_calls，支持流式)\n")
    sys.stderr.write("   POST /v1/responses          (Responses API，Codex CLI 兼容)\n")
    sys.stderr.write("   POST /v1/messages           (Anthropic API，Claude Code / CC Switch 兼容)\n")
    sys.stderr.write("   GET  /health\n")
    sys.stderr.write("   GET/POST/DELETE /admin/credentials  (凭证池管理)\n")
    sys.stderr.write("   添加账号：python3 converter.py login（自动等待扫码并保存）\n")
    if credits_mod is not None:
        sys.stderr.write("   GET  /admin/credits           (积分/签到状态)\n")
        sys.stderr.write("   POST /admin/checkin           (手动触发签到+积分刷新)\n")
        sys.stderr.write("   每日签到 + 快过期积分优先调度已启用\n")
    if args.api_key:
        sys.stderr.write("   鉴权已启用（API key 已设置）\n")
    sys.stderr.write(f"   图片限制  : {CONFIG['max_images']} 张/请求，策略 {CONFIG['image_policy']}\n")
    if CONFIG["log_path"]:
        sys.stderr.write(f"   日志      : {CONFIG['log_path']}\n")
    if args.desensitize:
        mode = "零宽脱敏 + 保留全文" if args.no_compact else "零宽脱敏 + 压缩摘要"
        sys.stderr.write(f"   脱敏      : 已启用（{mode}）\n")
    sys.stderr.write("按 Ctrl+C 退出。\n\n")

    # 启动时写一条标记
    _log(f"==== converter 启动 ====")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    sys.exit(main())
