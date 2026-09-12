"""上游 Chat 转发、SSE 聚合、脱敏与体积限制。"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

import httpx
from fastapi import HTTPException
from fastapi.responses import JSONResponse

from anthropic_adapter import AnthropicStreamConverter
from credential_runtime import _dynamic_request_headers, session_key
from desensitize import desensitize_body
from model_table import _catalog_pending, _in_region, _upstream_model, guard_model
from request_limits import ImageLimitError, apply_image_policy
from responses_adapter import ResponsesStreamConverter
import runtime
from runtime import CONFIG, _network_error_text, _truncate
from safe_logging import sanitize_log_text
from site_routing import chat_url_for_headers, profile_for_headers, profile_region
from upstream_io import ChatSSEAccumulator, UpstreamResponseError, open_backend_stream

def _check_auth(authorization: Optional[str], x_api_key: Optional[str]):
    key = CONFIG["api_key"]
    if not key:
        return
    token = ""
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
    if not token and x_api_key:
        token = x_api_key
    if token != key:
        raise HTTPException(status_code=401, detail={"error": {"message": "invalid api key", "type": "auth_error"}})


def _cred_for(payload: dict, model: str | None = None, *, region=None):
    """返回 ((凭据管理器, 代次), headers)；无可用凭据返回 503，模型冷却返回 429。"""
    raw_key = session_key(payload)
    skey = f"{region}:{raw_key}" if raw_key and region is not None else raw_key
    pool = CONFIG.get("cred_pool")
    if pool is not None:
        picked = pool.headers_for(skey, model, region=region, with_generation=True)
        if picked is None:
            until = pool.model_cooldown_until(model, region=region)
            if until:
                t = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(until))
                raise HTTPException(status_code=429, detail={"error": {
                    "message": f"模型 {model} 额度冷却中（全部凭证），预计 {t} 重置后恢复",
                    "type": "rate_limit_error"}})
            raise HTTPException(status_code=503, headers={"Retry-After": "3" if _catalog_pending(region) else "30"},
                                detail={"error": {"message": "无可用凭证（未登录、目录/额度未就绪或全部熔断）",
                                                  "type": "auth_error"}})
        cm, headers = picked
    else:
        cm = CONFIG["cred"]
        if cm is None:
            raise HTTPException(status_code=503, detail={"error": {"message": "未找到登录凭据，请先在桌面端登录 CodeBuddy/WorkBuddy", "type": "auth_error"}})
        with cm._lock:
            headers = cm.get_headers()
            cm = (cm, cm._generation)
    profile = profile_for_headers(headers)
    if not _in_region(profile, region):
        raise HTTPException(status_code=503, detail={"error": {"message": "未找到指定地域凭据", "type": "auth_error"}})
    headers.update(_dynamic_request_headers(f"{profile}:{skey}" if skey else None))
    return cm, headers


def _route_chat(payload, body, rid):
    """根据所选账号自动确定后端地域、产品及模型，不改变客户端地址。"""
    cred, headers = _cred_for(payload, body.get("model"))
    profile = profile_for_headers(headers)
    routed_model = _upstream_model(body.get("model"), profile)
    if routed_model != body.get("model"):
        body = {**body, "model": routed_model}
        _guard_request_size(body)
    url = chat_url_for_headers(headers)
    runtime._log(f"[{rid}] ROUTE | region={profile_region(profile)} | profile={profile} | model={routed_model} | url={url}")
    return body, cred, headers, url


def _note_cred_status(cred, status: int, model: str | None = None, raw: bytes = b""):
    """后端 401/403 熔断该凭证；429 按 (凭证,模型) 冷却。黏性会话下次请求自动换绑。"""
    pool = CONFIG.get("cred_pool")
    if pool is not None and cred is not None:
        cm, generation = cred if isinstance(cred, tuple) else (cred, None)
        pool.note_status(cm, status, model=model, raw=raw, generation=generation)


def _prepare_payload(payload, field="messages") -> dict:
    """先处理整次请求的图片，再进行适配、日志记录和凭证选取。"""
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail={"error": {
            "message": "请求体必须是 JSON 对象", "type": "invalid_request_error"}})
    try:
        prepared, stats = apply_image_policy(
            payload, field=field, max_images=CONFIG["max_images"], policy=CONFIG["image_policy"])
    except ImageLimitError as error:
        runtime._log(f"[limit] 图片超限，拒绝请求 | count={error.count} | limit={error.limit}")
        raise HTTPException(status_code=413, detail={"error": {
            "message": str(error), "type": "invalid_request_error", "param": field,
            "code": "too_many_images", "image_count": error.count, "max_images": error.limit}}) from None
    if stats["dropped"]:
        runtime._log(f"[limit] 保留最新图片 | count={stats['count']} | retained={stats['retained']} | dropped={stats['dropped']}")
    return prepared


def _normalize_tool_choice(body):
    """上游只接收字符串；点名调用等价于仅提供该工具并设 required。"""
    choice = body.get("tool_choice")
    if not isinstance(choice, dict):
        return
    function = choice.get("function", choice)
    name = function.get("name") if isinstance(function, dict) else None
    tools = body.get("tools")
    matches = [tool for tool in tools if isinstance(tool, dict) and tool.get("type") == "function"
               and isinstance(tool.get("function"), dict) and tool["function"].get("name") == name] if isinstance(tools, list) else []
    if choice.get("type") != "function" or not isinstance(name, str) or not name.strip() or len(matches) != 1:
        raise HTTPException(status_code=400, detail={"error": {"message": "tool_choice must name exactly one declared function",
                            "type": "invalid_request_error", "param": "tool_choice"}})
    body["tools"], body["tool_choice"] = matches, "required"


def _prepare_chat_body(body: dict, *, region=None) -> dict:
    """统一模型、首条 system、后端流式参数、脱敏与体积预算。"""
    body = dict(body)
    body.setdefault("model", "auto")
    guard_model(body["model"], region=region)
    messages = body.get("messages")
    if not isinstance(messages, list) or not messages or any(not isinstance(message, dict) for message in messages):
        raise HTTPException(status_code=400, detail={"error": {
            "message": "messages must be a non-empty array of objects", "type": "invalid_request_error"}})
    if messages[0].get("role") != "system":
        system_index = next((index for index, message in enumerate(messages) if message.get("role") == "system"), None)
        if system_index is None:
            messages = [{"role": "system", "content": "You are a helpful assistant."}, *messages]
        else:
            messages = [messages[system_index], *messages[:system_index], *messages[system_index + 1:]]
        body["messages"] = messages
    _normalize_tool_choice(body)
    body["stream"] = True
    body.setdefault("stream_options", {"include_usage": True})
    body = _chat_body_desensitize(body)
    _guard_request_size(body)
    return body


def _guard_request_size(body: dict) -> None:
    """限制处理后发往上游的 JSON 字节数，不截断文本或工具参数。"""
    size = 0
    limit = CONFIG["max_request_bytes"]
    try:
        for part in json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False).iterencode(body):
            size += len(part.encode("utf-8"))
            if size > limit:
                runtime._log(f"[limit] 请求体超限，拒绝请求 | limit_bytes={limit}")
                raise HTTPException(status_code=413, detail={"error": {
                    "message": f"处理后的请求体超过网关上限 {limit} 字节，请缩短历史或压缩图片",
                    "type": "invalid_request_error", "code": "request_too_large", "max_bytes": limit}})
    except (ValueError, UnicodeError) as error:
        raise HTTPException(status_code=400, detail={"error": {
            "message": "请求体包含无法序列化的 JSON 值", "type": "invalid_request_error"}}) from None


def _last_user_text(messages: list) -> str:
    """取最后一条 user 消息的文本，用于日志预览。"""
    for m in reversed(messages):
        if m.get("role") != "user":
            continue
        content = m.get("content", "")
        if isinstance(content, list):
            for blk in content:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    return str(blk.get("text", ""))
            return ""
        return str(content)
    return ""


def _log_finish(model_name: str, t0: float, result: dict, rid: str = ""):
    """记录完成请求的耗时、结束原因、用量、工具调用和有界响应预览。"""
    elapsed = time.time() - t0
    prefix = f"[{rid}] " if rid else ""
    choice = (result.get("choices") or [{}])[0]
    finish = choice.get("finish_reason")
    msg = choice.get("message") or {}
    tcs = msg.get("tool_calls") or []
    usage = result.get("usage") or {}
    tag = ""
    if finish == "content-filter":
        tag = " ⚠️内容审核拦截"
    tc_names = [t.get("function", {}).get("name") for t in tcs]
    runtime._log(f"{prefix}◀ RESPONSE {model_name} | {elapsed:.1f}s | finish={finish}{tag}"
         + (f" | tool_calls={tc_names}" if tc_names else "")
         + f" | tokens={usage.get('total_tokens', '?')}")
    runtime._log_json(f"{prefix}RESPONSE BODY (预览)", result)


def _chat_completion(merged: dict) -> dict:
    message = {"role": "assistant", "content": merged["content"] or None}
    for key in ("reasoning_content", "refusal", "tool_calls"):
        if merged.get(key):
            message[key] = merged[key]
    return {
        "id": "chatcmpl-" + os.urandom(12).hex(), "object": "chat.completion",
        "created": int(time.time()), "model": merged.get("model") or "unknown",
        "choices": [{"index": 0, "message": message,
                     "finish_reason": merged.get("finish_reason") or ("tool_calls" if merged.get("tool_calls") else "stop")}],
        "usage": merged.get("usage") or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _completion_to_merged(result: dict) -> dict:
    choice = result["choices"][0]
    return {**choice["message"], "finish_reason": choice["finish_reason"],
            "model": result.get("model"), "usage": result.get("usage")}


async def _collect_stream(response: httpx.Response) -> dict:
    """使用公共聚合器保留正文、思考和工具调用，并验证流完整性。"""
    accumulator = ChatSSEAccumulator()
    async for line in response.aiter_lines():
        accumulator.feed_line(line)
        if accumulator.done:
            break
    return _chat_completion(accumulator.result())


_TOOL_CALL_MAX_RETRY = 3


def _tool_choice_satisfied(tool_calls, body):
    choice = body.get("tool_choice")
    if choice == "none":
        return not tool_calls
    if choice != "required":
        return True
    names = {tool.get("function", {}).get("name") for tool in body.get("tools", [])
             if isinstance(tool, dict) and isinstance(tool.get("function"), dict)}
    return bool(tool_calls) and all(call.get("function", {}).get("name") in names for call in tool_calls)


def _tool_calls_healthy(tool_calls) -> bool:
    """校验聚合后的 tool_calls：name 非空且 arguments 为合法 JSON。"""
    if not tool_calls:
        return True
    for tc in tool_calls:
        if not isinstance(tc.get("id"), str) or not tc["id"].strip():
            return False
        fn = tc.get("function") or {}
        if not (fn.get("name") or "").strip() or not (fn.get("arguments") or "").strip():
            return False
        try:
            json.loads(fn.get("arguments") or "")
        except Exception:
            return False
    return True


def _merge_chat_sse_text(text: str) -> dict:
    """文本路径与异步流路径使用同一聚合器。"""
    accumulator = ChatSSEAccumulator()
    for line in text.splitlines():
        accumulator.feed_line(line)
    return accumulator.result()


def _chat_result_to_sse_lines(m: dict) -> list[str]:
    """把聚合结果伪流式化为标准 OpenAI SSE 文本行（chat 直接转发，anthropic 喂转换器）；reasoning 先于正文重放。"""
    content = m.get("content") or ""
    reasoning = m.get("reasoning_content") or ""
    tcs = m.get("tool_calls") or []
    finish = m.get("finish_reason") or "stop"
    model = m.get("model")

    def _line(delta: dict, fr=None) -> str:
        payload = {"choices": [{"index": 0, "delta": delta, "finish_reason": fr}]}
        if model:
            payload["model"] = model
        return "data: " + json.dumps(payload, ensure_ascii=False)

    lines = [_line({"role": "assistant", "content": ""})]
    for i in range(0, len(reasoning), 48):
        lines.append(_line({"reasoning_content": reasoning[i:i + 48]}))
    for i in range(0, len(content), 48):
        lines.append(_line({"content": content[i:i + 48]}))
    refusal = m.get("refusal") or ""
    for i in range(0, len(refusal), 48):
        lines.append(_line({"refusal": refusal[i:i + 48]}))
    for i, tc in enumerate(tcs):
        lines.append(_line({"tool_calls": [dict(tc, index=i)]}))
    lines.append(_line({}, finish))
    if m.get("usage"):
        lines.append("data: " + json.dumps({"choices": [], "usage": m["usage"]}, ensure_ascii=False))
    lines.append("data: [DONE]")
    return lines


def _backend_stream(url, headers, body, *, timeout=300, rid="", model_name="?"):
    return open_backend_stream(
        url, headers, body, read_timeout=timeout,
        on_retry=lambda error: runtime._log(
            f"[{rid}] 建连失败，重试 1/1 | {model_name} | {_network_error_text(error)}"),
    )


def _safe_err_raw(raw: bytes, status: int) -> dict:
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        return {"error": {"message": raw.decode("utf-8", "replace")[:500], "type": "upstream_error", "code": status}}


def _check_upstream_status(status, raw, cred, model):
    if status != 200:
        _note_cred_status(cred, status, model=model, raw=raw)
        raise UpstreamResponseError(status, raw)


def _upstream_failure(error, model_name, t0, rid):
    """统一失败日志与错误体，协议包装由各端点负责。"""
    if isinstance(error, UpstreamResponseError):
        status, raw = error.status, error.raw
        category = f"HTTP {status}"
    else:
        status, raw = 502, _network_error_text(error).encode("utf-8")
        category = "网络错误"
    elapsed = time.time() - t0 if t0 else 0
    runtime._log(f"[{rid}] ✗ {category} | {model_name} | {elapsed:.1f}s | {sanitize_log_text(raw.decode('utf-8', 'replace'), 512)}")
    runtime._log_text_body(f"[{rid}] ERROR BODY", raw.decode("utf-8", "replace"))
    return status, raw


async def _fetch_checked_chat(url, headers, body, model_name, rid, cred=None, *, filter_retry=False):
    """统一聚合与工具校验；仅工具损坏可重新生成，网络错误不整单重放。"""
    attempts = _TOOL_CALL_MAX_RETRY + 1 if body.get("tools") else 1
    for attempt in range(attempts):
        if filter_retry:
            status, raw, _ = await _post_backend_with_filter_retry(url, headers, body, rid, model_name)
            _check_upstream_status(status, raw, cred, body.get("model"))
            result = _chat_completion(_merge_chat_sse_text(raw.decode("utf-8", "replace")))
        else:
            async with _backend_stream(url, headers, body, rid=rid, model_name=model_name) as response:
                if response.status_code != 200:
                    _check_upstream_status(response.status_code, await response.aread(), cred, body.get("model"))
                result = await _collect_stream(response)
        calls = result["choices"][0]["message"].get("tool_calls")
        if _tool_calls_healthy(calls) and _tool_choice_satisfied(calls, body):
            return result
        if attempt + 1 < attempts:
            runtime._log(f"[{rid}] tool_calls 损坏，重试 {attempt + 1}/{attempts - 1} | {model_name}")
    raise UpstreamResponseError(502, b"Invalid upstream tool_calls after retries")


async def _chat_sse_lines(url, headers, body, model_name, t0, rid, cred=None, *, aggregate=False, filter_retry=False):
    """提供公共 Chat SSE 行流；日志仅缓存预览，透传分支不缓存完整正文。"""
    if aggregate:
        result = await _fetch_checked_chat(url, headers, body, model_name, rid, cred, filter_retry=filter_retry)
        for line in _chat_result_to_sse_lines(_completion_to_merged(result)):
            yield line
            yield ""
        _log_finish(model_name, t0, result, rid)
        return
    tracker = ChatSSEAccumulator(collect=False)
    preview = bytearray()
    budget = CONFIG["log_body_limit"] if CONFIG.get("log_path") else 0
    async with _backend_stream(url, headers, body, rid=rid, model_name=model_name) as response:
        if response.status_code != 200:
            _check_upstream_status(response.status_code, await response.aread(), cred, body.get("model"))
        async for line in response.aiter_lines():
            tracker.feed_line(line)
            if tracker.done or tracker.finish_reason:
                tracker.result()  # 先验证，再向客户端发出成功终止帧。
            remaining = budget - len(preview)
            if remaining > 0:
                preview.extend((line[:remaining] + "\n").encode("utf-8")[:remaining])
            yield line
            if tracker.done:
                yield ""
                break
    merged = tracker.result()
    runtime._log(f"[{rid}] ◀ RESPONSE {model_name} | {time.time() - t0:.1f}s | stream finish={merged['finish_reason']}"
         + f" | tokens={(merged['usage'] or {}).get('total_tokens', '?')}")
    runtime._log_text_body(f"[{rid}] RESPONSE SSE PREVIEW", preview.decode("utf-8", "replace"))


async def _stream_upstream(url: str, headers: dict, body: dict,
                           model_name: str = "?", t0: float = 0.0, rid: str = "", cred=None):
    try:
        async for line in _chat_sse_lines(url, headers, body, model_name, t0, rid, cred, aggregate=bool(body.get("tools"))):
            yield (line + "\n").encode("utf-8")
    except (httpx.HTTPError, UpstreamResponseError) as error:
        status, raw = _upstream_failure(error, model_name, t0, rid)
        yield _err_event(raw, status)




def _err_event(msg: bytes, status: int) -> bytes:
    chunk = {"error": {"message": sanitize_log_text(msg.decode("utf-8", "replace"), 512),
                       "type": "upstream_error", "code": status}}
    return f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n".encode("utf-8")


def _looks_like_content_filter_text(text: str) -> bool:
    text = (text or "").lower()
    return (
        "content-filter" in text
        or "content_filter" in text
        or "敏感内容" in text
        or "内容审核" in text
        or "无法响应您的请求" in text
    )


def _chat_body_desensitize(body: dict, *, force_compact: bool = False) -> dict:
    if not CONFIG.get("desensitize"):
        return body
    return desensitize_body(
        body,
        roles=("system", "developer"),
        desensitize_harness_user=True,
        desensitize_tools=True,
        compact_harness=(force_compact or not CONFIG.get("no_compact")),
        strip_tool_metadata=True,
    )


async def _post_backend_once(url: str, headers: dict, body: dict, *, rid="") -> tuple[int, bytes]:
    async with _backend_stream(url, headers, body, timeout=120, rid=rid, model_name=body.get("model", "?")) as r:
        if r.status_code != 200:
            return r.status_code, await r.aread()
        lines = []
        async for line in r.aiter_lines():
            lines.append(line)
            if line.strip().startswith("data:") and line.strip()[5:].strip() == "[DONE]":
                break
        return r.status_code, ("\n".join(lines) + "\n").encode("utf-8")


async def _post_backend_with_filter_retry(url: str, headers: dict, body: dict,
                                          rid: str = "", model_name: str = "?") -> tuple[int, bytes, dict]:
    prefix = f"[{rid}] " if rid else ""
    status, raw = await _post_backend_once(url, headers, body, rid=rid)
    text = raw.decode("utf-8", "replace")
    if status == 200 and _looks_like_content_filter_text(text) and CONFIG.get("desensitize") and CONFIG.get("no_compact"):
        retry_body = _chat_body_desensitize(body, force_compact=True)
        runtime._log(f"{prefix}↻ RESPONSES {model_name} | content filter detected, retry with compact harness")
        try:
            _guard_request_size(retry_body)
        except HTTPException:
            return status, raw, body
        runtime._log_json(f"{prefix}RESPONSES RETRY CHAT BODY (预览)", retry_body)
        retry_status, retry_raw = await _post_backend_once(url, headers, retry_body, rid=rid)
        retry_text = retry_raw.decode("utf-8", "replace")
        if retry_status == 200 and not _looks_like_content_filter_text(retry_text):
            return retry_status, retry_raw, retry_body
    return status, raw, body


async def _nonstream_adapted(url, headers, body, model_name, t0, rid, cred, *, anthropic=False):
    converter = AnthropicStreamConverter(model=model_name) if anthropic else ResponsesStreamConverter(model=model_name)
    try:
        collected = await _fetch_checked_chat(url, headers, body, model_name, rid, cred, filter_retry=not anthropic)
        for line in _chat_result_to_sse_lines(_completion_to_merged(collected)):
            converter.feed_line(line)
        converter.finish()
    except (httpx.HTTPError, UpstreamResponseError) as error:
        status, raw = _upstream_failure(error, model_name, t0, rid)
        raise HTTPException(status_code=status, detail=_safe_err_raw(raw, status)) from None
    result = converter.get_nonstream_response()
    _log_finish(model_name, t0, collected, rid)
    return JSONResponse(content=result)


async def _stream_adapted(url, headers, body, model_name, t0, rid, cred=None, *, anthropic=False):
    """协议适配只处理事件映射，连接、聚合与错误边界共用。"""
    converter = AnthropicStreamConverter(model=model_name) if anthropic else ResponsesStreamConverter(model=model_name)
    try:
        async for line in _chat_sse_lines(
                url, headers, body, model_name, t0, rid, cred,
                aggregate=not anthropic or bool(body.get("tools")), filter_retry=not anthropic):
            events = converter.feed_line(line)
            if events:
                yield events.encode("utf-8")
        events = converter.finish()
        if events:
            yield events.encode("utf-8")
    except (httpx.HTTPError, UpstreamResponseError) as error:
        status, raw = _upstream_failure(error, model_name, t0, rid)
        event = {"type": "error", "error": {
            "message": sanitize_log_text(raw.decode("utf-8", "replace"), 512),
            "type": "api_error" if anthropic else "upstream_error", "code": status}}
        prefix = "event: error\n" if anthropic else ""
        yield (prefix + f"data: {json.dumps(event, ensure_ascii=False)}\n\n").encode("utf-8")


async def _stream_responses(url: str, headers: dict, body: dict,
                            model_name: str = "?", t0: float = 0.0, rid: str = "", cred=None):
    async for chunk in _stream_adapted(url, headers, body, model_name, t0, rid, cred):
        yield chunk

async def _stream_anthropic(url: str, headers: dict, body: dict,
                            model_name: str = "?", t0: float = 0.0, rid: str = "", cred=None):
    async for chunk in _stream_adapted(url, headers, body, model_name, t0, rid, cred, anthropic=True):
        yield chunk
