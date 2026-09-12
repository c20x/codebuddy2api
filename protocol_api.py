"""OpenAI Chat / Responses 与 Anthropic Messages 路由。"""

from __future__ import annotations

import os
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from anthropic_adapter import anthropic_request_to_chat
from responses_adapter import responses_request_to_chat
from responses_projection import project_responses_chat_body
from chat_proxy import (
    _check_auth, _fetch_checked_chat, _last_user_text, _log_finish,
    _nonstream_adapted, _prepare_chat_body, _prepare_payload, _route_chat,
    _safe_err_raw, _stream_anthropic, _stream_responses, _stream_upstream,
    _upstream_failure, _usage_begin,
)
from model_table import current_model_details
import runtime
from runtime import CONFIG, PASSTHROUGH_BODY_KEYS, _truncate
from upstream_io import UpstreamResponseError

def register(app: FastAPI) -> None:
    app.add_api_route("/v1/models", list_models, methods=["GET"])
    app.add_api_route("/v1/chat/completions", chat_completions, methods=["POST"])
    app.add_api_route("/v1/responses", create_response, methods=["POST"])
    app.add_api_route("/v1/messages", create_message, methods=["POST"])
    app.add_api_route("/v1/messages/count_tokens", count_tokens, methods=["POST"])


def list_models(authorization: Optional[str] = Header(default=None),
                x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    _check_auth(authorization, x_api_key)
    data = [{"id": item["id"], "object": "model", "created": 1700000000, "owned_by": "codebuddy",
             "credits": item["credits"], "credits_by_profile": item["credits_by_profile"]}
            for item in current_model_details()]
    return {"object": "list", "data": data}


async def chat_completions(request: Request,
                           authorization: Optional[str] = Header(default=None),
                           x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    _check_auth(authorization, x_api_key)
    # 凭证在构造后端 headers 时按会话黏绑选取

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"bad json: {e}", "type": "invalid_request_error"}})

    payload = _prepare_payload(payload)
    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(status_code=400, detail={"error": {"message": "messages is required", "type": "invalid_request_error"}})

    # 构造后端 body：只透传已知的合法字段
    client_wants_stream = bool(payload.get("stream"))
    body = {k: payload[k] for k in PASSTHROUGH_BODY_KEYS if k in payload}
    body = _prepare_chat_body(body)

    # 日志：请求摘要
    model_name = payload.get("model", "auto")
    tool_names = [t.get("function", {}).get("name") for t in (payload.get("tools") or [])
                  if isinstance(t, dict)]
    last_user = _last_user_text(messages)
    rid = os.urandom(4).hex()
    _usage_begin(rid, model_name, protocol="chat")
    runtime._log(f"[{rid}] ▶ REQUEST {model_name} | stream={client_wants_stream} | msgs={len(messages)}"
         + (f" | tools={tool_names}" if tool_names else "")
         + (f" | last_user={_truncate(last_user, 60)!r}" if last_user else ""))
    body, cred, headers, url = _route_chat(payload, body, rid)
    runtime._log_json(f"[{rid}] REQUEST BODY (发往后端，预览)", body)
    t0 = time.time()

    if client_wants_stream:
        return StreamingResponse(
            _stream_upstream(url, headers, body, model_name, t0, rid, cred=cred),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # 非流式：后端只支持流式，这里把后端 SSE 聚合成单个 chat.completion 响应
    try:
        collected = await _fetch_checked_chat(url, headers, body, model_name, rid, cred)
    except (httpx.HTTPError, UpstreamResponseError) as error:
        status, raw = _upstream_failure(error, model_name, t0, rid)
        raise HTTPException(status_code=status, detail=_safe_err_raw(raw, status)) from None
    _log_finish(model_name, t0, collected, rid)
    return JSONResponse(content=collected)


async def create_response(request: Request,
                          authorization: Optional[str] = Header(default=None),
                          x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """OpenAI Responses API 兼容端点。

    Codex CLI 使用 Responses API（wire_api = "responses"）而非 Chat Completions。
    本端点接收 Responses 格式请求，转换为 Chat 格式发往后端，再将后端的 Chat SSE
    转换为 Responses 语义事件流返回。
    """
    _check_auth(authorization, x_api_key)

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"bad json: {e}", "type": "invalid_request_error"}})

    payload = _prepare_payload(payload, field="input")
    # 转换请求：Responses → Chat
    try:
        chat_body = responses_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"request conversion error: {e}", "type": "invalid_request_error"}})

    chat_body, projection_stats = project_responses_chat_body(chat_body)
    chat_body = _prepare_chat_body(chat_body)

    client_wants_stream = payload.get("stream", True)  # Codex CLI 默认 stream
    model_name = payload.get("model", "auto")
    rid = os.urandom(4).hex()
    _usage_begin(rid, model_name, protocol="responses")
    runtime._log(f"[{rid}] ▶ RESPONSES {model_name} | stream={client_wants_stream} | input_items={len(payload.get('input', []))}")
    runtime._log(
        f"[{rid}] ── RESPONSES PROJECTION ── "
        f"mode={projection_stats.get('mode')} "
        f"| msgs {projection_stats.get('original_messages')}→{projection_stats.get('projected_messages')} "
        f"| chars {projection_stats.get('original_message_chars')}→{projection_stats.get('projected_message_chars')} "
        f"| tools {projection_stats.get('original_tools')}→{projection_stats.get('projected_tools')} "
        f"| tool_chars {projection_stats.get('original_tool_chars')}→{projection_stats.get('projected_tool_chars')} "
        f"| summarized_history={projection_stats.get('summarized_history_messages', 0)} "
        f"| dropped_harness={projection_stats.get('dropped_harness_messages', 0)} "
        f"| anchor_user={projection_stats.get('anchor_user_preserved', False)}"
    )
    chat_body, cred, headers, url = _route_chat(payload, chat_body, rid)
    runtime._log_json(f"[{rid}] RESPONSES → CHAT BODY (预览)", chat_body)
    t0 = time.time()

    if client_wants_stream:
        return StreamingResponse(
            _stream_responses(url, headers, chat_body, model_name, t0, rid, cred=cred),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return await _nonstream_adapted(url, headers, chat_body, model_name, t0, rid, cred)


async def create_message(request: Request,
                         authorization: Optional[str] = Header(default=None),
                         x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """Anthropic Messages API 兼容端点。

    Claude Code / CC Switch 使用 Anthropic Messages API（POST /v1/messages）。
    本端点接收 Anthropic 格式请求，转换为 Chat 格式发往后端，再将后端的 Chat SSE
    转换为 Anthropic SSE 事件流返回。
    """
    _check_auth(authorization, x_api_key)

    try:
        payload = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"bad json: {e}", "type": "invalid_request_error"}})

    payload = _prepare_payload(payload)
    # 将 Anthropic 格式消息、工具规范在进入后端前统一转换为 OpenAI Chat 格式。
    messages = payload.get("messages") or []
    if not messages:
        raise HTTPException(status_code=400, detail={"error": {"message": "messages is required", "type": "invalid_request_error"}})

    try:
        chat_body = anthropic_request_to_chat(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"error": {"message": f"request conversion error: {e}", "type": "invalid_request_error"}})

    chat_body = _prepare_chat_body(chat_body)
    model_name = payload.get("model", "auto")
    chat_messages = chat_body.get("messages", [])
    rid = os.urandom(4).hex()
    _usage_begin(rid, model_name, protocol="anthropic")
    runtime._log(f"[{rid}] ▶ ANTHROPIC {model_name} | msgs={len(chat_messages)} | anthropic_msgs={len(messages)}")
    chat_body, cred, headers, url = _route_chat(payload, chat_body, rid)
    runtime._log_json(f"[{rid}] ANTHROPIC → CHAT BODY (预览)", chat_body)
    t0 = time.time()

    if not payload.get("stream", True):
        return await _nonstream_adapted(url, headers, chat_body, model_name, t0, rid, cred, anthropic=True)

    return StreamingResponse(
        _stream_anthropic(url, headers, chat_body, model_name, t0, rid, cred=cred),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


async def count_tokens(request: Request,
                       authorization: Optional[str] = Header(default=None),
                       x_api_key: Optional[str] = Header(default=None, alias="X-Api-Key")):
    """Anthropic token 计数端点（stub）。

    Claude Code 可能在发送消息前调用此端点。
    返回一个简单估算值，不做实际 token 计数。
    """
    _check_auth(authorization, x_api_key)
    return {"input_tokens": 0}
