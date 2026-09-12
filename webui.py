"""本机账号池管理界面：静态页走已有 /admin API，不读取或回传 token。"""

from __future__ import annotations

from pathlib import Path

from fastapi.responses import FileResponse, HTMLResponse

WEBUI_FILE = Path(__file__).with_name("webui.html")


def serve_webui():
    if WEBUI_FILE.is_file():
        return FileResponse(WEBUI_FILE, media_type="text/html; charset=utf-8")
    return HTMLResponse("<p>webui.html missing</p>", status_code=500)


def register(app) -> None:
    app.add_api_route("/", serve_webui, methods=["GET"], include_in_schema=False, name="webui_root")
    app.add_api_route("/admin", serve_webui, methods=["GET"], include_in_schema=False, name="webui_admin")
