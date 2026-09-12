"""本机凭据目录发现、桌面端种子导入与账号身份。"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import auth_oauth
from client_profiles import account_key
import runtime
from site_routing import profile_for_auth

def managed_auth_dir() -> Path:
    """自管凭证目录：CODEBUDDY_AUTH_DIR 已设置则用其（容器挂载场景），否则项目下 auth/。"""
    env_dir = os.environ.get("CODEBUDDY_AUTH_DIR")
    return Path(env_dir) if env_dir else Path(__file__).resolve().parent / "auth"


def auth_dirs() -> list[Path]:
    """桌面端登录态目录（仅作种子来源，不直接挂进池）。"""
    home = Path.home()
    plat = sys.platform
    if plat == "darwin":
        return [home / "Library" / "Application Support" / "CodeBuddyExtension" / "Data" / "Public" / "auth"]
    if plat == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        return [local / "CodeBuddyExtension" / "Data" / "Public" / "auth"]
    xdg = Path(os.environ.get("XDG_DATA_HOME", home / ".local" / "share"))
    return [xdg / "CodeBuddyExtension" / "Data" / "Public" / "auth"]


def seed_credentials():
    """把桌面端已登录凭据复制进自管目录（只补缺失文件，不覆盖）。CODEBUDDY_AUTH_DIR 模式跳过。"""
    if os.environ.get("CODEBUDDY_AUTH_DIR"):
        return
    dst_dir = managed_auth_dir()
    dst_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dst_dir, 0o700)
    except OSError:
        pass
    have_uids = {u for u in (_cred_identity(f) for f in dst_dir.glob("*.info")) if u}
    for src_dir in auth_dirs():
        if not src_dir.is_dir():
            continue
        for f in sorted(src_dir.glob("*.info")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
            except Exception as e:
                runtime._log(f"[cred] 种子跳过（无法解析）: {f.name}: {e}")
                continue
            uid, verr = auth_oauth.validate_cred_data(data)
            if verr:
                runtime._log(f"[cred] 种子跳过（入库校验失败：{verr}）: {f.name}")
                continue
            identity = _credential_identity(data)
            if uid and identity in have_uids:
                runtime._log(f"[cred] 种子跳过（同账号已在自管目录）: {f.name}")
                continue
            dst = dst_dir / f.name
            if not dst.exists():
                try:
                    shutil.copyfile(f, dst)
                    os.chmod(dst, 0o600)
                    if uid:
                        have_uids.add(identity)
                    runtime._log(f"[cred] 已复制桌面端凭据到自管目录: {f.name}")
                except OSError as e:
                    runtime._log(f"[cred] 复制凭据失败 {f.name}: {e}")


def find_auth_files() -> list[Path]:
    """扫描自管目录下的全部 *.info 凭据文件。"""
    d = managed_auth_dir()
    return sorted(d.glob("*.info")) if d.is_dir() else []


def _cred_uid(path) -> Optional[str]:
    """读取凭据文件的 account.uid（兼容 accounts[0]）作为账号去重键；读不出返回 None。"""
    try:
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        acct = d.get("account")
        if not isinstance(acct, dict):
            arr = d.get("accounts")
            acct = arr[0] if isinstance(arr, list) and arr and isinstance(arr[0], dict) else {}
        return acct.get("uid")
    except Exception:
        return None

def _credential_account(data: dict) -> dict:
    account = data.get("account")
    if not isinstance(account, dict):
        accounts = data.get("accounts") or []
        account = accounts[0] if isinstance(accounts, list) and accounts and isinstance(accounts[0], dict) else {}
    return account


def _credential_identity(data: dict) -> str:
    account = _credential_account(data)
    return account_key(profile_for_auth(data.get("auth") or {}), account.get("uid"), account.get("enterpriseId"))


def _cred_identity(path) -> str | None:
    try:
        return _credential_identity(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def find_auth_file() -> Path | None:
    files = find_auth_files()
    return files[0] if files else None
