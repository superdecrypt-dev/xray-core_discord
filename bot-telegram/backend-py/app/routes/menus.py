import json
from pathlib import Path

from fastapi import APIRouter, Depends

from ..adapters import system
from ..auth import verify_shared_secret
from ..config import get_settings
from ..schemas import ActionRequest, ActionResponse
from ..services import MENU_HANDLERS
from ..utils.response import error_response

router = APIRouter(tags=["menus"])


def _load_commands_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"menus": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"menus": []}


@router.get("/api/menus", dependencies=[Depends(verify_shared_secret)])
def get_menus() -> dict:
    settings = get_settings()
    return _load_commands_file(settings.commands_file)


@router.get("/api/main-menu", dependencies=[Depends(verify_shared_secret)])
def get_main_menu_overview() -> dict:
    settings = get_settings()
    data = _load_commands_file(settings.commands_file)
    return {
        "mode": "standalone",
        "dangerous_actions_enabled": settings.enable_dangerous_actions,
        "menu_count": len(data.get("menus", [])),
        "menus": data.get("menus", []),
    }


@router.get("/api/users/options", dependencies=[Depends(verify_shared_secret)])
def get_user_options(proto: str | None = None) -> dict:
    proto_norm = (proto or "").strip().lower()
    if proto_norm and proto_norm not in {"vless", "vmess", "trojan"}:
        return {"users": []}

    records = system.list_accounts()
    if proto_norm:
        records = [(p, u) for p, u in records if p == proto_norm]

    return {
        "users": [{"proto": p, "username": u} for p, u in records],
    }


@router.get("/api/inbounds/options", dependencies=[Depends(verify_shared_secret)])
def get_inbound_options() -> dict:
    tags = system.list_inbound_tags()
    return {
        "inbounds": [{"tag": tag} for tag in tags],
    }


@router.get("/api/network/domain-options", dependencies=[Depends(verify_shared_secret)])
def get_network_domain_options(mode: str | None = None) -> dict:
    entries = system.list_warp_domain_options(mode=mode)
    return {
        "entries": [{"entry": item} for item in entries],
    }


@router.post(
    "/api/menu/{menu_id}/action",
    dependencies=[Depends(verify_shared_secret)],
    response_model=ActionResponse,
)
def run_menu_action(menu_id: str, payload: ActionRequest) -> dict:
    settings = get_settings()
    handler = MENU_HANDLERS.get(menu_id)
    if handler is None:
        return error_response("unknown_menu", "Menu", f"Menu tidak dikenal: {menu_id}")

    return handler(payload.action, payload.params, settings)
