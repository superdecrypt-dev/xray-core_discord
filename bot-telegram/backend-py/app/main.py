import logging

from fastapi import FastAPI

from .adapters import system_mutations
from .config import get_settings
from .routes.menus import router as menu_router

app = FastAPI(title="xray-telegram-backend", version="1.0.0")
app.include_router(menu_router)
logger = logging.getLogger("xray-telegram-backend")


@app.on_event("startup")
def startup_account_info_compat_refresh() -> None:
    try:
        ok, title, msg = system_mutations.op_account_info_compat_refresh_if_needed()
        if ok:
            logger.info("%s | %s", title, msg)
        else:
            logger.warning("%s | %s", title, msg)
    except Exception as exc:
        logger.warning("Startup compat refresh gagal: %s", exc)


@app.get("/health")
def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "service": "backend-py",
        "dangerous_actions_enabled": settings.enable_dangerous_actions,
    }
