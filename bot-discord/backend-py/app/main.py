from fastapi import FastAPI

from .config import get_settings
from .routes.menus import router as menu_router

app = FastAPI(title="xray-discord-backend", version="1.0.0")
app.include_router(menu_router)


@app.get("/health")
def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "service": "backend-py",
        "dangerous_actions_enabled": settings.enable_dangerous_actions,
    }
