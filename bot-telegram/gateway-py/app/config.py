from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BOT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_ENV_FILE = BOT_ROOT / ".env"

if LOCAL_ENV_FILE.exists():
    load_dotenv(LOCAL_ENV_FILE, override=False)


@dataclass(frozen=True)
class AppConfig:
    token: str
    backend_base_url: str
    shared_secret: str
    commands_file: str
    admin_chat_ids: set[str]
    admin_user_ids: set[str]
    bot_username: str


def _parse_set(raw: str | None) -> set[str]:
    if not raw:
        return set()
    out: set[str] = set()
    for part in raw.split(","):
        value = part.strip()
        if value:
            out.add(value)
    return out


def _require_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(f"{name} belum diset.")
    return value


def _default_commands_file() -> str:
    local_commands = BOT_ROOT / "shared" / "commands.json"
    if local_commands.exists():
        return str(local_commands)
    return "/opt/bot-telegram/shared/commands.json"


def load_config() -> AppConfig:
    return AppConfig(
        token=_require_env("TELEGRAM_BOT_TOKEN"),
        backend_base_url=(os.getenv("BACKEND_BASE_URL") or "http://127.0.0.1:8080").strip(),
        shared_secret=_require_env("INTERNAL_SHARED_SECRET"),
        commands_file=(os.getenv("COMMANDS_FILE") or _default_commands_file()).strip(),
        admin_chat_ids=_parse_set(os.getenv("TELEGRAM_ADMIN_CHAT_IDS")),
        admin_user_ids=_parse_set(os.getenv("TELEGRAM_ADMIN_USER_IDS")),
        bot_username=(os.getenv("TELEGRAM_BOT_USERNAME") or "").strip().lstrip("@"),
    )
