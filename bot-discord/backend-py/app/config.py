import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BOT_ROOT = Path(__file__).resolve().parents[2]
LOCAL_ENV_FILE = BOT_ROOT / ".env"

# In local development, allow reading bot-discord/.env without overriding
# variables that were already injected by systemd/environment.
if LOCAL_ENV_FILE.exists():
    load_dotenv(LOCAL_ENV_FILE, override=False)


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    internal_shared_secret: str
    backend_host: str
    backend_port: int
    commands_file: str
    enable_dangerous_actions: bool


_SETTINGS: Settings | None = None


def _default_commands_file() -> str:
    local_commands = BOT_ROOT / "shared" / "commands.json"
    if local_commands.exists():
        return str(local_commands)
    return "/opt/bot-discord/shared/commands.json"


def get_settings() -> Settings:
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings(
            internal_shared_secret=os.getenv("INTERNAL_SHARED_SECRET", "").strip(),
            backend_host=os.getenv("BACKEND_HOST", "127.0.0.1").strip(),
            backend_port=int(os.getenv("BACKEND_PORT", "8080")),
            commands_file=os.getenv("COMMANDS_FILE", _default_commands_file()).strip(),
            enable_dangerous_actions=_get_bool("ENABLE_DANGEROUS_ACTIONS", True),
        )
    return _SETTINGS
