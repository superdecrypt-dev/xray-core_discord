import os
from dataclasses import dataclass


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


def get_settings() -> Settings:
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings(
            internal_shared_secret=os.getenv("INTERNAL_SHARED_SECRET", "").strip(),
            backend_host=os.getenv("BACKEND_HOST", "127.0.0.1").strip(),
            backend_port=int(os.getenv("BACKEND_PORT", "8080")),
            commands_file=os.getenv("COMMANDS_FILE", "/opt/bot-discord/shared/commands.json").strip(),
            enable_dangerous_actions=_get_bool("ENABLE_DANGEROUS_ACTIONS", True),
        )
    return _SETTINGS
