from dataclasses import dataclass
import os


@dataclass
class Settings:
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8787"))
    internal_shared_secret: str = os.getenv("INTERNAL_SHARED_SECRET", "")


settings = Settings()
