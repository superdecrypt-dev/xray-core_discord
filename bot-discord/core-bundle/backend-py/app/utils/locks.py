from pathlib import Path


def ensure_lock_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)
