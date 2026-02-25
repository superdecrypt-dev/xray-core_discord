import hmac

from fastapi import Header, HTTPException, status

from .config import get_settings


def verify_shared_secret(x_internal_shared_secret: str | None = Header(default=None)) -> None:
    settings = get_settings()

    # If secret is not configured, keep backend closed by default.
    if not settings.internal_shared_secret:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="INTERNAL_SHARED_SECRET belum dikonfigurasi.",
        )

    provided = x_internal_shared_secret or ""
    if not hmac.compare_digest(provided, settings.internal_shared_secret):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: shared secret tidak valid.",
        )
