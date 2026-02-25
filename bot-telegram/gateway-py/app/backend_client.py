from __future__ import annotations

from dataclasses import dataclass

import httpx


DEFAULT_TIMEOUT_SECONDS = 30.0
ACTION_TIMEOUTS_SECONDS: dict[str, float] = {
    "5:setup_domain_custom": 420.0,
    "5:setup_domain_cloudflare": 420.0,
    "6:run": 190.0,
}


@dataclass
class BackendActionResponse:
    ok: bool
    code: str
    title: str
    message: str
    data: dict


@dataclass(frozen=True)
class BackendUserOption:
    proto: str
    username: str


class BackendError(RuntimeError):
    pass


class BackendClient:
    def __init__(self, base_url: str, shared_secret: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._headers = {"X-Internal-Shared-Secret": shared_secret}

    async def run_action(self, menu_id: str, action: str, params: dict[str, str]) -> BackendActionResponse:
        timeout = ACTION_TIMEOUTS_SECONDS.get(f"{menu_id}:{action}", DEFAULT_TIMEOUT_SECONDS)
        payload = {"action": action, "params": params}

        try:
            async with httpx.AsyncClient(base_url=self._base_url, headers=self._headers, timeout=timeout) as client:
                response = await client.post(f"/api/menu/{menu_id}/action", json=payload)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text.strip()
            raise BackendError(f"HTTP {exc.response.status_code}: {body[:400]}") from exc
        except Exception as exc:
            raise BackendError(str(exc)) from exc

        if not isinstance(data, dict):
            raise BackendError("Response backend tidak valid (bukan JSON object).")

        return BackendActionResponse(
            ok=bool(data.get("ok", False)),
            code=str(data.get("code") or "unknown"),
            title=str(data.get("title") or "Result"),
            message=str(data.get("message") or ""),
            data=data.get("data") if isinstance(data.get("data"), dict) else {},
        )

    async def list_user_options(self, proto: str | None = None) -> list[BackendUserOption]:
        params = {"proto": proto} if proto else None
        try:
            async with httpx.AsyncClient(base_url=self._base_url, headers=self._headers, timeout=15.0) as client:
                response = await client.get("/api/users/options", params=params)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text.strip()
            raise BackendError(f"HTTP {exc.response.status_code}: {body[:400]}") from exc
        except Exception as exc:
            raise BackendError(str(exc)) from exc

        users_raw = data.get("users") if isinstance(data, dict) else None
        if not isinstance(users_raw, list):
            return []

        out: list[BackendUserOption] = []
        for item in users_raw:
            if not isinstance(item, dict):
                continue
            p = str(item.get("proto") or "").strip().lower()
            u = str(item.get("username") or "").strip()
            if not p or not u:
                continue
            out.append(BackendUserOption(proto=p, username=u))
        return out

    async def health(self) -> dict:
        try:
            async with httpx.AsyncClient(base_url=self._base_url, headers=self._headers, timeout=8.0) as client:
                response = await client.get("/health")
                response.raise_for_status()
                data = response.json()
        except Exception as exc:
            raise BackendError(str(exc)) from exc

        if not isinstance(data, dict):
            raise BackendError("Response health backend tidak valid.")
        return data
