from typing import Any



def ok_response(title: str, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "ok": True,
        "code": "ok",
        "title": title,
        "message": message,
        "data": data or {},
    }



def error_response(code: str, title: str, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "ok": False,
        "code": code,
        "title": title,
        "message": message,
        "data": data or {},
    }
