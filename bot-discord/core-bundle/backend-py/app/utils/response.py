def ok(data: dict) -> dict:
    return {"ok": True, "data": data}


def fail(message: str) -> dict:
    return {"ok": False, "message": message}
