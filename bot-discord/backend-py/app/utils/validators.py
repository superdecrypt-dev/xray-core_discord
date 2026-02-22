from .response import error_response



def require_param(params: dict, key: str, title: str) -> tuple[bool, str | dict]:
    value = str(params.get(key, "")).strip()
    if not value:
        return False, error_response("missing_param", title, f"Parameter '{key}' wajib diisi.")
    return True, value



def parse_lines(params: dict, default: int = 80, minimum: int = 10, maximum: int = 500) -> int:
    raw = params.get("lines", default)
    try:
        num = int(raw)
    except (TypeError, ValueError):
        return default
    if num < minimum:
        return minimum
    if num > maximum:
        return maximum
    return num
