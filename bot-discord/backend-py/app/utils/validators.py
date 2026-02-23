import re
from datetime import datetime

from .response import error_response

PROTOCOLS = {"vless", "vmess", "trojan"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
TRUE_SET = {"1", "true", "yes", "y", "on", "aktif", "enable", "enabled"}
FALSE_SET = {"0", "false", "no", "n", "off", "nonaktif", "disable", "disabled"}


def require_param(params: dict, key: str, title: str) -> tuple[bool, str | dict]:
    value = str(params.get(key, "")).strip()
    if not value:
        return False, error_response("missing_param", title, f"Parameter '{key}' wajib diisi.")
    return True, value


def require_protocol(params: dict, title: str, key: str = "proto") -> tuple[bool, str | dict]:
    ok, proto_or_err = require_param(params, key, title)
    if not ok:
        return False, proto_or_err
    proto = str(proto_or_err).strip().lower()
    if proto not in PROTOCOLS:
        return False, error_response("invalid_param", title, "Protocol harus vless/vmess/trojan.")
    return True, proto


def require_username(params: dict, title: str, key: str = "username") -> tuple[bool, str | dict]:
    ok, user_or_err = require_param(params, key, title)
    if not ok:
        return False, user_or_err
    username = str(user_or_err).strip()
    if not USERNAME_RE.match(username):
        return False, error_response(
            "invalid_param",
            title,
            "Username tidak valid. Gunakan huruf/angka/._- tanpa spasi.",
        )
    return True, username


def parse_bool_value(raw: object, default: bool | None = None) -> bool | None:
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    text = str(raw).strip().lower()
    if text in TRUE_SET:
        return True
    if text in FALSE_SET:
        return False
    return default


def require_bool_param(params: dict, key: str, title: str) -> tuple[bool, bool | dict]:
    ok, raw_or_err = require_param(params, key, title)
    if not ok:
        return False, raw_or_err
    val = parse_bool_value(raw_or_err, default=None)
    if val is None:
        return False, error_response(
            "invalid_param",
            title,
            f"Parameter '{key}' harus on/off atau true/false.",
        )
    return True, val


def require_positive_int_param(params: dict, key: str, title: str, minimum: int = 1) -> tuple[bool, int | dict]:
    ok, raw_or_err = require_param(params, key, title)
    if not ok:
        return False, raw_or_err
    try:
        value = int(str(raw_or_err).strip())
    except (TypeError, ValueError):
        return False, error_response("invalid_param", title, f"Parameter '{key}' harus angka bulat.")
    if value < minimum:
        return False, error_response("invalid_param", title, f"Parameter '{key}' minimal {minimum}.")
    return True, value


def require_positive_float_param(params: dict, key: str, title: str, minimum: float = 0.0001) -> tuple[bool, float | dict]:
    ok, raw_or_err = require_param(params, key, title)
    if not ok:
        return False, raw_or_err
    text = str(raw_or_err).strip().lower().replace("mbit", "").replace("mbps", "")
    try:
        value = float(text)
    except (TypeError, ValueError):
        return False, error_response("invalid_param", title, f"Parameter '{key}' harus angka.")
    if value < minimum:
        return False, error_response("invalid_param", title, f"Parameter '{key}' harus lebih dari 0.")
    return True, value


def require_date_param(params: dict, key: str, title: str) -> tuple[bool, str | dict]:
    ok, raw_or_err = require_param(params, key, title)
    if not ok:
        return False, raw_or_err
    text = str(raw_or_err).strip()
    try:
        datetime.strptime(text, "%Y-%m-%d")
    except ValueError:
        return False, error_response("invalid_param", title, f"Parameter '{key}' harus format YYYY-MM-DD.")
    return True, text


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
