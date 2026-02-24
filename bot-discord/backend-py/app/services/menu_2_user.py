from ..adapters import system, system_mutations
from ..utils.response import error_response, ok_response
from ..utils.validators import (
    parse_bool_value,
    require_param,
    require_positive_float_param,
    require_positive_int_param,
    require_protocol,
    require_username,
)


def _fmt_number(value: float) -> str:
    if value <= 0:
        return "0"
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.3f}".rstrip("0").rstrip(".")


def handle(action: str, params: dict, settings) -> dict:
    if action == "list_users":
        title, msg = system.op_user_list()
        return ok_response(title, msg)

    if action == "search_user":
        ok, query_or_err = require_param(params, "query", "User Management - Search")
        if not ok:
            return query_or_err
        title, msg = system.op_user_search(query_or_err)
        return ok_response(title, msg)

    if action == "add_user":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "User Management", "Dangerous actions dinonaktifkan via env.")
        title = "User Management - Add User"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_d, days_or_err = require_positive_int_param(params, "days", title, minimum=1)
        if not ok_d:
            return days_or_err
        ok_q, quota_or_err = require_positive_float_param(params, "quota_gb", title)
        if not ok_q:
            return quota_or_err

        ip_enabled = bool(parse_bool_value(params.get("ip_limit_enabled"), default=False))
        ip_limit = 0
        raw_ip_limit = str(params.get("ip_limit", "")).strip()
        if raw_ip_limit:
            try:
                ip_limit = int(raw_ip_limit)
            except ValueError:
                return error_response("invalid_param", title, "Parameter 'ip_limit' harus angka bulat.")
            if ip_limit < 0:
                return error_response("invalid_param", title, "Parameter 'ip_limit' tidak boleh negatif.")
            if ip_limit > 0:
                ip_enabled = True
        if ip_enabled and ip_limit <= 0:
            return error_response("invalid_param", title, "IP limit aktif tapi nilai 'ip_limit' belum valid (>0).")

        speed_enabled = bool(parse_bool_value(params.get("speed_limit_enabled"), default=False))
        speed_down = 0.0
        speed_up = 0.0
        if speed_enabled:
            ok_sd, sd_or_err = require_positive_float_param(params, "speed_down_mbit", title)
            if not ok_sd:
                return sd_or_err
            ok_su, su_or_err = require_positive_float_param(params, "speed_up_mbit", title)
            if not ok_su:
                return su_or_err
            speed_down = float(sd_or_err)
            speed_up = float(su_or_err)

        ok_add, title_add, msg_add = system_mutations.op_user_add(
            proto=proto_or_err,
            username=user_or_err,
            days=int(days_or_err),
            quota_gb=float(quota_or_err),
            ip_enabled=ip_enabled,
            ip_limit=ip_limit,
            speed_enabled=speed_enabled,
            speed_down_mbit=speed_down,
            speed_up_mbit=speed_up,
        )
        if ok_add:
            ip_limit_text = "OFF"
            if ip_enabled:
                ip_limit_text = f"ON ({ip_limit})"

            speed_limit_text = "OFF"
            if speed_enabled and speed_down > 0 and speed_up > 0:
                speed_limit_text = f"ON (DOWN {_fmt_number(speed_down)} Mbps | UP {_fmt_number(speed_up)} Mbps)"

            lines = [
                "Akun berhasil dibuat.",
                f"Username    : {user_or_err}",
                f"Protokol    : {proto_or_err}",
                f"Masa Aktif  : {int(days_or_err)} hari",
                f"Quota       : {_fmt_number(float(quota_or_err))} GB",
                f"IP Limit    : {ip_limit_text}",
                f"Speed Limit : {speed_limit_text}",
            ]

            data: dict[str, object] = {}
            data["add_user_summary"] = {
                "username": str(user_or_err),
                "protocol": str(proto_or_err),
                "active_days": int(days_or_err),
                "quota_gb": f"{_fmt_number(float(quota_or_err))} GB",
                "ip_limit": ip_limit_text,
                "speed_limit": speed_limit_text,
            }
            ok_download, download_or_err = system_mutations.op_user_account_file_download(proto_or_err, user_or_err)
            if ok_download and isinstance(download_or_err, dict):
                data["download_file"] = download_or_err
                filename = str(download_or_err.get("filename") or f"{user_or_err}@{proto_or_err}.txt")
                lines.append(f"File TXT    : {filename} (download)")
            else:
                lines.append("File TXT    : gagal menyiapkan file download")
                data["download_error"] = str(download_or_err)

            return ok_response(title_add, "\n".join(lines), data=data)
        return error_response("user_add_failed", title_add, msg_add)

    if action == "delete_user":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "User Management", "Dangerous actions dinonaktifkan via env.")
        title = "User Management - Delete User"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_del, title_del, msg_del = system_mutations.op_user_delete(proto_or_err, user_or_err)
        if ok_del:
            return ok_response(title_del, msg_del)
        return error_response("user_delete_failed", title_del, msg_del)

    if action == "extend_expiry":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "User Management", "Dangerous actions dinonaktifkan via env.")
        title = "User Management - Extend Expiry"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_m, mode_or_err = require_param(params, "mode", title)
        if not ok_m:
            return mode_or_err
        ok_v, value_or_err = require_param(params, "value", title)
        if not ok_v:
            return value_or_err
        ok_ext, title_ext, msg_ext = system_mutations.op_user_extend_expiry(
            proto=proto_or_err,
            username=user_or_err,
            mode=str(mode_or_err),
            value=str(value_or_err),
        )
        if ok_ext:
            return ok_response(title_ext, msg_ext)
        return error_response("user_extend_failed", title_ext, msg_ext)

    if action == "account_info":
        ok_p, proto_or_err = require_param(params, "proto", "User Management - Account Info")
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_param(params, "username", "User Management - Account Info")
        if not ok_u:
            return user_or_err
        title, msg = system.op_account_info(proto_or_err.lower(), user_or_err)
        return ok_response(title, msg)

    return error_response("unknown_action", "User Management", f"Action tidak dikenal: {action}")
