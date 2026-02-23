from ..adapters import system, system_mutations
from ..utils.response import error_response, ok_response
from ..utils.validators import (
    require_bool_param,
    require_param,
    require_positive_float_param,
    require_positive_int_param,
    require_protocol,
    require_username,
)


def handle(action: str, params: dict, settings) -> dict:
    if action == "summary":
        title, msg = system.op_quota_summary()
        return ok_response(title, msg)

    if action == "detail":
        ok_p, proto_or_err = require_param(params, "proto", "Quota Detail")
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_param(params, "username", "Quota Detail")
        if not ok_u:
            return user_or_err
        title, msg = system.op_quota_detail(proto_or_err.lower(), user_or_err)
        return ok_response(title, msg)

    if action == "set_quota_limit":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Set Limit"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_q, quota_or_err = require_positive_float_param(params, "quota_gb", title)
        if not ok_q:
            return quota_or_err
        ok_m, t, m = system_mutations.op_quota_set_limit(proto_or_err, user_or_err, float(quota_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_set_limit_failed", t, m)

    if action == "reset_quota_used":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Reset Used"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_m, t, m = system_mutations.op_quota_reset_used(proto_or_err, user_or_err)
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_reset_used_failed", t, m)

    if action == "manual_block":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Manual Block"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_e, enabled_or_err = require_bool_param(params, "enabled", title)
        if not ok_e:
            return enabled_or_err
        ok_m, t, m = system_mutations.op_quota_manual_block(proto_or_err, user_or_err, bool(enabled_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_manual_block_failed", t, m)

    if action == "ip_limit_enable":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - IP Limit"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_e, enabled_or_err = require_bool_param(params, "enabled", title)
        if not ok_e:
            return enabled_or_err
        ok_m, t, m = system_mutations.op_quota_ip_limit_enable(proto_or_err, user_or_err, bool(enabled_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_ip_limit_toggle_failed", t, m)

    if action == "set_ip_limit":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Set IP Limit"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_l, lim_or_err = require_positive_int_param(params, "ip_limit", title, minimum=1)
        if not ok_l:
            return lim_or_err
        ok_m, t, m = system_mutations.op_quota_set_ip_limit(proto_or_err, user_or_err, int(lim_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_set_ip_limit_failed", t, m)

    if action == "unlock_ip_lock":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Unlock IP Lock"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_m, t, m = system_mutations.op_quota_unlock_ip_lock(proto_or_err, user_or_err)
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_unlock_ip_failed", t, m)

    if action == "set_speed_download":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Speed Download"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_v, val_or_err = require_positive_float_param(params, "speed_down_mbit", title)
        if not ok_v:
            return val_or_err
        ok_m, t, m = system_mutations.op_quota_set_speed_down(proto_or_err, user_or_err, float(val_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_speed_down_failed", t, m)

    if action == "set_speed_upload":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Speed Upload"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_v, val_or_err = require_positive_float_param(params, "speed_up_mbit", title)
        if not ok_v:
            return val_or_err
        ok_m, t, m = system_mutations.op_quota_set_speed_up(proto_or_err, user_or_err, float(val_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_speed_up_failed", t, m)

    if action == "speed_limit":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Quota & Access Control", "Dangerous actions dinonaktifkan via env.")
        title = "Quota - Speed Limit"
        ok_p, proto_or_err = require_protocol(params, title)
        if not ok_p:
            return proto_or_err
        ok_u, user_or_err = require_username(params, title)
        if not ok_u:
            return user_or_err
        ok_e, enabled_or_err = require_bool_param(params, "enabled", title)
        if not ok_e:
            return enabled_or_err
        ok_m, t, m = system_mutations.op_quota_speed_limit(proto_or_err, user_or_err, bool(enabled_or_err))
        if ok_m:
            return ok_response(t, m)
        return error_response("quota_speed_toggle_failed", t, m)

    return error_response("unknown_action", "Quota & Access Control", f"Action tidak dikenal: {action}")
