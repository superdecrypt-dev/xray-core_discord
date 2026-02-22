from ..adapters import system
from ..utils.response import error_response, ok_response
from ..utils.validators import require_param


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

    return error_response("unknown_action", "Quota & Access Control", f"Action tidak dikenal: {action}")
