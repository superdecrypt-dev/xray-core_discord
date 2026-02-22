from ..adapters import system
from ..utils.response import error_response, ok_response
from ..utils.validators import require_param


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

    return error_response("unknown_action", "User Management", f"Action tidak dikenal: {action}")
