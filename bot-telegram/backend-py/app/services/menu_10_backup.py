from ..adapters import backup_restore
from ..utils.response import error_response, ok_response
from ..utils.validators import require_param


def handle(action: str, params: dict, settings) -> dict:
    if action == "list_backups":
        ok, title, msg = backup_restore.op_backup_list()
        if ok:
            return ok_response(title, msg)
        return error_response("backup_list_failed", title, msg)

    if action == "create_backup":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Backup/Restore", "Dangerous actions dinonaktifkan via env.")
        ok, title, msg, data = backup_restore.op_backup_create()
        if ok:
            return ok_response(title, msg, data=data if isinstance(data, dict) else None)
        return error_response("backup_create_failed", title, msg)

    if action == "restore_latest":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Backup/Restore", "Dangerous actions dinonaktifkan via env.")
        ok, title, msg = backup_restore.op_restore_latest_local()
        if ok:
            return ok_response(title, msg)
        return error_response("backup_restore_latest_failed", title, msg)

    if action == "restore_from_upload":
        if not settings.enable_dangerous_actions:
            return error_response("forbidden", "Backup/Restore", "Dangerous actions dinonaktifkan via env.")
        ok_param, upload_or_err = require_param(params, "upload_path", "Backup/Restore - Restore Upload")
        if not ok_param:
            return upload_or_err
        ok, title, msg = backup_restore.op_restore_from_upload(str(upload_or_err))
        if ok:
            return ok_response(title, msg)
        return error_response("backup_restore_upload_failed", title, msg)

    return error_response("unknown_action", "Backup/Restore", f"Action tidak dikenal: {action}")
