from ..utils.response import error_response, ok_response


INFO_TEXT = (
    "Menu 9 disiapkan untuk lifecycle installer bot Discord.\n"
    "Gunakan installer shell standalone untuk aksi install/update service.\n"
    "Bot ini tidak memanggil manage.sh dan berjalan sebagai stack terpisah."
)


def handle(action: str, params: dict, settings) -> dict:
    if action == "info":
        return ok_response("Install BOT Discord", INFO_TEXT)
    return error_response("unknown_action", "Install BOT Discord", f"Action tidak dikenal: {action}")
