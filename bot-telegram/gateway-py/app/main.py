from __future__ import annotations
import io
import logging
import socket
import time
from dataclasses import dataclass
import html
from pathlib import Path

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .backend_client import (
    BackendClient,
    BackendDomainOption,
    BackendError,
    BackendInboundOption,
    BackendRootDomainOption,
    BackendUserOption,
)
from .commands_loader import ActionSpec, CommandCatalog, MenuSpec
from .config import AppConfig, load_config
from .render import (
    action_form_prompt,
    action_result_text,
    confirm_text,
    decode_download_payload,
    main_menu_text,
    menu_text,
)


LOGGER = logging.getLogger("xray-telegram-gateway")
CALLBACK_SEP = "|"
ACTIONS_PER_PAGE = 6
BUTTONS_PER_ROW = 2
BUTTON_LABEL_MAX = 28
CALLBACK_DATA_MAX_LEN = 96
CLEANUP_FULL_SWEEP = -1
CLEANUP_MAX_LIMIT = 200
CLEANUP_KEEP_MESSAGES = 1
CLEANUP_MAX_SCAN_IDS = 2000
DELETE_PICK_PAGE_SIZE = 12
DELETE_PICK_PROTOCOLS = ("vless", "vmess", "trojan")
FORM_CHOICE_PAGE_SIZE = 12
FORM_CHOICE_PROTOCOLS = ("vless", "vmess", "trojan")
ROOT_DOMAIN_FALLBACK_OPTIONS = (
    "vyxara1.web.id",
    "vyxara2.web.id",
)
FORM_CHOICE_MANUAL_VALUE = "__manual_input__"
FORM_CHOICE_SKIP_VALUE = "__skip_optional__"
FORM_CHOICE_USERNAME_ACTIONS = {
    "extend_expiry",
    "account_info",
    "detail",
    "set_quota_limit",
    "reset_quota_used",
    "manual_block",
    "ip_limit_enable",
    "set_ip_limit",
    "unlock_ip_lock",
    "set_speed_download",
    "set_speed_upload",
    "speed_limit",
    "set_warp_user_mode",
}
KEY_PENDING_FORM = "pending_form"
KEY_PENDING_CONFIRM = "pending_confirm"
KEY_PENDING_DELETE_PICK = "pending_delete_pick"
KEY_PENDING_UPLOAD_RESTORE = "pending_upload_restore"
KEY_LAST_ACTION_TS = "last_action_ts"
KEY_LAST_CLEANUP_TS = "last_cleanup_ts"
BOT_ROOT = Path(__file__).resolve().parents[2]
UPLOAD_RESTORE_MAX_BYTES = 20 * 1024 * 1024
UPLOAD_RESTORE_DIRS = (
    Path("/var/lib/xray-telegram-bot/tmp/uploads"),
    Path("/opt/bot-telegram/runtime/tmp/uploads"),
    BOT_ROOT / "runtime" / "tmp" / "uploads",
)
DOWNLOAD_LOCAL_ALLOW_DIRS = (
    Path("/var/lib/xray-telegram-bot/backups/archives"),
    Path("/opt/bot-telegram/runtime/backups/archives"),
    BOT_ROOT / "runtime" / "backups" / "archives",
)


@dataclass
class Runtime:
    config: AppConfig
    catalog: CommandCatalog
    backend: BackendClient
    hostname: str


def _get_runtime(context: ContextTypes.DEFAULT_TYPE) -> Runtime:
    runtime = context.application.bot_data.get("runtime")
    if not isinstance(runtime, Runtime):
        raise RuntimeError("Runtime belum terinisialisasi.")
    return runtime


def _is_authorized(runtime: Runtime, update: Update) -> tuple[bool, str]:
    if runtime.config.allow_unrestricted_access:
        return True, ""

    user_id = str(update.effective_user.id) if update.effective_user else ""
    chat_id = str(update.effective_chat.id) if update.effective_chat else ""

    if runtime.config.admin_user_ids and user_id not in runtime.config.admin_user_ids:
        return False, "Akses ditolak: user Telegram belum terdaftar sebagai admin."

    if runtime.config.admin_chat_ids and chat_id not in runtime.config.admin_chat_ids:
        return False, "Akses ditolak: chat ini belum diizinkan untuk panel."

    return True, ""


def _clear_pending(context: ContextTypes.DEFAULT_TYPE) -> None:
    pending_confirm = context.user_data.get(KEY_PENDING_CONFIRM)
    if isinstance(pending_confirm, dict):
        action_id = str(pending_confirm.get("action_id") or "").strip()
        params = pending_confirm.get("params") if isinstance(pending_confirm.get("params"), dict) else {}
        if action_id == "restore_from_upload" and isinstance(params, dict):
            _cleanup_uploaded_archive(str(params.get("upload_path") or ""))
    context.user_data.pop(KEY_PENDING_FORM, None)
    context.user_data.pop(KEY_PENDING_CONFIRM, None)
    context.user_data.pop(KEY_PENDING_DELETE_PICK, None)
    context.user_data.pop(KEY_PENDING_UPLOAD_RESTORE, None)


def _fmt_size(num: int) -> str:
    n = max(0, int(num))
    if n >= 1024**3:
        return f"{n / (1024**3):.2f} GiB"
    if n >= 1024**2:
        return f"{n / (1024**2):.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.2f} KiB"
    return f"{n} B"


def _is_subpath(path: Path, base: Path) -> bool:
    try:
        rp = path.resolve()
        rb = base.resolve()
    except Exception:
        return False
    return rp == rb or rb in rp.parents


def _resolve_restore_upload_dir() -> Path:
    for candidate in UPLOAD_RESTORE_DIRS:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except Exception:
            continue
    return UPLOAD_RESTORE_DIRS[0]


def _cleanup_uploaded_archive(raw_path: str) -> None:
    path_text = str(raw_path or "").strip()
    if not path_text:
        return
    try:
        resolved = Path(path_text).resolve()
    except Exception:
        return
    if not any(_is_subpath(resolved, root) for root in UPLOAD_RESTORE_DIRS):
        return
    try:
        resolved.unlink(missing_ok=True)
    except Exception:
        pass


def _resolve_local_download(data: dict) -> tuple[str, Path] | None:
    raw_path = str(data.get("download_local_path") or "").strip()
    if not raw_path:
        return None
    try:
        resolved = Path(raw_path).resolve()
    except Exception:
        return None
    if not resolved.exists() or not resolved.is_file():
        return None
    if not any(_is_subpath(resolved, root) for root in DOWNLOAD_LOCAL_ALLOW_DIRS):
        return None

    filename = str(data.get("download_filename") or "").strip() or resolved.name
    return filename, resolved


def _cooldown_remaining(
    context: ContextTypes.DEFAULT_TYPE,
    *,
    user_id: str,
    key: str,
    min_interval_sec: float,
) -> float:
    if min_interval_sec <= 0:
        return 0.0

    now = time.monotonic()
    scope = context.application.bot_data.setdefault("_cooldowns", {})
    user_scope = scope.setdefault(user_id, {})
    try:
        prev = float(user_scope.get(key, 0.0))
    except Exception:
        prev = 0.0

    elapsed = now - prev
    if elapsed < min_interval_sec:
        return min_interval_sec - elapsed

    user_scope[key] = now
    return 0.0


def _throttle_message(seconds_left: float) -> str:
    if seconds_left <= 1:
        return "Terlalu cepat. Coba lagi dalam ~1 detik."
    return f"Terlalu cepat. Coba lagi dalam ~{int(seconds_left + 0.99)} detik."


def _short_button_label(text: str, max_len: int = BUTTON_LABEL_MAX) -> str:
    if len(text) <= max_len:
        return text
    if max_len < 4:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def _rows_from_buttons(buttons: list[InlineKeyboardButton], per_row: int = BUTTONS_PER_ROW) -> list[list[InlineKeyboardButton]]:
    rows: list[list[InlineKeyboardButton]] = []
    for idx in range(0, len(buttons), per_row):
        rows.append(buttons[idx : idx + per_row])
    return rows


def _main_menu_keyboard(runtime: Runtime) -> InlineKeyboardMarkup:
    buttons: list[InlineKeyboardButton] = []
    for menu in runtime.catalog.menus:
        label = f"{menu.id}) {menu.label}"
        buttons.append(InlineKeyboardButton(_short_button_label(label), callback_data=f"m{CALLBACK_SEP}{menu.id}"))

    rows = _rows_from_buttons(buttons)
    rows.append([InlineKeyboardButton("🔄 Refresh", callback_data="h")])
    return InlineKeyboardMarkup(rows)


def _menu_pages(menu: MenuSpec) -> int:
    total = len(menu.actions)
    if total <= 0:
        return 1
    return ((total - 1) // ACTIONS_PER_PAGE) + 1


def _menu_keyboard(menu: MenuSpec, page: int) -> InlineKeyboardMarkup:
    total_pages = _menu_pages(menu)
    page = max(0, min(page, total_pages - 1))

    start = page * ACTIONS_PER_PAGE
    chunk = menu.actions[start : start + ACTIONS_PER_PAGE]

    buttons: list[InlineKeyboardButton] = []
    for action in chunk:
        buttons.append(
            InlineKeyboardButton(
                _short_button_label(action.label),
                callback_data=f"a{CALLBACK_SEP}{menu.id}{CALLBACK_SEP}{action.id}",
            )
        )

    rows = _rows_from_buttons(buttons)

    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"p{CALLBACK_SEP}{menu.id}{CALLBACK_SEP}{page - 1}"))
        nav.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="noop"))
        if page + 1 < total_pages:
            nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"p{CALLBACK_SEP}{menu.id}{CALLBACK_SEP}{page + 1}"))
        rows.append(nav)

    rows.append(
        [
            InlineKeyboardButton("🏠 Main Menu", callback_data="h"),
        ]
    )
    return InlineKeyboardMarkup(rows)


def _result_keyboard(menu_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("⬅️ Kembali ke Action", callback_data=f"m{CALLBACK_SEP}{menu_id}")],
            [InlineKeyboardButton("🏠 Main Menu", callback_data="h")],
        ]
    )


def _callback_chat_id(update: Update) -> int:
    query = update.callback_query
    if query is not None and query.message is not None:
        return query.message.chat.id
    if update.effective_chat is not None:
        return update.effective_chat.id
    raise RuntimeError("Chat ID callback tidak tersedia.")


def _confirm_keyboard(menu_id: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [InlineKeyboardButton("✅ Jalankan", callback_data="rc"), InlineKeyboardButton("❌ Batal", callback_data=f"m{CALLBACK_SEP}{menu_id}")],
        ]
    )


def _safe_int(raw: str, default: int = 0) -> int:
    try:
        return int(raw)
    except Exception:
        return default


def _delete_pick_proto_keyboard(menu_id: str) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    proto_buttons = [
        InlineKeyboardButton(proto.upper(), callback_data=f"dup_proto{CALLBACK_SEP}{proto}")
        for proto in DELETE_PICK_PROTOCOLS
    ]
    rows.extend(_rows_from_buttons(proto_buttons))
    rows.append([InlineKeyboardButton("⬅️ Kembali", callback_data=f"m{CALLBACK_SEP}{menu_id}")])
    return InlineKeyboardMarkup(rows)


def _delete_pick_users_keyboard(menu_id: str, page: int, users: list[str]) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    start = page * DELETE_PICK_PAGE_SIZE
    chunk = users[start : start + DELETE_PICK_PAGE_SIZE]

    user_buttons: list[InlineKeyboardButton] = []
    for idx, username in enumerate(chunk, start=start):
        user_buttons.append(
            InlineKeyboardButton(
                _short_button_label(username, max_len=22),
                callback_data=f"dup_user{CALLBACK_SEP}{idx}",
            )
        )
    rows.extend(_rows_from_buttons(user_buttons))

    total_pages = ((len(users) - 1) // DELETE_PICK_PAGE_SIZE) + 1 if users else 1
    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"dup_page{CALLBACK_SEP}{page - 1}"))
        nav.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="noop"))
        if page + 1 < total_pages:
            nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"dup_page{CALLBACK_SEP}{page + 1}"))
        rows.append(nav)

    rows.append([InlineKeyboardButton("↩️ Ganti Protocol", callback_data=f"dup_proto_menu{CALLBACK_SEP}{menu_id}")])
    rows.append([InlineKeyboardButton("⬅️ Kembali", callback_data=f"m{CALLBACK_SEP}{menu_id}")])
    return InlineKeyboardMarkup(rows)


def _delete_pick_text_proto() -> str:
    return (
        "<b>User Management · Delete User</b>\n"
        "Pilih protocol dulu, lalu pilih username dari daftar."
    )


def _delete_pick_text_users(proto: str, page: int, users: list[str]) -> str:
    total_pages = ((len(users) - 1) // DELETE_PICK_PAGE_SIZE) + 1 if users else 1
    return (
        "<b>User Management · Delete User</b>\n"
        f"Protocol: <code>{html.escape(proto.upper())}</code>\n"
        f"Total user: <code>{len(users)}</code>\n"
        f"Halaman: <code>{page + 1}/{total_pages}</code>\n"
        "Pilih user yang mau dihapus:"
    )


async def _show_delete_user_proto_picker(
    *,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    query,
    menu_id: str,
) -> None:
    context.user_data.pop(KEY_PENDING_DELETE_PICK, None)
    await _send_or_edit(
        query=query,
        chat_id=chat_id,
        context=context,
        text=_delete_pick_text_proto(),
        reply_markup=_delete_pick_proto_keyboard(menu_id),
    )


async def _show_delete_user_list_picker(
    *,
    runtime: Runtime,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    query,
    menu_id: str,
    proto: str,
    page: int = 0,
) -> None:
    try:
        options: list[BackendUserOption] = await runtime.backend.list_user_options(proto=proto)
    except BackendError as exc:
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=(
                "<b>❌ Gagal Ambil Daftar User</b>\n"
                f"<pre>{html.escape(str(exc)[:1200])}</pre>"
            ),
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("↩️ Kembali", callback_data=f"dup_proto_menu{CALLBACK_SEP}{menu_id}")]]
            ),
        )
        return

    usernames = list(dict.fromkeys([o.username for o in options if o.proto == proto]))
    if not usernames:
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=(
                "<b>User Management · Delete User</b>\n"
                f"Protocol <code>{html.escape(proto.upper())}</code> belum punya user."
            ),
            reply_markup=InlineKeyboardMarkup(
                [[InlineKeyboardButton("↩️ Ganti Protocol", callback_data=f"dup_proto_menu{CALLBACK_SEP}{menu_id}")]]
            ),
        )
        return

    page_max = ((len(usernames) - 1) // DELETE_PICK_PAGE_SIZE)
    page = max(0, min(page, page_max))
    context.user_data[KEY_PENDING_DELETE_PICK] = {
        "menu_id": menu_id,
        "proto": proto,
        "users": usernames,
        "page": page,
    }
    await _send_or_edit(
        query=query,
        chat_id=chat_id,
        context=context,
        text=_delete_pick_text_users(proto, page, usernames),
        reply_markup=_delete_pick_users_keyboard(menu_id, page, usernames),
    )


def _serialize_choice_options(options: list[tuple[str, str]]) -> list[dict[str, str]]:
    return [{"label": str(label), "value": str(value)} for label, value in options]


def _is_truthy(raw: str) -> bool:
    val = str(raw or "").strip().lower()
    return val in {"1", "true", "on", "yes", "y", "enable", "enabled"}


def _field_is_required(pending: dict, field: ActionSpec) -> bool:
    if field.required:
        return True

    # Add User: saat speed limit ON, nilai down/up wajib diisi.
    if field.id in {"speed_down_mbit", "speed_up_mbit"}:
        params = pending.get("params") if isinstance(pending.get("params"), dict) else {}
        return _is_truthy(str(params.get("speed_limit_enabled") or ""))

    return False


def _pending_choice_options(pending: dict) -> list[dict[str, str]]:
    raw = pending.get("choice_options")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        label = str(item.get("label") or "").strip()
        value = str(item.get("value") or "").strip()
        if not label and not value:
            continue
        out.append({"label": label or value, "value": value or label})
    return out


def _is_click_only_field(action_id: str, field_id: str) -> bool:
    return action_id == "setup_domain_cloudflare" and field_id == "root_domain"


def _choice_total_pages(choice_options: list[dict[str, str]]) -> int:
    if not choice_options:
        return 1
    return ((len(choice_options) - 1) // FORM_CHOICE_PAGE_SIZE) + 1


def _choice_keyboard(menu_id: str, choice_options: list[dict[str, str]], page: int) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    if choice_options:
        start = page * FORM_CHOICE_PAGE_SIZE
        chunk = choice_options[start : start + FORM_CHOICE_PAGE_SIZE]
        option_buttons: list[InlineKeyboardButton] = []
        for idx, item in enumerate(chunk, start=start):
            option_buttons.append(
                InlineKeyboardButton(
                    _short_button_label(str(item.get("label") or str(item.get("value") or "")), max_len=22),
                    callback_data=f"pfc{CALLBACK_SEP}{idx}",
                )
            )
        rows.extend(_rows_from_buttons(option_buttons))

    total_pages = _choice_total_pages(choice_options)
    if total_pages > 1:
        nav: list[InlineKeyboardButton] = []
        if page > 0:
            nav.append(InlineKeyboardButton("◀️ Prev", callback_data=f"pfp{CALLBACK_SEP}{page - 1}"))
        nav.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="noop"))
        if page + 1 < total_pages:
            nav.append(InlineKeyboardButton("Next ▶️", callback_data=f"pfp{CALLBACK_SEP}{page + 1}"))
        rows.append(nav)

    rows.append([InlineKeyboardButton("❌ Batal", callback_data=f"cf{CALLBACK_SEP}{menu_id}")])
    return InlineKeyboardMarkup(rows)


async def _resolve_form_choice_options(runtime: Runtime, pending: dict, field_id: str) -> list[tuple[str, str]]:
    action_id = str(pending.get("action_id") or "").strip()
    params = pending.get("params") if isinstance(pending.get("params"), dict) else {}

    if field_id == "proto":
        return [(proto.upper(), proto) for proto in FORM_CHOICE_PROTOCOLS]

    if field_id in {"enabled", "proxied", "allow_existing_same_ip", "speed_limit_enabled"}:
        return [("ON", "on"), ("OFF", "off")]

    if field_id == "mode":
        if action_id == "extend_expiry":
            return [("Extend (+hari)", "extend"), ("Set Tanggal", "set")]
        if action_id == "set_egress_mode":
            return [("Direct", "direct"), ("Warp", "warp"), ("Balancer", "balancer")]
        if action_id == "set_warp_global_mode":
            return [("Direct", "direct"), ("Warp", "warp")]
        if action_id in {"set_warp_user_mode", "set_warp_inbound_mode", "set_warp_domain_mode"}:
            return [("Direct", "direct"), ("Warp", "warp"), ("Off (inherit)", "off")]

    if field_id == "strategy":
        if action_id == "set_balancer_strategy":
            return [("random", "random"), ("roundRobin", "roundRobin"), ("leastPing", "leastPing"), ("leastLoad", "leastLoad")]
        if action_id == "set_dns_query_strategy":
            return [
                ("UseIP", "UseIP"),
                ("UseIPv4", "UseIPv4"),
                ("UseIPv6", "UseIPv6"),
                ("PreferIPv4", "PreferIPv4"),
                ("PreferIPv6", "PreferIPv6"),
            ]

    if field_id == "subdomain_mode":
        return [("AUTO", "auto"), ("MANUAL", "manual")]

    if field_id == "root_domain" and action_id == "setup_domain_cloudflare":
        try:
            options: list[BackendRootDomainOption] = await runtime.backend.list_domain_root_options()
            roots = list(dict.fromkeys([o.root_domain for o in options if o.root_domain]))
        except BackendError:
            roots = []

        if not roots:
            roots = list(ROOT_DOMAIN_FALLBACK_OPTIONS)
        return [(root, root) for root in roots]

    if field_id == "days":
        return [("7", "7"), ("30", "30"), ("60", "60"), ("90", "90")]

    if field_id == "quota_gb":
        return [("10", "10"), ("50", "50"), ("100", "100"), ("200", "200")]

    if field_id == "ip_limit":
        return [("OFF (0)", "0"), ("1", "1"), ("2", "2"), ("3", "3")]

    if field_id == "speed_down_mbit":
        return [("10", "10"), ("20", "20"), ("50", "50"), ("100", "100")]

    if field_id == "speed_up_mbit":
        return [("5", "5"), ("10", "10"), ("20", "20"), ("50", "50")]

    if field_id == "limit":
        return [("10", "10"), ("15", "15"), ("25", "25"), ("50", "50"), ("100", "100")]

    if field_id == "username" and action_id in FORM_CHOICE_USERNAME_ACTIONS:
        proto = str(params.get("proto") or "").strip().lower()
        if proto not in FORM_CHOICE_PROTOCOLS:
            return []
        try:
            options: list[BackendUserOption] = await runtime.backend.list_user_options(proto=proto)
        except BackendError:
            return []
        usernames = list(dict.fromkeys([o.username for o in options if o.proto == proto and o.username]))
        return [(u, u) for u in usernames]

    if field_id == "inbound_tag" and action_id == "set_warp_inbound_mode":
        try:
            options: list[BackendInboundOption] = await runtime.backend.list_inbound_options()
        except BackendError:
            return []
        tags = list(dict.fromkeys([o.tag for o in options if o.tag]))
        return [(tag, tag) for tag in tags]

    if field_id == "entry" and action_id == "set_warp_domain_mode":
        mode = str(params.get("mode") or "").strip().lower()
        mode_q = mode if mode in {"direct", "warp"} else None
        try:
            options: list[BackendDomainOption] = await runtime.backend.list_warp_domain_options(mode=mode_q)
        except BackendError:
            return []
        entries = list(dict.fromkeys([o.entry for o in options if o.entry]))
        return [(ent, ent) for ent in entries]

    return []


async def _render_pending_choice_prompt(
    *,
    runtime: Runtime,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    pending: dict,
    query=None,
) -> None:
    menu = runtime.catalog.get_menu(str(pending.get("menu_id", "")))
    action = runtime.catalog.get_action(str(pending.get("menu_id", "")), str(pending.get("action_id", "")))
    if menu is None or action is None or action.modal is None:
        raise RuntimeError("State pilihan input tidak valid.")

    idx = int(pending.get("index", 0))
    if idx < 0 or idx >= len(action.modal.fields):
        raise RuntimeError("Index pilihan input tidak valid.")
    field = action.modal.fields[idx]

    choice_options = _pending_choice_options(pending)
    page_max = _choice_total_pages(choice_options) - 1
    page = max(0, min(int(pending.get("choice_page", 0)), page_max))
    pending["choice_page"] = page
    context.user_data[KEY_PENDING_FORM] = pending

    await _send_or_edit(
        query=query,
        chat_id=chat_id,
        context=context,
        text=(
            f"{action_form_prompt(menu, action, field, idx + 1, len(action.modal.fields))}\n\n"
            "Pilih nilainya lewat tombol."
        ),
        reply_markup=_choice_keyboard(menu.id, choice_options, page),
    )


def _manual_input_prompt(menu: MenuSpec, action: ActionSpec, field, idx: int, total: int) -> str:
    return (
        f"{action_form_prompt(menu, action, field, idx, total)}\n\n"
        "Mode input manual aktif. Ketik nilainya sekarang."
    )


async def _send_or_edit(
    *,
    query,
    chat_id: int,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    reply_markup: InlineKeyboardMarkup | None = None,
) -> None:
    if query is not None:
        try:
            await query.edit_message_text(text=text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)
            return
        except BadRequest as exc:
            # Hindari duplikasi pesan saat payload tidak berubah.
            if "message is not modified" in str(exc).lower():
                return
            LOGGER.debug("Edit message gagal, fallback kirim pesan baru: %s", exc)
        except Exception as exc:
            LOGGER.debug("Edit message exception, fallback kirim pesan baru: %s", exc)

    await context.bot.send_message(
        chat_id=chat_id,
        text=text,
        parse_mode=ParseMode.HTML,
        reply_markup=reply_markup,
    )


async def _run_action(
    *,
    runtime: Runtime,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    menu_id: str,
    action_id: str,
    params: dict[str, str],
    query,
) -> None:
    try:
        result = await runtime.backend.run_action(menu_id=menu_id, action=action_id, params=params)
    except BackendError as exc:
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=(
                "<b>❌ Backend Error</b>\n"
                "Tidak bisa menjalankan action.\n\n"
                f"<pre>{str(exc)[:1800]}</pre>"
            ),
            reply_markup=_result_keyboard(menu_id),
        )
        return

    await _send_or_edit(
        query=query,
        chat_id=chat_id,
        context=context,
        text=action_result_text(result),
        reply_markup=_result_keyboard(menu_id),
    )

    local_attachment = _resolve_local_download(result.data)
    if local_attachment is not None:
        filename, local_path = local_attachment
        try:
            with local_path.open("rb") as fp:
                await context.bot.send_document(
                    chat_id=chat_id,
                    document=fp,
                    filename=filename,
                    caption=f"File hasil: {filename}",
                )
        except Exception as exc:
            LOGGER.warning("Gagal kirim lampiran lokal %s: %s", local_path, exc)
        return

    attachment = decode_download_payload(result.data)
    if attachment is None:
        return

    filename, payload = attachment
    if not payload:
        return

    bio = io.BytesIO(payload)
    bio.name = filename
    try:
        await context.bot.send_document(
            chat_id=chat_id,
            document=bio,
            filename=filename,
            caption=f"File hasil: {filename}",
        )
    except Exception as exc:
        LOGGER.warning("Gagal kirim lampiran %s: %s", filename, exc)


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    ok, reason = _is_authorized(runtime, update)
    if not ok:
        await update.effective_message.reply_text(reason)
        return

    await update.effective_message.reply_text(
        "Selamat datang. Gunakan /panel untuk membuka kontrol server.",
    )


def _parse_cleanup_limit(context: ContextTypes.DEFAULT_TYPE) -> tuple[int | None, str]:
    if not context.args:
        return CLEANUP_FULL_SWEEP, ""

    raw = str(context.args[0]).strip()
    if not raw.isdigit():
        return None, f"Argumen cleanup harus angka 1-{CLEANUP_MAX_LIMIT}. Contoh: /cleanup 80"

    limit = int(raw)
    if limit < 1 or limit > CLEANUP_MAX_LIMIT:
        return None, f"Batas cleanup harus antara 1 sampai {CLEANUP_MAX_LIMIT}."

    return limit, ""


async def cmd_cleanup(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    ok, reason = _is_authorized(runtime, update)
    if not ok:
        if update.effective_message:
            await update.effective_message.reply_text(reason)
        return

    chat = update.effective_chat
    msg = update.effective_message
    if chat is None or msg is None:
        return

    user_id = str(update.effective_user.id) if update.effective_user else ""
    wait = _cooldown_remaining(
        context,
        user_id=user_id,
        key=KEY_LAST_CLEANUP_TS,
        min_interval_sec=runtime.config.cleanup_cooldown_seconds,
    )
    if wait > 0:
        await msg.reply_text(_throttle_message(wait))
        return

    limit, err = _parse_cleanup_limit(context)
    if limit is None:
        await msg.reply_text(err)
        return

    _clear_pending(context)

    deleted = 0
    skipped = 0
    anchor_message_id = int(msg.message_id)
    scan_message_id = anchor_message_id
    full_sweep = limit == CLEANUP_FULL_SWEEP
    target_deleted = max(anchor_message_id - CLEANUP_KEEP_MESSAGES, 0) if full_sweep else int(limit)
    max_scan = max(CLEANUP_MAX_SCAN_IDS, int(limit) + CLEANUP_KEEP_MESSAGES) if not full_sweep else CLEANUP_MAX_SCAN_IDS
    scanned = 0

    # Hapus sampai target jumlah pesan TERHAPUS tercapai, bukan sekadar jumlah ID yang dipindai.
    while scan_message_id >= 1 and deleted < target_deleted and scanned < max_scan:
        try:
            await context.bot.delete_message(chat_id=chat.id, message_id=scan_message_id)
            deleted += 1
        except Exception:
            skipped += 1
        scan_message_id -= 1
        scanned += 1

    suffix = ""
    if full_sweep and scanned >= max_scan and deleted < target_deleted:
        suffix = f" (dibatasi scan maksimal {max_scan} message-id)"

    await context.bot.send_message(
        chat_id=chat.id,
        text=f"🧹 Cleanup selesai: {deleted} pesan dihapus, {skipped} dilewati.{suffix}",
    )


async def cmd_panel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    ok, reason = _is_authorized(runtime, update)
    if not ok:
        await update.effective_message.reply_text(reason)
        return

    _clear_pending(context)

    await update.effective_message.reply_text(
        main_menu_text(runtime.hostname, len(runtime.catalog.menus)),
        parse_mode=ParseMode.HTML,
        reply_markup=_main_menu_keyboard(runtime),
    )


async def _prompt_next_form_field(
    *,
    runtime: Runtime,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    pending: dict,
    query=None,
) -> None:
    menu = runtime.catalog.get_menu(str(pending.get("menu_id", "")))
    action = runtime.catalog.get_action(str(pending.get("menu_id", "")), str(pending.get("action_id", "")))
    if menu is None or action is None or action.modal is None:
        raise RuntimeError("State form tidak valid.")

    idx = int(pending.get("index", 0))
    if idx < 0 or idx >= len(action.modal.fields):
        raise RuntimeError("Index form tidak valid.")

    field = action.modal.fields[idx]
    click_only_field = _is_click_only_field(action.id, field.id)
    choice_options = await _resolve_form_choice_options(runtime, pending, field.id)
    choice_with_manual: list[tuple[str, str]] = list(choice_options)
    if not click_only_field:
        if choice_options:
            choice_with_manual.append(("✍️ Lainnya (input manual)", FORM_CHOICE_MANUAL_VALUE))
        else:
            choice_with_manual.append(("✍️ Input Manual", FORM_CHOICE_MANUAL_VALUE))
    if not click_only_field and not _field_is_required(pending, field):
        choice_with_manual.append(("⏭️ Lewati", FORM_CHOICE_SKIP_VALUE))

    pending.pop("manual_entry", None)
    pending["choice_options"] = _serialize_choice_options(choice_with_manual)
    pending["choice_page"] = 0
    context.user_data[KEY_PENDING_FORM] = pending
    await _render_pending_choice_prompt(
        runtime=runtime,
        context=context,
        chat_id=chat_id,
        pending=pending,
        query=query,
    )


async def _submit_pending_form_value(
    *,
    runtime: Runtime,
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    pending: dict,
    raw_value: str,
    query=None,
    reply_message=None,
) -> None:
    menu_id = str(pending.get("menu_id", ""))
    action_id = str(pending.get("action_id", ""))
    menu = runtime.catalog.get_menu(menu_id)
    action = runtime.catalog.get_action(menu_id, action_id)
    if menu is None or action is None or action.modal is None:
        _clear_pending(context)
        if reply_message is not None:
            await reply_message.reply_text("Sesi input rusak. Jalankan /panel lagi.")
        elif query is not None:
            await query.answer("Sesi input rusak. Jalankan /panel lagi.", show_alert=True)
        return

    idx = int(pending.get("index", 0))
    if idx < 0 or idx >= len(action.modal.fields):
        _clear_pending(context)
        if reply_message is not None:
            await reply_message.reply_text("Sesi input sudah selesai. Jalankan /panel lagi.")
        elif query is not None:
            await query.answer("Sesi input sudah selesai. Jalankan /panel lagi.", show_alert=True)
        return

    field = action.modal.fields[idx]
    value = str(raw_value or "").strip()
    manual_entry = bool(pending.get("manual_entry"))
    if manual_entry and len(value) > runtime.config.max_manual_input_len:
        msg = f"Input terlalu panjang (maks {runtime.config.max_manual_input_len} karakter)."
        if reply_message is not None:
            await reply_message.reply_text(msg)
        elif query is not None:
            await query.answer(msg, show_alert=True)
        return

    choice_options = _pending_choice_options(pending)
    if choice_options and not manual_entry:
        allowed = {str(item.get("value") or "") for item in choice_options}
        if value not in allowed:
            if reply_message is not None:
                await reply_message.reply_text("Untuk field ini gunakan tombol pilihan yang tersedia.")
            elif query is not None:
                await query.answer("Gunakan tombol pilihan.", show_alert=True)
            return

        if value == FORM_CHOICE_MANUAL_VALUE:
            pending.pop("choice_options", None)
            pending.pop("choice_page", None)
            pending["manual_entry"] = True
            context.user_data[KEY_PENDING_FORM] = pending
            text = _manual_input_prompt(menu, action, field, idx + 1, len(action.modal.fields))
            markup = InlineKeyboardMarkup(
                [[InlineKeyboardButton("❌ Batal", callback_data=f"cf{CALLBACK_SEP}{menu_id}")]]
            )
            if query is not None:
                await _send_or_edit(
                    query=query,
                    chat_id=chat_id,
                    context=context,
                    text=text,
                    reply_markup=markup,
                )
            elif reply_message is not None:
                await reply_message.reply_text(
                    text,
                    parse_mode=ParseMode.HTML,
                    reply_markup=markup,
                )
            return

        if value == FORM_CHOICE_SKIP_VALUE:
            value = ""
    elif value.lower() in {"-", "skip", "lewati"}:
        value = ""

    if manual_entry:
        pending.pop("manual_entry", None)

    if _field_is_required(pending, field) and not value:
        if reply_message is not None:
            await reply_message.reply_text("Field ini wajib diisi. Coba lagi.")
        elif query is not None:
            await query.answer("Field ini wajib diisi.", show_alert=True)
        await _prompt_next_form_field(runtime=runtime, context=context, chat_id=chat_id, pending=pending, query=query)
        return

    params = pending.get("params") if isinstance(pending.get("params"), dict) else {}
    if value:
        params[field.id] = value

    pending["params"] = params
    next_idx = idx + 1
    if field.id == "speed_limit_enabled" and not _is_truthy(value):
        # Saat speed limit OFF/skip, lewati field speed down/up.
        while next_idx < len(action.modal.fields):
            next_field_id = action.modal.fields[next_idx].id
            if next_field_id not in {"speed_down_mbit", "speed_up_mbit"}:
                break
            next_idx += 1

    pending["index"] = next_idx
    pending.pop("choice_options", None)
    pending.pop("choice_page", None)
    context.user_data[KEY_PENDING_FORM] = pending

    if pending["index"] < len(action.modal.fields):
        await _prompt_next_form_field(runtime=runtime, context=context, chat_id=chat_id, pending=pending, query=query)
        return

    context.user_data.pop(KEY_PENDING_FORM, None)

    if action.confirm:
        context.user_data[KEY_PENDING_CONFIRM] = {
            "menu_id": menu_id,
            "action_id": action_id,
            "params": params,
        }
        if query is not None:
            await _send_or_edit(
                query=query,
                chat_id=chat_id,
                context=context,
                text=confirm_text(menu, action, params),
                reply_markup=_confirm_keyboard(menu_id),
            )
        elif reply_message is not None:
            await reply_message.reply_text(
                confirm_text(menu, action, params),
                parse_mode=ParseMode.HTML,
                reply_markup=_confirm_keyboard(menu_id),
            )
        return

    if query is not None:
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text="<b>⏳ Menjalankan action...</b>",
            reply_markup=_result_keyboard(menu_id),
        )
    elif reply_message is not None:
        await reply_message.reply_text("⏳ Menjalankan action...")

    await _run_action(
        runtime=runtime,
        context=context,
        chat_id=chat_id,
        menu_id=menu_id,
        action_id=action_id,
        params=params,
        query=query,
    )


async def on_document_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    ok, reason = _is_authorized(runtime, update)
    if not ok:
        if update.effective_message:
            await update.effective_message.reply_text(reason)
        return

    pending_upload = context.user_data.get(KEY_PENDING_UPLOAD_RESTORE)
    if not isinstance(pending_upload, dict):
        return

    msg = update.effective_message
    chat = update.effective_chat
    doc = msg.document if msg else None
    if msg is None or chat is None or doc is None:
        return

    name = str(doc.file_name or "").strip()
    if not name.lower().endswith(".tar.gz"):
        await msg.reply_text("File restore harus berekstensi .tar.gz")
        return

    size_bytes = int(doc.file_size or 0)
    if size_bytes > UPLOAD_RESTORE_MAX_BYTES:
        await msg.reply_text(
            (
                "Ukuran file terlalu besar untuk restore upload.\n"
                f"Maksimal: {_fmt_size(UPLOAD_RESTORE_MAX_BYTES)}\n"
                f"File ini: {_fmt_size(size_bytes)}"
            )
        )
        return

    upload_dir = _resolve_restore_upload_dir()
    upload_id = f"{int(time.time())}-{doc.file_unique_id}"
    upload_name = f"restore-upload-{upload_id}.tar.gz"
    upload_path = upload_dir / upload_name

    try:
        tg_file = await doc.get_file()
        await tg_file.download_to_drive(custom_path=str(upload_path))
    except Exception as exc:
        LOGGER.warning("Gagal download file restore upload: %s", exc)
        await msg.reply_text("Gagal mengunduh file dari Telegram. Coba kirim ulang.")
        return

    menu_id = str(pending_upload.get("menu_id") or "10")
    action_id = str(pending_upload.get("action_id") or "restore_from_upload")
    menu = runtime.catalog.get_menu(menu_id)
    action = runtime.catalog.get_action(menu_id, action_id)
    if menu is None or action is None:
        context.user_data.pop(KEY_PENDING_UPLOAD_RESTORE, None)
        _cleanup_uploaded_archive(str(upload_path))
        await msg.reply_text("Action restore upload tidak ditemukan. Jalankan /panel lagi.")
        return

    params = {"upload_path": str(upload_path)}
    context.user_data.pop(KEY_PENDING_UPLOAD_RESTORE, None)
    context.user_data[KEY_PENDING_CONFIRM] = {
        "menu_id": menu_id,
        "action_id": action_id,
        "params": params,
    }

    confirm_msg = (
        f"<b>Konfirmasi: {html.escape(menu.label)} · {html.escape(action.label)}</b>\n\n"
        f"- File: <code>{html.escape(name or upload_name)}</code>\n"
        f"- Ukuran: <code>{html.escape(_fmt_size(size_bytes))}</code>\n\n"
        "Lanjutkan eksekusi restore?"
    )
    await msg.reply_text(
        confirm_msg,
        parse_mode=ParseMode.HTML,
        reply_markup=_confirm_keyboard(menu_id),
    )


async def on_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    ok, reason = _is_authorized(runtime, update)
    if not ok:
        await update.effective_message.reply_text(reason)
        return

    pending_upload = context.user_data.get(KEY_PENDING_UPLOAD_RESTORE)
    if isinstance(pending_upload, dict):
        await update.effective_message.reply_text(
            "Sesi restore upload aktif. Kirim file backup .tar.gz atau tekan Batal."
        )
        return

    pending = context.user_data.get(KEY_PENDING_FORM)
    if not isinstance(pending, dict):
        return

    await _submit_pending_form_value(
        runtime=runtime,
        context=context,
        chat_id=update.effective_chat.id,
        pending=pending,
        raw_value=(update.effective_message.text or ""),
        query=None,
        reply_message=update.effective_message,
    )


async def on_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    query = update.callback_query
    if query is None:
        return

    ok, reason = _is_authorized(runtime, update)
    if not ok:
        await query.answer(reason, show_alert=True)
        return

    data = str(query.data or "")
    if not data or len(data) > CALLBACK_DATA_MAX_LEN:
        await query.answer("Payload callback tidak valid.", show_alert=True)
        return
    await query.answer()
    chat_id = _callback_chat_id(update)
    user_id = str(update.effective_user.id) if update.effective_user else ""

    if data == "noop":
        return

    if data == "h":
        _clear_pending(context)
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=main_menu_text(runtime.hostname, len(runtime.catalog.menus)),
            reply_markup=_main_menu_keyboard(runtime),
        )
        return

    if data.startswith(f"cf{CALLBACK_SEP}"):
        _clear_pending(context)
        parts = data.split(CALLBACK_SEP)
        menu_id = parts[1] if len(parts) > 1 else ""
        menu = runtime.catalog.get_menu(menu_id)
        if menu is None:
            await _send_or_edit(
                query=query,
                chat_id=chat_id,
                context=context,
                text=main_menu_text(runtime.hostname, len(runtime.catalog.menus)),
                reply_markup=_main_menu_keyboard(runtime),
            )
            return
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=menu_text(menu, 0, _menu_pages(menu)),
            reply_markup=_menu_keyboard(menu, 0),
        )
        return

    if data.startswith(f"pfp{CALLBACK_SEP}"):
        pending = context.user_data.get(KEY_PENDING_FORM)
        if not isinstance(pending, dict):
            await query.answer("Sesi input tidak aktif.", show_alert=True)
            return
        choice_options = _pending_choice_options(pending)
        if not choice_options:
            await query.answer("Pilihan tombol tidak tersedia.", show_alert=True)
            return
        parts = data.split(CALLBACK_SEP)
        page = _safe_int(parts[1] if len(parts) > 1 else "0", default=0)
        page_max = _choice_total_pages(choice_options) - 1
        page = max(0, min(page, page_max))
        pending["choice_page"] = page
        context.user_data[KEY_PENDING_FORM] = pending
        await _render_pending_choice_prompt(
            runtime=runtime,
            context=context,
            chat_id=chat_id,
            pending=pending,
            query=query,
        )
        return

    if data.startswith(f"pfc{CALLBACK_SEP}"):
        pending = context.user_data.get(KEY_PENDING_FORM)
        if not isinstance(pending, dict):
            await query.answer("Sesi input tidak aktif.", show_alert=True)
            return
        choice_options = _pending_choice_options(pending)
        if not choice_options:
            await query.answer("Pilihan tombol tidak tersedia.", show_alert=True)
            return
        parts = data.split(CALLBACK_SEP)
        idx = _safe_int(parts[1] if len(parts) > 1 else "-1", default=-1)
        if idx < 0 or idx >= len(choice_options):
            await query.answer("Pilihan tidak valid.", show_alert=True)
            return
        value = str(choice_options[idx].get("value") or "")
        await _submit_pending_form_value(
            runtime=runtime,
            context=context,
            chat_id=chat_id,
            pending=pending,
            raw_value=value,
            query=query,
            reply_message=None,
        )
        return

    if data.startswith(f"dup_proto_menu{CALLBACK_SEP}"):
        parts = data.split(CALLBACK_SEP)
        menu_id = parts[1] if len(parts) > 1 else "2"
        await _show_delete_user_proto_picker(
            context=context,
            chat_id=chat_id,
            query=query,
            menu_id=menu_id,
        )
        return

    if data.startswith(f"dup_proto{CALLBACK_SEP}"):
        parts = data.split(CALLBACK_SEP)
        if len(parts) != 2:
            await query.answer("Protocol tidak valid.", show_alert=True)
            return
        proto = parts[1].strip().lower()
        if proto not in DELETE_PICK_PROTOCOLS:
            await query.answer("Protocol tidak valid.", show_alert=True)
            return
        await _show_delete_user_list_picker(
            runtime=runtime,
            context=context,
            chat_id=chat_id,
            query=query,
            menu_id="2",
            proto=proto,
            page=0,
        )
        return

    if data.startswith(f"dup_page{CALLBACK_SEP}"):
        state = context.user_data.get(KEY_PENDING_DELETE_PICK)
        if not isinstance(state, dict):
            await query.answer("Sesi pemilihan user tidak aktif.", show_alert=True)
            return
        proto = str(state.get("proto") or "").strip().lower()
        menu_id = str(state.get("menu_id") or "2")
        users = state.get("users") if isinstance(state.get("users"), list) else []
        if proto not in DELETE_PICK_PROTOCOLS or not users:
            await query.answer("Sesi pemilihan user tidak valid.", show_alert=True)
            return
        parts = data.split(CALLBACK_SEP)
        page = _safe_int(parts[1] if len(parts) > 1 else "0", default=0)
        page_max = ((len(users) - 1) // DELETE_PICK_PAGE_SIZE)
        page = max(0, min(page, page_max))
        state["page"] = page
        context.user_data[KEY_PENDING_DELETE_PICK] = state
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=_delete_pick_text_users(proto, page, users),
            reply_markup=_delete_pick_users_keyboard(menu_id, page, users),
        )
        return

    if data.startswith(f"dup_user{CALLBACK_SEP}"):
        state = context.user_data.get(KEY_PENDING_DELETE_PICK)
        if not isinstance(state, dict):
            await query.answer("Sesi pemilihan user tidak aktif.", show_alert=True)
            return
        proto = str(state.get("proto") or "").strip().lower()
        menu_id = str(state.get("menu_id") or "2")
        users = state.get("users") if isinstance(state.get("users"), list) else []
        if proto not in DELETE_PICK_PROTOCOLS or not users:
            await query.answer("Sesi pemilihan user tidak valid.", show_alert=True)
            return
        parts = data.split(CALLBACK_SEP)
        idx = _safe_int(parts[1] if len(parts) > 1 else "-1", default=-1)
        if idx < 0 or idx >= len(users):
            await query.answer("User tidak valid.", show_alert=True)
            return
        username = str(users[idx])
        context.user_data.pop(KEY_PENDING_DELETE_PICK, None)

        menu = runtime.catalog.get_menu(menu_id)
        action = runtime.catalog.get_action(menu_id, "delete_user")
        if menu is None or action is None:
            await query.answer("Action tidak ditemukan.", show_alert=True)
            return

        params = {
            "proto": proto,
            "username": username,
        }
        context.user_data[KEY_PENDING_CONFIRM] = {
            "menu_id": menu_id,
            "action_id": "delete_user",
            "params": params,
        }
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=confirm_text(menu, action, params),
            reply_markup=_confirm_keyboard(menu_id),
        )
        return

    if data == "rc":
        pending = context.user_data.get(KEY_PENDING_CONFIRM)
        if not isinstance(pending, dict):
            await query.answer("Tidak ada aksi yang menunggu konfirmasi.", show_alert=True)
            return

        wait = _cooldown_remaining(
            context,
            user_id=user_id,
            key=KEY_LAST_ACTION_TS,
            min_interval_sec=runtime.config.action_cooldown_seconds,
        )
        if wait > 0:
            await query.answer(_throttle_message(wait), show_alert=True)
            return

        menu_id = str(pending.get("menu_id", ""))
        action_id = str(pending.get("action_id", ""))
        params = pending.get("params") if isinstance(pending.get("params"), dict) else {}
        context.user_data.pop(KEY_PENDING_CONFIRM, None)

        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text="<b>⏳ Menjalankan action...</b>",
            reply_markup=_result_keyboard(menu_id),
        )
        await _run_action(
            runtime=runtime,
            context=context,
            chat_id=chat_id,
            menu_id=menu_id,
            action_id=action_id,
            params=params,
            query=query,
        )
        if action_id == "restore_from_upload":
            _cleanup_uploaded_archive(str(params.get("upload_path") or ""))
        return

    parts = data.split(CALLBACK_SEP)
    kind = parts[0]

    if kind == "m" and len(parts) == 2:
        _clear_pending(context)
        menu = runtime.catalog.get_menu(parts[1])
        if menu is None:
            await query.answer("Menu tidak ditemukan.", show_alert=True)
            return
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=menu_text(menu, 0, _menu_pages(menu)),
            reply_markup=_menu_keyboard(menu, 0),
        )
        return

    if kind == "p" and len(parts) == 3:
        menu = runtime.catalog.get_menu(parts[1])
        if menu is None:
            await query.answer("Menu tidak ditemukan.", show_alert=True)
            return
        try:
            page = int(parts[2])
        except ValueError:
            page = 0
        page = max(0, min(page, _menu_pages(menu) - 1))
        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text=menu_text(menu, page, _menu_pages(menu)),
            reply_markup=_menu_keyboard(menu, page),
        )
        return

    if kind == "a" and len(parts) == 3:
        menu_id = parts[1]
        action_id = parts[2]
        menu = runtime.catalog.get_menu(menu_id)
        action = runtime.catalog.get_action(menu_id, action_id)
        if menu is None or action is None:
            await query.answer("Action tidak ditemukan.", show_alert=True)
            return

        _clear_pending(context)

        if menu_id == "2" and action_id == "delete_user":
            await _show_delete_user_proto_picker(
                context=context,
                chat_id=chat_id,
                query=query,
                menu_id=menu_id,
            )
            return

        if menu_id == "10" and action_id == "restore_from_upload":
            context.user_data[KEY_PENDING_UPLOAD_RESTORE] = {
                "menu_id": menu_id,
                "action_id": action_id,
            }
            await _send_or_edit(
                query=query,
                chat_id=chat_id,
                context=context,
                text=(
                    "<b>Restore Upload</b>\n"
                    "Kirim file backup berekstensi <code>.tar.gz</code> lewat Telegram.\n"
                    f"Ukuran maksimal: <code>{html.escape(_fmt_size(UPLOAD_RESTORE_MAX_BYTES))}</code>\n\n"
                    "Setelah file diterima, bot akan minta konfirmasi sebelum restore dijalankan."
                ),
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("❌ Batal", callback_data=f"cf{CALLBACK_SEP}{menu_id}")]]
                ),
            )
            return

        if action.mode == "modal" and action.modal and len(action.modal.fields) > 0:
            context.user_data[KEY_PENDING_FORM] = {
                "menu_id": menu_id,
                "action_id": action_id,
                "index": 0,
                "params": {},
            }
            await _prompt_next_form_field(
                runtime=runtime,
                context=context,
                chat_id=chat_id,
                pending=context.user_data[KEY_PENDING_FORM],
                query=query,
            )
            return

        params: dict[str, str] = {}
        if action.confirm:
            context.user_data[KEY_PENDING_CONFIRM] = {
                "menu_id": menu_id,
                "action_id": action_id,
                "params": params,
            }
            await _send_or_edit(
                query=query,
                chat_id=chat_id,
                context=context,
                text=confirm_text(menu, action, params),
                reply_markup=_confirm_keyboard(menu_id),
            )
            return

        wait = _cooldown_remaining(
            context,
            user_id=user_id,
            key=KEY_LAST_ACTION_TS,
            min_interval_sec=runtime.config.action_cooldown_seconds,
        )
        if wait > 0:
            await query.answer(_throttle_message(wait), show_alert=True)
            return

        await _send_or_edit(
            query=query,
            chat_id=chat_id,
            context=context,
            text="<b>⏳ Menjalankan action...</b>",
            reply_markup=_result_keyboard(menu_id),
        )
        await _run_action(
            runtime=runtime,
            context=context,
            chat_id=chat_id,
            menu_id=menu_id,
            action_id=action_id,
            params=params,
            query=query,
        )
        return

    await query.answer("Interaksi tidak dikenali. Jalankan /panel lagi.", show_alert=True)


async def post_init(application: Application) -> None:
    runtime = application.bot_data.get("runtime")
    if isinstance(runtime, Runtime):
        try:
            health = await runtime.backend.health()
            LOGGER.info("Backend health: %s", health)
        except Exception as exc:
            LOGGER.warning("Backend health check saat startup gagal: %s", exc)

    try:
        await application.bot.set_my_commands(
            [
                BotCommand("panel", "Open panel VPS"),
                BotCommand("cleanup", "Hapus pesan menumpuk"),
            ]
        )
    except Exception as exc:
        LOGGER.warning("Gagal set bot commands: %s", exc)


def main() -> None:
    logging.basicConfig(
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        level=logging.INFO,
    )

    config = load_config()
    catalog = CommandCatalog.load(config.commands_file)
    backend = BackendClient(config.backend_base_url, config.shared_secret)

    runtime = Runtime(
        config=config,
        catalog=catalog,
        backend=backend,
        hostname=socket.gethostname(),
    )

    application = Application.builder().token(config.token).post_init(post_init).build()
    application.bot_data["runtime"] = runtime

    application.add_handler(CommandHandler("start", cmd_start))
    application.add_handler(CommandHandler("panel", cmd_panel))
    application.add_handler(CommandHandler("cleanup", cmd_cleanup))

    application.add_handler(CallbackQueryHandler(on_callback))
    application.add_handler(MessageHandler(filters.Document.ALL, on_document_input))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text_input))

    LOGGER.info("Starting xray-telegram-gateway")
    application.run_polling(allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    main()
