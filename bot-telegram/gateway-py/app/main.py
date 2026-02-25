from __future__ import annotations

import io
import logging
import socket
from dataclasses import dataclass
import html

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ParseMode
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from .backend_client import BackendClient, BackendError
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
KEY_PENDING_FORM = "pending_form"
KEY_PENDING_CONFIRM = "pending_confirm"


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
    user_id = str(update.effective_user.id) if update.effective_user else ""
    chat_id = str(update.effective_chat.id) if update.effective_chat else ""

    if runtime.config.admin_user_ids and user_id not in runtime.config.admin_user_ids:
        return False, "Akses ditolak: user Telegram belum terdaftar sebagai admin."

    if runtime.config.admin_chat_ids and chat_id not in runtime.config.admin_chat_ids:
        return False, "Akses ditolak: chat ini belum diizinkan untuk panel."

    return True, ""


def _clear_pending(context: ContextTypes.DEFAULT_TYPE) -> None:
    context.user_data.pop(KEY_PENDING_FORM, None)
    context.user_data.pop(KEY_PENDING_CONFIRM, None)


def _main_menu_keyboard(runtime: Runtime) -> InlineKeyboardMarkup:
    rows: list[list[InlineKeyboardButton]] = []
    for menu in runtime.catalog.menus:
        label = f"{menu.id}) {menu.label}"
        rows.append([InlineKeyboardButton(label[:56], callback_data=f"m{CALLBACK_SEP}{menu.id}")])
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

    rows: list[list[InlineKeyboardButton]] = []
    for action in chunk:
        rows.append(
            [
                InlineKeyboardButton(
                    action.label[:56],
                    callback_data=f"a{CALLBACK_SEP}{menu.id}{CALLBACK_SEP}{action.id}",
                )
            ]
        )

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


async def _send_or_edit(
    *,
    query,
    chat_id: int,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    reply_markup: InlineKeyboardMarkup,
) -> None:
    if query is not None:
        try:
            await query.edit_message_text(text=text, reply_markup=reply_markup, parse_mode=ParseMode.HTML)
            return
        except Exception:
            pass

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


async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    _clear_pending(context)
    await update.effective_message.reply_text("Input aktif dibatalkan.")


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
) -> None:
    menu = runtime.catalog.get_menu(str(pending.get("menu_id", "")))
    action = runtime.catalog.get_action(str(pending.get("menu_id", "")), str(pending.get("action_id", "")))
    if menu is None or action is None or action.modal is None:
        raise RuntimeError("State form tidak valid.")

    idx = int(pending.get("index", 0))
    if idx < 0 or idx >= len(action.modal.fields):
        raise RuntimeError("Index form tidak valid.")

    field = action.modal.fields[idx]
    await context.bot.send_message(
        chat_id=chat_id,
        text=action_form_prompt(menu, action, field, idx + 1, len(action.modal.fields)),
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("❌ Batal", callback_data=f"cf{CALLBACK_SEP}{menu.id}")]]
        ),
    )


async def on_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    runtime = _get_runtime(context)
    ok, reason = _is_authorized(runtime, update)
    if not ok:
        await update.effective_message.reply_text(reason)
        return

    pending = context.user_data.get(KEY_PENDING_FORM)
    if not isinstance(pending, dict):
        return

    menu_id = str(pending.get("menu_id", ""))
    action_id = str(pending.get("action_id", ""))
    menu = runtime.catalog.get_menu(menu_id)
    action = runtime.catalog.get_action(menu_id, action_id)
    if menu is None or action is None or action.modal is None:
        _clear_pending(context)
        await update.effective_message.reply_text("Sesi input rusak. Jalankan /panel lagi.")
        return

    idx = int(pending.get("index", 0))
    if idx < 0 or idx >= len(action.modal.fields):
        _clear_pending(context)
        await update.effective_message.reply_text("Sesi input sudah selesai. Jalankan /panel lagi.")
        return

    field = action.modal.fields[idx]
    raw = (update.effective_message.text or "").strip()
    value = raw
    if raw.lower() in {"-", "skip", "lewati"}:
        value = ""

    if field.required and not value:
        await update.effective_message.reply_text("Field ini wajib diisi. Coba lagi.")
        await _prompt_next_form_field(runtime=runtime, context=context, chat_id=update.effective_chat.id, pending=pending)
        return

    params = pending.get("params") if isinstance(pending.get("params"), dict) else {}
    if value:
        params[field.id] = value

    pending["params"] = params
    pending["index"] = idx + 1
    context.user_data[KEY_PENDING_FORM] = pending

    if pending["index"] < len(action.modal.fields):
        await _prompt_next_form_field(runtime=runtime, context=context, chat_id=update.effective_chat.id, pending=pending)
        return

    context.user_data.pop(KEY_PENDING_FORM, None)

    if action.confirm:
        context.user_data[KEY_PENDING_CONFIRM] = {
            "menu_id": menu_id,
            "action_id": action_id,
            "params": params,
        }
        await update.effective_message.reply_text(
            confirm_text(menu, action, params),
            parse_mode=ParseMode.HTML,
            reply_markup=_confirm_keyboard(menu_id),
        )
        return

    await update.effective_message.reply_text("⏳ Menjalankan action...")
    await _run_action(
        runtime=runtime,
        context=context,
        chat_id=update.effective_chat.id,
        menu_id=menu_id,
        action_id=action_id,
        params=params,
        query=None,
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
    await query.answer()
    chat_id = _callback_chat_id(update)

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

    if data == "rc":
        pending = context.user_data.get(KEY_PENDING_CONFIRM)
        if not isinstance(pending, dict):
            await query.answer("Tidak ada aksi yang menunggu konfirmasi.", show_alert=True)
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

        if action.mode == "modal" and action.modal and len(action.modal.fields) > 0:
            context.user_data[KEY_PENDING_FORM] = {
                "menu_id": menu_id,
                "action_id": action_id,
                "index": 0,
                "params": {},
            }
            await _send_or_edit(
                query=query,
                chat_id=chat_id,
                context=context,
                text=(
                    f"<b>{html.escape(menu.label)} · {html.escape(action.label)}</b>\n"
                    "Mode input aktif. Ikuti prompt yang dikirim bot."
                ),
                reply_markup=InlineKeyboardMarkup(
                    [[InlineKeyboardButton("❌ Batal Input", callback_data=f"cf{CALLBACK_SEP}{menu_id}")]]
                ),
            )
            await _prompt_next_form_field(
                runtime=runtime,
                context=context,
                chat_id=chat_id,
                pending=context.user_data[KEY_PENDING_FORM],
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
                BotCommand("cancel", "Batalkan input aktif"),
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
    application.add_handler(CommandHandler("cancel", cmd_cancel))

    application.add_handler(CallbackQueryHandler(on_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text_input))

    LOGGER.info("Starting xray-telegram-gateway")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
