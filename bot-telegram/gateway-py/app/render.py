from __future__ import annotations

import base64
import html
from datetime import datetime, timezone

from .backend_client import BackendActionResponse
from .commands_loader import ActionSpec, FieldSpec, MenuSpec


def now_utc_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _trim(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    if max_len < 4:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def as_pre(text: str, max_len: int = 3300) -> str:
    return f"<pre>{html.escape(_trim(text, max_len))}</pre>"


def main_menu_text(hostname: str, menu_count: int) -> str:
    lines = [
        "<b>XRAY TELEGRAM CONTROL</b>",
        "Panel standalone untuk kontrol VPS.",
        "",
        f"• Host: <code>{html.escape(hostname)}</code>",
        f"• Menu aktif: <code>{menu_count}</code>",
        f"• Updated: <code>{now_utc_text()}</code>",
        "",
        "Pilih menu di bawah:",
    ]
    return "\n".join(lines)


def menu_text(menu: MenuSpec, page: int, total_pages: int) -> str:
    lines = [
        f"<b>{html.escape(menu.label)}</b>",
    ]
    if menu.description:
        lines.append(html.escape(menu.description))
    lines.append("")
    lines.append(f"Halaman aksi <code>{page + 1}/{max(total_pages, 1)}</code>")
    lines.append("Pilih action:")
    return "\n".join(lines)


def action_form_prompt(menu: MenuSpec, action: ActionSpec, field: FieldSpec, idx: int, total: int) -> str:
    lines = [
        f"<b>{html.escape(menu.label)} · {html.escape(action.label)}</b>",
        f"Input <code>{idx}/{total}</code>",
        "",
        f"Field: <code>{html.escape(field.id)}</code>",
        f"Label: {html.escape(field.label)}",
    ]
    if field.placeholder:
        lines.append(f"Contoh: <code>{html.escape(field.placeholder)}</code>")
    if field.required:
        lines.append("Wajib diisi.")
    else:
        lines.append("Opsional. Isi '-' untuk skip.")
    lines.append("")
    lines.append("Kirim nilainya sekarang.")
    return "\n".join(lines)


def confirm_text(menu: MenuSpec, action: ActionSpec, params: dict[str, str]) -> str:
    lines = [
        f"<b>Konfirmasi: {html.escape(menu.label)} · {html.escape(action.label)}</b>",
        "",
    ]
    if not params:
        lines.append("Tanpa parameter.")
    else:
        lines.append(as_pre("\n".join([f"{k}={v}" for k, v in params.items()]), max_len=1200))
    lines.append("")
    lines.append("Lanjutkan eksekusi?")
    return "\n".join(lines)


def action_result_text(result: BackendActionResponse) -> str:
    icon = "✅" if result.ok else "❌"
    title = html.escape(result.title or "Result")
    message = result.message or "(no output)"

    lines = [
        f"<b>{icon} {title}</b>",
        f"Code: <code>{html.escape(result.code)}</code>",
        "",
        as_pre(message, max_len=3300),
    ]
    return "\n".join(lines)


def decode_download_payload(data: dict) -> tuple[str, bytes] | None:
    raw = data.get("download_file")
    if not isinstance(raw, dict):
        return None

    filename = str(raw.get("filename") or "download.txt")
    content_base64 = str(raw.get("content_base64") or "")
    if not content_base64:
        return None

    try:
        payload = base64.b64decode(content_base64, validate=True)
    except Exception:
        return None

    return filename, payload
