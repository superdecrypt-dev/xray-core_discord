from __future__ import annotations

import hashlib
import io
import json
import os
import re
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from ..utils.locks import file_lock
from .system import run_cmd

BACKUP_LOCK_FILE = "/var/lock/xray-backup-restore.lock"
BACKUP_SCHEMA_VERSION = 1
BACKUP_RETENTION_KEEP = 10
MAX_UPLOAD_ARCHIVE_BYTES = 20 * 1024 * 1024
SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")

BOT_STATE_DIR = Path(os.getenv("BOT_STATE_DIR", "/var/lib/xray-telegram-bot"))
BACKUP_ROOT_DIR = BOT_STATE_DIR / "backups"
BACKUP_ARCHIVES_DIR = BACKUP_ROOT_DIR / "archives"
BACKUP_SAFETY_DIR = BACKUP_ROOT_DIR / "safety"
UPLOAD_DIR_PRIMARY = BOT_STATE_DIR / "tmp" / "uploads"
UPLOAD_DIR_ALT = Path("/opt/bot-telegram/runtime/tmp/uploads")
UPLOAD_DIR_LOCALDEV = Path("/app/autoscript/bot-telegram/runtime/tmp/uploads")

BACKUP_SOURCE_PATHS = (
    Path("/usr/local/etc/xray/conf.d"),
    Path("/etc/nginx/conf.d/xray.conf"),
    Path("/opt/account"),
    Path("/opt/quota"),
    Path("/opt/speed"),
    Path("/etc/xray-speed/config.json"),
    Path("/var/lib/xray-speed/state.json"),
    Path("/var/lib/xray-manage/network_state.json"),
    Path("/etc/wireproxy/config.conf"),
    Path("/etc/xray/domain"),
    Path("/opt/cert/fullchain.pem"),
    Path("/opt/cert/privkey.pem"),
)

RESTORE_ALLOWED_DIRS = (
    Path("/usr/local/etc/xray/conf.d"),
    Path("/opt/account"),
    Path("/opt/quota"),
    Path("/opt/speed"),
)
RESTORE_ALLOWED_FILES = (
    Path("/etc/nginx/conf.d/xray.conf"),
    Path("/etc/xray-speed/config.json"),
    Path("/var/lib/xray-speed/state.json"),
    Path("/var/lib/xray-manage/network_state.json"),
    Path("/etc/wireproxy/config.conf"),
    Path("/etc/xray/domain"),
    Path("/opt/cert/fullchain.pem"),
    Path("/opt/cert/privkey.pem"),
)

VALIDATION_COMMANDS = (
    ["xray", "run", "-test", "-confdir", "/usr/local/etc/xray/conf.d"],
    ["nginx", "-t"],
)
REQUIRED_RESTART_SERVICES = (
    "xray",
    "nginx",
    "xray-speed",
    "xray-expired",
    "xray-quota",
    "xray-limit-ip",
)
OPTIONAL_RESTART_SERVICES = ("wireproxy",)


def _now_utc_text() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_size(num: int) -> str:
    n = max(0, int(num))
    if n >= 1024**3:
        return f"{n / (1024**3):.2f} GiB"
    if n >= 1024**2:
        return f"{n / (1024**2):.2f} MiB"
    if n >= 1024:
        return f"{n / 1024:.2f} KiB"
    return f"{n} B"


def _ensure_backup_dirs() -> None:
    for p in (BACKUP_ARCHIVES_DIR, BACKUP_SAFETY_DIR, UPLOAD_DIR_PRIMARY):
        p.mkdir(parents=True, exist_ok=True)
        try:
            p.chmod(0o700)
        except Exception:
            pass


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iter_backup_files() -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    for base in BACKUP_SOURCE_PATHS:
        if base.is_file():
            key = str(base)
            if key not in seen:
                seen.add(key)
                out.append(base)
            continue
        if not base.is_dir():
            continue
        for fp in sorted(base.rglob("*")):
            if not fp.is_file():
                continue
            key = str(fp)
            if key in seen:
                continue
            seen.add(key)
            out.append(fp)
    return out


def _to_rel_path(path: Path) -> str:
    return str(path).lstrip("/")


def _enforce_retention(directory: Path, keep: int = BACKUP_RETENTION_KEEP) -> None:
    files = [p for p in directory.glob("*.tar.gz") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except Exception:
            pass


def _create_backup_archive(kind: str) -> tuple[bool, str, dict[str, Any] | None]:
    _ensure_backup_dirs()
    dst_dir = BACKUP_SAFETY_DIR if kind == "safety" else BACKUP_ARCHIVES_DIR
    files = _iter_backup_files()
    if not files:
        return False, "Tidak ada file yang bisa dibackup.", None

    backup_id = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    filename = f"{kind}-backup-{backup_id}.tar.gz"
    archive_path = dst_dir / filename

    manifest_entries: list[dict[str, Any]] = []
    for fp in files:
        rel = _to_rel_path(fp)
        try:
            size = int(fp.stat().st_size)
            sha = _sha256_file(fp)
        except Exception as exc:
            return False, f"Gagal membaca file backup {fp}: {exc}", None
        manifest_entries.append(
            {
                "path": rel,
                "size_bytes": size,
                "sha256": sha,
            }
        )

    manifest = {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "backup_id": backup_id,
        "kind": kind,
        "created_at_utc": _now_utc_text(),
        "include_cert": True,
        "entries": manifest_entries,
    }
    manifest_raw = json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8")

    try:
        with tarfile.open(archive_path, "w:gz") as tf:
            for fp in files:
                rel = _to_rel_path(fp)
                tf.add(fp, arcname=f"payload/{rel}", recursive=False)
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest_raw)
            info.mtime = int(datetime.now(timezone.utc).timestamp())
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(manifest_raw))
    except Exception as exc:
        return False, f"Gagal membuat arsip backup: {exc}", None

    _enforce_retention(dst_dir)
    size_bytes = int(archive_path.stat().st_size) if archive_path.exists() else 0
    data = {
        "backup_id": backup_id,
        "kind": kind,
        "archive_path": str(archive_path),
        "archive_filename": archive_path.name,
        "size_bytes": size_bytes,
    }
    return True, "ok", data


def _is_subpath(path: Path, base: Path) -> bool:
    try:
        rp = path.resolve()
        rb = base.resolve()
    except Exception:
        return False
    return rp == rb or rb in rp.parents


def _is_allowed_restore_target(path: Path) -> bool:
    target = path.resolve()
    for base in RESTORE_ALLOWED_DIRS:
        if _is_subpath(target, base):
            return True
    for file_path in RESTORE_ALLOWED_FILES:
        if target == file_path.resolve():
            return True
    return False


def _normalize_member_name(raw: str) -> tuple[bool, str]:
    name = str(raw or "").strip()
    if not name:
        return False, "Nama member archive kosong."
    p = PurePosixPath(name)
    if p.is_absolute():
        return False, f"Member archive path absolut tidak diizinkan: {name}"
    if ".." in p.parts:
        return False, f"Member archive path traversal terdeteksi: {name}"
    return True, str(p)


def _validate_archive_file(archive_path: Path) -> tuple[bool, str]:
    if not archive_path.exists() or not archive_path.is_file():
        return False, f"File archive tidak ditemukan: {archive_path}"
    if not str(archive_path.name).lower().endswith(".tar.gz"):
        return False, "File restore harus berekstensi .tar.gz"
    return True, "ok"


def _validate_upload_archive_path(upload_path: str) -> tuple[bool, str, Path | None]:
    raw = str(upload_path or "").strip()
    if not raw:
        return False, "upload_path wajib diisi.", None
    p = Path(raw)
    try:
        rp = p.resolve()
    except Exception as exc:
        return False, f"Path upload tidak valid: {exc}", None

    allowed_roots = (UPLOAD_DIR_PRIMARY, UPLOAD_DIR_ALT, UPLOAD_DIR_LOCALDEV)
    if not any(_is_subpath(rp, root) for root in allowed_roots):
        return False, "Path upload berada di lokasi yang tidak diizinkan.", None

    ok, msg = _validate_archive_file(rp)
    if not ok:
        return False, msg, None

    size_bytes = int(rp.stat().st_size)
    if size_bytes > MAX_UPLOAD_ARCHIVE_BYTES:
        return (
            False,
            (
                f"Ukuran file upload terlalu besar ({_fmt_size(size_bytes)}). "
                f"Maksimal {_fmt_size(MAX_UPLOAD_ARCHIVE_BYTES)}."
            ),
            None,
        )
    return True, "ok", rp


def _load_and_validate_manifest(
    archive_path: Path,
) -> tuple[bool, str, dict[str, Any] | None, list[dict[str, Any]] | None]:
    ok_file, msg_file = _validate_archive_file(archive_path)
    if not ok_file:
        return False, msg_file, None, None

    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            payload_members: dict[str, tarfile.TarInfo] = {}
            manifest_member: tarfile.TarInfo | None = None

            for member in tf.getmembers():
                ok_name, name_or_err = _normalize_member_name(member.name)
                if not ok_name:
                    return False, str(name_or_err), None, None
                norm_name = str(name_or_err)
                if norm_name == "manifest.json":
                    manifest_member = member
                    continue
                if member.isfile() and norm_name.startswith("payload/"):
                    rel = norm_name[len("payload/") :].lstrip("/")
                    payload_members[rel] = member

            if manifest_member is None or not manifest_member.isfile():
                return False, "manifest.json tidak ditemukan di archive.", None, None

            raw_manifest = tf.extractfile(manifest_member)
            if raw_manifest is None:
                return False, "manifest.json tidak bisa dibaca.", None, None
            manifest = json.loads(raw_manifest.read().decode("utf-8", errors="ignore"))
            if not isinstance(manifest, dict):
                return False, "manifest.json tidak valid.", None, None
            if int(manifest.get("schema_version") or 0) != BACKUP_SCHEMA_VERSION:
                return False, "Versi manifest tidak didukung.", None, None

            entries_raw = manifest.get("entries")
            if not isinstance(entries_raw, list) or not entries_raw:
                return False, "Manifest entries kosong/tidak valid.", None, None

            entries: list[dict[str, Any]] = []
            for item in entries_raw:
                if not isinstance(item, dict):
                    return False, "Manifest entry tidak valid.", None, None
                rel = str(item.get("path") or "").strip().lstrip("/")
                sha = str(item.get("sha256") or "").strip().lower()
                try:
                    size = int(item.get("size_bytes"))
                except Exception:
                    return False, f"size_bytes tidak valid untuk {rel}", None, None

                if not rel:
                    return False, "Entry path kosong pada manifest.", None, None
                ok_rel, rel_norm_or_err = _normalize_member_name(rel)
                if not ok_rel:
                    return False, str(rel_norm_or_err), None, None
                rel_norm = str(rel_norm_or_err)
                if rel_norm not in payload_members:
                    return False, f"Payload file tidak ditemukan: {rel_norm}", None, None
                if not SHA256_HEX_RE.match(sha):
                    return False, f"Checksum sha256 tidak valid untuk {rel_norm}", None, None
                if size < 0:
                    return False, f"Ukuran file tidak valid untuk {rel_norm}", None, None

                target = Path("/") / rel_norm
                if not _is_allowed_restore_target(target):
                    return False, f"Path restore tidak diizinkan: /{rel_norm}", None, None

                member = payload_members[rel_norm]
                if int(member.size) != size:
                    return False, f"Ukuran file mismatch untuk {rel_norm}", None, None

                fp = tf.extractfile(member)
                if fp is None:
                    return False, f"Gagal membaca payload: {rel_norm}", None, None
                digest = _sha256_bytes(fp.read())
                if digest != sha:
                    return False, f"Checksum mismatch untuk {rel_norm}", None, None

                entries.append({"path": rel_norm, "sha256": sha, "size_bytes": size})

            return True, "ok", manifest, entries
    except Exception as exc:
        return False, f"Gagal membaca archive: {exc}", None, None


def _write_bytes_atomic(path: Path, payload: bytes) -> tuple[bool, str]:
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return False, f"Gagal menyiapkan direktori {parent}: {exc}"

    uid = 0
    gid = 0
    mode = 0o600
    if path.exists():
        try:
            st = path.stat()
            uid = int(st.st_uid)
            gid = int(st.st_gid)
            mode = int(st.st_mode & 0o777)
        except Exception:
            pass

    fd = -1
    tmp_path = ""
    try:
        fd, tmp_path = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(parent))
        with os.fdopen(fd, "wb") as fp:
            fd = -1
            fp.write(payload)
            fp.flush()
            os.fsync(fp.fileno())
        try:
            os.chmod(tmp_path, mode)
        except Exception:
            pass
        try:
            os.chown(tmp_path, uid, gid)
        except Exception:
            pass
        os.replace(tmp_path, str(path))
    except Exception as exc:
        if fd >= 0:
            try:
                os.close(fd)
            except Exception:
                pass
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
        return False, f"Gagal menulis file {path}: {exc}"
    return True, "ok"


def _apply_archive(archive_path: Path, entries: list[dict[str, Any]]) -> tuple[bool, str]:
    try:
        with tarfile.open(archive_path, "r:gz") as tf:
            for item in entries:
                rel = str(item["path"])
                member = tf.getmember(f"payload/{rel}")
                fp = tf.extractfile(member)
                if fp is None:
                    return False, f"Gagal membaca payload: {rel}"
                payload = fp.read()
                dst = Path("/") / rel
                ok_write, msg_write = _write_bytes_atomic(dst, payload)
                if not ok_write:
                    return False, msg_write
    except Exception as exc:
        return False, f"Gagal apply archive: {exc}"
    return True, "ok"


def _run_post_restore_validation() -> tuple[bool, str]:
    for cmd in VALIDATION_COMMANDS:
        ok, out = run_cmd(cmd, timeout=60)
        if not ok:
            return False, f"Validasi gagal: {' '.join(cmd)}\n{out}"

    for svc in REQUIRED_RESTART_SERVICES:
        ok_restart, out_restart = run_cmd(["systemctl", "restart", svc], timeout=40)
        if not ok_restart:
            return False, f"Gagal restart service {svc}:\n{out_restart}"
        ok_active, out_active = run_cmd(["systemctl", "is-active", svc], timeout=10)
        state = out_active.splitlines()[-1].strip() if out_active else "-"
        if (not ok_active) or state != "active":
            return False, f"Service {svc} tidak aktif setelah restart (state={state})."

    for svc in OPTIONAL_RESTART_SERVICES:
        run_cmd(["systemctl", "restart", svc], timeout=30)

    return True, "ok"


def _restore_archive_with_safety(
    archive_path: Path,
    source_label: str,
) -> tuple[bool, str]:
    ok_manifest, msg_manifest, _, entries = _load_and_validate_manifest(archive_path)
    if not ok_manifest or entries is None:
        return False, msg_manifest

    ok_safety, msg_safety, safety_data = _create_backup_archive("safety")
    if not ok_safety or safety_data is None:
        return False, f"Gagal membuat snapshot pra-restore: {msg_safety}"
    safety_path = Path(str(safety_data.get("archive_path") or "")).resolve()

    ok_apply, msg_apply = _apply_archive(archive_path, entries)
    if ok_apply:
        ok_validate, msg_validate = _run_post_restore_validation()
        if ok_validate:
            return (
                True,
                (
                    f"Restore berhasil dari {source_label}.\n"
                    f"- File dipulihkan: {len(entries)}\n"
                    f"- Snapshot safety: {safety_path.name}"
                ),
            )
        msg_apply = msg_validate

    rb_ok, rb_msg, _, rb_entries = _load_and_validate_manifest(safety_path)
    if not rb_ok or rb_entries is None:
        return False, f"Restore gagal: {msg_apply}\nRollback gagal: {rb_msg}"

    rb_apply_ok, rb_apply_msg = _apply_archive(safety_path, rb_entries)
    if not rb_apply_ok:
        return False, f"Restore gagal: {msg_apply}\nRollback gagal apply: {rb_apply_msg}"

    rb_validate_ok, rb_validate_msg = _run_post_restore_validation()
    if not rb_validate_ok:
        return False, f"Restore gagal: {msg_apply}\nRollback gagal validasi: {rb_validate_msg}"

    return (
        False,
        (
            f"Restore gagal: {msg_apply}\n"
            f"Rollback otomatis berhasil menggunakan snapshot {safety_path.name}."
        ),
    )


def op_backup_create() -> tuple[bool, str, str, dict[str, Any] | None]:
    title = "Backup/Restore - Create Backup"
    with file_lock(BACKUP_LOCK_FILE):
        ok, msg, data = _create_backup_archive("manual")
    if not ok or data is None:
        return False, title, msg, None

    size_bytes = int(data.get("size_bytes") or 0)
    filename = str(data.get("archive_filename") or "-")
    archive_path = str(data.get("archive_path") or "")
    result_data = {
        "backup_id": str(data.get("backup_id") or ""),
        "download_local_path": archive_path,
        "download_filename": filename,
        "size_bytes": size_bytes,
        "kind": "manual",
    }
    msg_text = (
        "Backup berhasil dibuat.\n"
        f"- File: {filename}\n"
        f"- Size: {_fmt_size(size_bytes)}\n"
        "- Scope: full + cert (tanpa env bot)"
    )
    return True, title, msg_text, result_data


def op_backup_list() -> tuple[bool, str, str]:
    title = "Backup/Restore - List Backups"
    _ensure_backup_dirs()
    files = [p for p in BACKUP_ARCHIVES_DIR.glob("*.tar.gz") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return True, title, "Belum ada backup lokal."

    lines = [
        f"Total backup lokal: {len(files)}",
        f"Retensi aktif: {BACKUP_RETENTION_KEEP} terbaru",
        "",
        f"{'NO':<4} {'FILE':<44} {'SIZE':<12} {'UPDATED (UTC)':<20}",
        f"{'-'*4:<4} {'-'*44:<44} {'-'*12:<12} {'-'*20:<20}",
    ]
    for idx, fp in enumerate(files[:50], start=1):
        size = _fmt_size(int(fp.stat().st_size))
        updated = datetime.fromtimestamp(fp.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        lines.append(f"{idx:<4} {fp.name[:44]:<44} {size:<12} {updated:<20}")
    return True, title, "\n".join(lines)


def op_restore_latest_local() -> tuple[bool, str, str]:
    title = "Backup/Restore - Restore Latest Local"
    _ensure_backup_dirs()
    files = [p for p in BACKUP_ARCHIVES_DIR.glob("*.tar.gz") if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return False, title, "Belum ada backup lokal untuk direstore."
    latest = files[0]

    with file_lock(BACKUP_LOCK_FILE):
        ok_restore, msg_restore = _restore_archive_with_safety(latest, source_label=f"local:{latest.name}")
    if ok_restore:
        return True, title, msg_restore
    return False, title, msg_restore


def op_restore_from_upload(upload_path: str) -> tuple[bool, str, str]:
    title = "Backup/Restore - Restore From Upload"
    ok_upload, msg_upload, archive_path = _validate_upload_archive_path(upload_path)
    if not ok_upload or archive_path is None:
        return False, title, msg_upload

    try:
        with file_lock(BACKUP_LOCK_FILE):
            ok_restore, msg_restore = _restore_archive_with_safety(
                archive_path,
                source_label=f"upload:{archive_path.name}",
            )
    finally:
        try:
            archive_path.unlink(missing_ok=True)
        except Exception:
            pass

    if ok_restore:
        return True, title, msg_restore
    return False, title, msg_restore
