"""Безпечне оновлення: пакет приймається лише якщо його маніфест підписано ВСТАНОВЛЕНИМ ключем випуску.

Довірений ключ — release_public.key уже встановленої програми, а не ключ із пакета.
Перевіряються: підпис, хеші всіх файлів, склад пакета, імена (zip-slip), розміри, версія (лише вперед).
Опис: model_rozpovsiudzhennia.md
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from integrity import MANIFEST, PROTECTED, PUBLIC_KEY, SIGNATURE, read_version, verify_release
from version import PRODUCT, version_tuple

MAX_MEMBER_BYTES = 5 * 1024 * 1024
MAX_MEMBERS = 32


class UpdateError(Exception):
    """Пакет оновлення відхилено; встановлена програма не змінена."""


def _safe_name(name):
    return bool(name) and Path(name).name == name and "\\" not in name and not name.startswith(".")


def verify_update(zip_path, app_dir):
    """Повертає (маніфест, {ім'я: байти}); будь-яка невідповідність — UpdateError."""
    d = Path(app_dir)
    try:
        key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode((d / PUBLIC_KEY).read_text(encoding="ascii").strip(), validate=True))
        installed = version_tuple(read_version(d))
    except Exception:
        raise UpdateError("Немає довіреного ключа випуску або встановлену версію не визначено.")
    try:
        with zipfile.ZipFile(zip_path) as z:
            infos = z.infolist()
            names = [i.filename for i in infos]
            if len(infos) > MAX_MEMBERS or len(set(names)) != len(names):
                raise UpdateError("Пакет має недопустиму структуру.")
            for i in infos:
                if i.is_dir() or not _safe_name(i.filename) or i.file_size > MAX_MEMBER_BYTES:
                    raise UpdateError(f"Недопустимий елемент пакета: {i.filename!r}.")
            if MANIFEST not in names or SIGNATURE not in names:
                raise UpdateError("У пакеті немає маніфесту або підпису.")
            manifest_bytes = z.read(MANIFEST)
            try:
                key.verify(base64.b64decode(z.read(SIGNATURE).decode("ascii").strip(), validate=True), manifest_bytes)
            except InvalidSignature:
                raise UpdateError("Підпис пакета недійсний: пакет не від видавця або змінений.")
            manifest = json.loads(manifest_bytes)
            files = manifest["files"]
            if manifest.get("product") != PRODUCT or not isinstance(files, dict):
                raise UpdateError("Пакет призначений для іншого продукту.")
            if PUBLIC_KEY in names or set(names) != set(files) | {MANIFEST, SIGNATURE} or not set(PROTECTED) <= set(files):
                raise UpdateError("Склад пакета не збігається з маніфестом.")
            if version_tuple(manifest["app_version"]) <= installed:
                raise UpdateError("Версія пакета не новіша за встановлену (відкат заборонено).")
            blobs = {}
            for name, expected in files.items():
                data = z.read(name)
                if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), str(expected)):
                    raise UpdateError(f"Файл {name} у пакеті не відповідає маніфесту.")
                blobs[name] = data
            blobs[MANIFEST], blobs[SIGNATURE] = manifest_bytes, z.read(SIGNATURE)
            return manifest, blobs
    except UpdateError:
        raise
    except (zipfile.BadZipFile, OSError, ValueError, KeyError, TypeError, UnicodeDecodeError, RuntimeError):
        raise UpdateError("Пакет пошкоджено.")


def apply_update(zip_path, app_dir):
    """Перевіряє й встановлює пакет; при збої повертає попередній стан. Повертає нову версію."""
    d = Path(app_dir)
    manifest, blobs = verify_update(zip_path, d)
    backup = d / ".update_backup"
    shutil.rmtree(backup, ignore_errors=True)
    backup.mkdir()
    for name in blobs:
        if (d / name).exists():
            shutil.copy2(d / name, backup / name)
    written = []
    try:
        for name, data in blobs.items():
            tmp = d / (name + ".new")
            tmp.write_bytes(data)
            os.replace(tmp, d / name)
            written.append(name)
        verify_release(d)                       # підсумкова перевірка встановленого набору
    except Exception:
        for name in written:
            if (backup / name).exists():
                shutil.copy2(backup / name, d / name)
            else:
                (d / name).unlink(missing_ok=True)
        for name in blobs:
            (d / (name + ".new")).unlink(missing_ok=True)
        raise UpdateError("Оновлення скасовано, попередню версію відновлено.")
    return manifest["app_version"]
