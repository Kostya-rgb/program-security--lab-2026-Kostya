"""Інструмент розробника: ключі випуску та підпис маніфесту (не входить до складу програми).

  python sign_release.py init  [--key ШЛЯХ]   створити пару ключів (один раз)
  python sign_release.py sign  [--key ШЛЯХ]   перерахувати хеші й підписати (після КОЖНОЇ зміни коду)
  python sign_release.py package [--key ШЛЯХ]  підписати й зібрати пакет оновлення planuvalnyk-<версія>.update.zip

Приватний ключ зберігається ПОЗА папкою проєкту (за замовчуванням ~/.planuvalnyk/release_private.pem, 0600)
і не передається разом з програмою. У проєкті лишається лише відкритий ключ release_public.key.
"""
import argparse
import base64
import getpass
import os
import sys
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from integrity import MANIFEST, PUBLIC_KEY, SIGNATURE, build_manifest, fingerprint

APP_DIR = Path(__file__).resolve().parent
DEFAULT_KEY = Path.home() / ".planuvalnyk" / "release_private.pem"


def init_keys(app_dir, key_path, password=b"", force=False, public_name=PUBLIC_KEY):
    key_path = Path(key_path)
    if key_path.exists() and not force:
        raise SystemExit(f"{key_path} уже існує (--force замінить його).")
    private = Ed25519PrivateKey.generate()
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    pem = private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (Path(app_dir) / public_name).write_text(base64.b64encode(public_raw).decode("ascii") + "\n", encoding="ascii")
    return fingerprint(public_raw)


def sign(app_dir, key_path, password=None):
    pem = Path(key_path).read_bytes()
    try:
        private = serialization.load_pem_private_key(pem, password=password or None)
    except TypeError:
        private = serialization.load_pem_private_key(pem, password=getpass.getpass("Пароль до ключа: ").encode())
    manifest = build_manifest(app_dir)
    (Path(app_dir) / MANIFEST).write_bytes(manifest)
    (Path(app_dir) / SIGNATURE).write_text(base64.b64encode(private.sign(manifest)).decode("ascii") + "\n",
                                            encoding="ascii")
    public_raw = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (Path(app_dir) / PUBLIC_KEY).write_text(base64.b64encode(public_raw).decode("ascii") + "\n", encoding="ascii")
    return fingerprint(public_raw)


def package(app_dir, key_path, out_dir=None, password=None):
    """Підписує поточний стан і пакує файли з маніфесту в архів оновлення. Ключ випуску в архів не входить."""
    import json
    fp = sign(app_dir, key_path, password)
    d = Path(app_dir)
    manifest = json.loads((d / MANIFEST).read_bytes())
    out = Path(out_dir or d) / f"planuvalnyk-{manifest['app_version']}.update.zip"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in [*manifest["files"], MANIFEST, SIGNATURE]:
            z.write(d / name, name)
    return out, fp


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["init", "sign", "package"])
    ap.add_argument("--key", default=str(DEFAULT_KEY))
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if a.command == "init":
        pw = getpass.getpass("Пароль до приватного ключа (порожній — без пароля): ").encode()
        fp = init_keys(APP_DIR, a.key, pw, a.force)
        print(f"Ключі створено. Приватний: {a.key}\nВідбиток відкритого ключа (запишіть у звіт): {fp}")
    elif a.command == "sign":
        fp = sign(APP_DIR, a.key)
        print(f"Маніфест підписано. Відбиток відкритого ключа: {fp}")
    else:
        out, fp = package(APP_DIR, a.key)
        print(f"Пакет оновлення: {out}\nВідбиток відкритого ключа: {fp}")


if __name__ == "__main__":
    sys.exit(main())
