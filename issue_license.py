"""Інструмент ВИДАВЦЯ: ключі ліцензій та видача ліцензій (не входить до складу програми).

  python issue_license.py init  [--key ШЛЯХ]
      створити пару ключів ліцензій (один раз); окрема від ключа підпису випуску
  python issue_license.py issue --device КОД --licensee ІМ'Я --serial НОМЕР [--major 1] [--out license.lic]
      видати ліцензію Pro для пристрою (код користувач бере в програмі: «Ліцензія…» або --device-id)

Приватний ключ (за замовчуванням ~/.planuvalnyk/license_private.pem, 0600) зберігається лише у видавця.
"""
import argparse
import base64
import getpass
import json
import re
import sys
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives import serialization

import sign_release
from licensing import LICENSE_PUBLIC, canonical
from version import PRODUCT, major

APP_DIR = Path(__file__).resolve().parent
DEFAULT_KEY = Path.home() / ".planuvalnyk" / "license_private.pem"
DEVICE_RE = re.compile(r"^[0-9a-f]{4}(-[0-9a-f]{4}){5}$")


def init_keys(app_dir, key_path, password=b"", force=False):
    return sign_release.init_keys(app_dir, key_path, password, force, public_name=LICENSE_PUBLIC)


def issue(key_path, device, licensee, serial, lic_major=None, out=None, password=None):
    device = device.strip().lower()
    if not DEVICE_RE.match(device):
        raise SystemExit("Код пристрою має вигляд xxxx-xxxx-xxxx-xxxx-xxxx-xxxx.")
    pem = Path(key_path).read_bytes()
    try:
        private = serialization.load_pem_private_key(pem, password=password or None)
    except TypeError:
        private = serialization.load_pem_private_key(pem, password=getpass.getpass("Пароль до ключа: ").encode())
    payload = {"product": PRODUCT, "edition": "pro", "serial": serial, "licensee": licensee, "device": device,
               "major": lic_major if lic_major is not None else major(), "issued": date.today().isoformat()}
    doc = {"payload": payload, "sig": base64.b64encode(private.sign(canonical(payload))).decode("ascii")}
    out = Path(out or "license.lic")
    out.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["init", "issue"])
    ap.add_argument("--key", default=str(DEFAULT_KEY))
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--device")
    ap.add_argument("--licensee")
    ap.add_argument("--serial")
    ap.add_argument("--major", type=int)
    ap.add_argument("--out", default="license.lic")
    a = ap.parse_args()
    if a.command == "init":
        pw = getpass.getpass("Пароль до приватного ключа (порожній — без пароля): ").encode()
        print(f"Ключі ліцензій створено. Приватний: {a.key}\nВідбиток license_public.key: "
              f"{init_keys(APP_DIR, a.key, pw, a.force)}\nПісля цього перепідпишіть випуск: python sign_release.py sign")
    else:
        if not (a.device and a.licensee and a.serial):
            ap.error("потрібні --device, --licensee, --serial")
        print(f"Ліцензію збережено: {issue(a.key, a.device, a.licensee, a.serial, a.major, a.out)}")


if __name__ == "__main__":
    sys.exit(main())
