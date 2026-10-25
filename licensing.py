"""Ліцензування «Планувальника справ»: Freemium + безстрокова ліцензія Pro (офлайн-активація).

Ліцензія — JSON із підписом Ed25519; прив'язана до коду пристрою. Перевіряється локально відкритим
ключем license_public.key; приватний ключ є лише у видавця (issue_license.py).
Опис: model_rozpovsiudzhennia.md
"""
import base64
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from version import APP_VERSION, PRODUCT, major

LICENSE_FILE = "license.lic"
LICENSE_PUBLIC = "license_public.key"


class LicenseError(Exception):
    """Ліцензію не прийнято (текст безпечно показувати користувачу)."""


class LicenseLimit(ValueError):
    """Досягнуто обмеження поточної редакції."""


@dataclass(frozen=True)
class Entitlements:
    edition: str
    max_profiles: "int | None"      # None — без обмежень
    max_tasks: "int | None"         # на профіль

    def summary(self):
        if self.max_profiles is None and self.max_tasks is None:
            return f"Редакція {self.edition}: без обмежень"
        return f"Редакція {self.edition}: до {self.max_profiles} профілів, до {self.max_tasks} задач на профіль"


FREE = Entitlements("Free", 3, 30)
PRO = Entitlements("Pro", None, None)
EDITIONS = {"pro": PRO}


# ---------------------------------------------------------------- код пристрою
def _machine_id():
    try:
        if sys.platform.startswith("win"):
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                return winreg.QueryValueEx(k, "MachineGuid")[0]
        if sys.platform == "darwin":
            out = subprocess.run(["ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5).stdout
            m = re.search(r'"IOPlatformUUID" = "([^"]+)"', out)
            if m:
                return m.group(1)
        for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if Path(p).exists():
                return Path(p).read_text(encoding="ascii").strip()
    except (OSError, ImportError, subprocess.SubprocessError, UnicodeDecodeError):
        pass
    return f"mac-{uuid.getnode():012x}"


def device_id():
    """Код пристрою: SHA-256 від ідентифікатора машини (сам ідентифікатор нікуди не передається)."""
    h = hashlib.sha256(b"planuvalnyk|device|v1|" + _machine_id().encode("utf-8")).hexdigest()[:24]
    return "-".join(h[i:i + 4] for i in range(0, 24, 4))


# ---------------------------------------------------------------- перевірка ліцензії
def canonical(payload):
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def verify_license(license_path, public_path, device, app_version=APP_VERSION):
    """Повертає (Entitlements, payload) або LicenseError."""
    try:
        doc = json.loads(Path(license_path).read_text(encoding="utf-8"))
        payload = doc["payload"]
        signature = base64.b64decode(doc["sig"], validate=True)
        public = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(Path(public_path).read_text(encoding="ascii").strip(), validate=True))
        public.verify(signature, canonical(payload))
    except InvalidSignature:
        raise LicenseError("Підпис ліцензії недійсний: файл змінено або видано не нашим ключем.")
    except (OSError, ValueError, KeyError, TypeError):
        raise LicenseError("Файл ліцензії або ключа пошкоджено.")
    if not isinstance(payload, dict) or payload.get("product") != PRODUCT:
        raise LicenseError("Ліцензія видана для іншого продукту.")
    edition = EDITIONS.get(payload.get("edition"))
    if edition is None:
        raise LicenseError("Невідома редакція в ліцензії.")
    if not hmac.compare_digest(str(payload.get("device", "")).lower(), str(device).lower()):
        raise LicenseError("Ліцензію видано для іншого пристрою.")
    lic_major = payload.get("major")
    if not isinstance(lic_major, int) or lic_major < major(app_version):
        raise LicenseError("Ліцензія не поширюється на цю версію програми.")
    return edition, payload


class LicenseManager:
    """Поточні права користувача. Перевіряється при кожному зверненні: підміна файлу в ході роботи
    не дає переваг, а недійсна ліцензія завжди повертає до безпечної редакції Free."""

    def __init__(self, app_dir, device_fn=device_id, app_version=APP_VERSION):
        self.dir = Path(app_dir)
        self._device_fn = device_fn
        self._version = app_version

    @property
    def device(self):
        return self._device_fn()

    def status(self):
        """(Entitlements, повідомлення про проблему або None, payload або None)."""
        lic = self.dir / LICENSE_FILE
        if not lic.exists():
            return FREE, None, None
        pub = self.dir / LICENSE_PUBLIC
        if not pub.exists():
            return FREE, f"Немає файлу {LICENSE_PUBLIC}: ліцензію перевірити неможливо.", None
        try:
            ent, payload = verify_license(lic, pub, self.device, self._version)
            return ent, None, payload
        except LicenseError as e:
            return FREE, str(e), None

    def entitlements(self):
        return self.status()[0]

    def summary(self):
        ent, err, payload = self.status()
        text = ent.summary()
        if payload:
            text += f" (ліцензія {payload.get('serial', '?')})"
        return text

    def activate(self, source):
        """Офлайн-активація: перевірити файл і лише тоді зберегти як license.lic."""
        pub = self.dir / LICENSE_PUBLIC
        if not pub.exists():
            raise LicenseError(f"Немає файлу {LICENSE_PUBLIC}.")
        ent, payload = verify_license(source, pub, self.device, self._version)
        target = self.dir / LICENSE_FILE
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_bytes(Path(source).read_bytes())
        os.replace(tmp, target)
        return ent, payload
