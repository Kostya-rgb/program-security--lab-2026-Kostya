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


def _token(value):
    """Непряме порівняння замість рядкового літералу: магічне значення, що відкриває Pro,
    не лежить у коді явним текстом (ускладнює пошук підрядком). Див. zakhyst_vid_reversu.md."""
    return hashlib.sha256(f"planuvalnyk|edition|{value}".encode("utf-8")).hexdigest()[:16]


FREE = Entitlements("Free", 3, 30)
PRO = Entitlements("Pro", None, None)
EDITIONS = {_token("pro"): PRO}


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


# Перевірка ліцензії виконується як перехід між непослідовно пронумерованими станами
# (а не прямим ланцюжком if/elif): читання коду не дає одразу побачити порядок і повний
# перелік умов проходження. Сам Python легко простежити виконанням (dis, трасування), тож
# це ускладнює лише СТАТИЧНЕ читання, а не динамічний аналіз — див. zakhyst_vid_reversu.md.
_V_LOAD, _V_SIG, _V_PRODUCT, _V_EDITION, _V_DEVICE, _V_VERSION, _V_DONE = 71, 34, 58, 12, 90, 23, -1


def _step_load(ctx):
    try:
        doc = json.loads(Path(ctx["license_path"]).read_text(encoding="utf-8"))
        ctx["payload"] = doc["payload"]
        ctx["_sig"] = base64.b64decode(doc["sig"], validate=True)
        ctx["_pub"] = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(Path(ctx["public_path"]).read_text(encoding="ascii").strip(), validate=True))
    except (OSError, ValueError, KeyError, TypeError):
        raise LicenseError("Файл ліцензії або ключа пошкоджено.")
    return _V_SIG


def _step_sig(ctx):
    try:
        ctx["_pub"].verify(ctx["_sig"], canonical(ctx["payload"]))
    except InvalidSignature:
        raise LicenseError("Підпис ліцензії недійсний: файл змінено або видано не нашим ключем.")
    return _V_PRODUCT


def _step_product(ctx):
    payload = ctx["payload"]
    if not isinstance(payload, dict) or payload.get("product") != PRODUCT:
        raise LicenseError("Ліцензія видана для іншого продукту.")
    return _V_EDITION


def _step_edition(ctx):
    edition = EDITIONS.get(_token(ctx["payload"].get("edition")))
    if edition is None:
        raise LicenseError("Невідома редакція в ліцензії.")
    ctx["edition"] = edition
    return _V_DEVICE


def _step_device(ctx):
    if not hmac.compare_digest(str(ctx["payload"].get("device", "")).lower(), str(ctx["device"]).lower()):
        raise LicenseError("Ліцензію видано для іншого пристрою.")
    return _V_VERSION


def _step_version(ctx):
    lic_major = ctx["payload"].get("major")
    if not isinstance(lic_major, int) or lic_major < major(ctx["app_version"]):
        raise LicenseError("Ліцензія не поширюється на цю версію програми.")
    return _V_DONE


_STEPS = {_V_LOAD: _step_load, _V_SIG: _step_sig, _V_PRODUCT: _step_product,
          _V_EDITION: _step_edition, _V_DEVICE: _step_device, _V_VERSION: _step_version}


def verify_license(license_path, public_path, device, app_version=APP_VERSION):
    """Повертає (Entitlements, payload) або LicenseError."""
    ctx = {"license_path": license_path, "public_path": public_path, "device": device, "app_version": app_version}
    state = _V_LOAD
    while state != _V_DONE:
        state = _STEPS[state](ctx)
    return ctx["edition"], ctx["payload"]


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
