"""Цілісність і автентичність програми «Планувальник справ».

Маніфест SHA-256 хешів файлів програми підписано Ed25519. Перевіряється відкритим ключем
release_public.key; приватний ключ зберігається поза проєктом (див. sign_release.py).
Опис рішень: kontrol_tsilisnosti.md
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MANIFEST, SIGNATURE, PUBLIC_KEY = "MANIFEST.json", "MANIFEST.sig", "release_public.key"
PROTECTED = ["main.py", "access_control.py", "crypto_store.py", "integrity.py", "requirements.txt"]


class IntegrityError(Exception):
    """Програму змінено, пошкоджено або підпис недійсний."""


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build_manifest(app_dir, files=PROTECTED):
    """Канонічний (детермінований) JSON-маніфест."""
    manifest = {"version": 1, "alg": "SHA-256", "files": {n: sha256_file(Path(app_dir) / n) for n in files}}
    return json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8")


def fingerprint(public_raw):
    """Відбиток відкритого ключа: звіряється з опублікованим окремо (довірений канал)."""
    h = hashlib.sha256(public_raw).hexdigest()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def verify_release(app_dir):
    """Повертає ("ok", відбиток) або ("unsigned", None); при порушенні — IntegrityError.
    Якщо є хоч один із файлів підпису, потрібні всі: видалення частини файлів — це порушення."""
    d = Path(app_dir)
    pub, man, sig = d / PUBLIC_KEY, d / MANIFEST, d / SIGNATURE
    present = [p.exists() for p in (pub, man, sig)]
    if not any(present):
        return "unsigned", None
    for p in (pub, man, sig):
        if not p.exists():
            raise IntegrityError(f"Відсутній файл підпису {p.name}.")
    try:
        public_raw = base64.b64decode(pub.read_text(encoding="ascii").strip(), validate=True)
        key = Ed25519PublicKey.from_public_bytes(public_raw)
        manifest_bytes = man.read_bytes()
        key.verify(base64.b64decode(sig.read_text(encoding="ascii").strip(), validate=True), manifest_bytes)
    except InvalidSignature:
        raise IntegrityError("Підпис маніфесту недійсний.")
    except (OSError, ValueError, TypeError):
        raise IntegrityError("Файли підпису пошкоджено.")
    try:
        files = json.loads(manifest_bytes)["files"]
        if not isinstance(files, dict) or not set(PROTECTED) <= set(files):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise IntegrityError("Маніфест пошкоджено або неповний.")
    for name, expected in files.items():
        if Path(name).name != name:
            raise IntegrityError("Маніфест містить недопустимий шлях.")
        path = d / name
        if not path.exists():
            raise IntegrityError(f"Відсутній файл програми {name}.")
        if not hmac.compare_digest(sha256_file(path), str(expected)):
            raise IntegrityError(f"Файл {name} змінено або пошкоджено.")
    return "ok", fingerprint(public_raw)
