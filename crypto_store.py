"""Симетричний захист даних «Планувальника справ».

AES-256-GCM (AEAD). Ієрархія ключів: пароль/ключ пристрою -> KEK -> DEK профілю -> дані задач.
Опис рішень: kryptografichnyi_zakhyst.md
"""
import base64
import hashlib
import json
import os
import hmac
import secrets
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALG = "AES-256-GCM"
KEY_LEN = 32
NONCE_LEN = 12                                   # 96 біт, випадковий для кожного шифрування
KEK_SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}      # окремі сіль і параметри від хеша для входу
SCRYPT_MAXMEM = 128 * 1024 * 1024
DEK_MAX_AGE_DAYS = 365                           # плановий строк життя DEK
TS_FMT = "%Y-%m-%dT%H:%M:%S"


class CryptoError(Exception):
    """Ключ недоступний, дані пошкоджені або підроблені."""


class IntegrityError(CryptoError):
    """Порушено цілісність або автентичність (MAC не збігається)."""


# ---------------------------------------------------------------- примітиви
def _b64e(data):
    return base64.b64encode(data).decode("ascii")


def _b64d(text):
    return base64.b64decode(text.encode("ascii"), validate=True)


def seal(key, plaintext, aad):
    """Шифрує; новий випадковий nonce при кожному виклику."""
    nonce = secrets.token_bytes(NONCE_LEN)
    return {"nonce": _b64e(nonce), "ct": _b64e(AESGCM(key).encrypt(nonce, plaintext, aad))}


def open_sealed(key, blob, aad):
    """Розшифровує й перевіряє цілісність; будь-яка помилка -> CryptoError."""
    try:
        return AESGCM(key).decrypt(_b64d(blob["nonce"]), _b64d(blob["ct"]), aad)
    except (InvalidTag, KeyError, ValueError, TypeError):
        raise CryptoError("Дані пошкоджено, змінено або ключ невірний.")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def mac_key(device_key):
    """Окремий ключ HMAC із ключа пристрою (розділення доменів через HKDF)."""
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None,
                info=b"planuvalnyk|users-mac|v1").derive(device_key)


def mac_tag(key, obj):
    return hmac.new(key, _canonical(obj), "sha256").hexdigest()


def mac_check(key, obj, tag):
    """Порівняння за сталий час."""
    if not isinstance(tag, str) or not hmac.compare_digest(mac_tag(key, obj), tag):
        raise IntegrityError("Порушено цілісність або автентичність файлу.")


def write_private(path, data: bytes):
    """Атомарний запис; тимчасовий файл одразу створюється з правами 0600 (де ОС це підтримує)."""
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def write_json_private(path, obj):
    write_private(path, json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8"))


# ---------------------------------------------------------------- ключ пристрою
class DeviceKey:
    """Файл device.key: ключі пристрою {kid: ключ}. Захищає профілі без пароля.
    Не створюється наново, якщо відсутній, коли профіль на нього посилається."""

    def __init__(self, path):
        self.path = path
        self._keys = None
        self.current = None
        self._mac_required = False       # після першого підписаного users.json знімати підпис не можна

    def _load(self, create):
        if self._keys is not None:
            return
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                keys = {k: _b64d(v) for k, v in data["keys"].items()}
                if data["current"] not in keys or any(len(v) != KEY_LEN for v in keys.values()):
                    raise ValueError
                self._keys, self.current = keys, data["current"]
                self._mac_required = bool(data.get("users_mac", False))
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                raise CryptoError(f"Файл {self.path.name} пошкоджено.")
        elif create:
            self._keys, self.current = {"k1": secrets.token_bytes(KEY_LEN)}, "k1"
            self._store()
        else:
            raise CryptoError(f"Відсутній {self.path.name}: дані профілів без пароля недоступні.")

    def _store(self):
        write_json_private(self.path, {"version": 1, "alg": ALG, "current": self.current,
                                       "users_mac": self._mac_required,
                                       "keys": {k: _b64e(v) for k, v in self._keys.items()}})

    def mac_required(self):
        """Чи вимагається підпис users.json (не створює файл ключів)."""
        if not self.path.exists():
            return False
        self._load(create=False)
        return self._mac_required

    def set_mac_required(self):
        self._load(create=True)
        if not self._mac_required:
            self._mac_required = True
            self._store()

    def current_kid(self):
        self.get()
        return self.current

    def get(self, kid=None):
        """kid=None — поточний ключ (створюється, якщо файлу ще немає)."""
        self._load(create=kid is None)
        key = self._keys.get(kid or self.current)
        if key is None:
            raise CryptoError("Ключ пристрою з потрібним ідентифікатором відсутній.")
        return key

    def add(self):
        """Додає новий ключ і робить його поточним; старі лишаються до retire()."""
        self._load(create=True)
        kid = f"k{max(int(k[1:]) for k in self._keys) + 1}"
        self._keys[kid] = secrets.token_bytes(KEY_LEN)
        self.current = kid
        self._store()
        return kid

    def retire(self, used_kids):
        """Видаляє ключі, на які більше ніхто не посилається."""
        self._load(create=False)
        self._keys = {k: v for k, v in self._keys.items() if k in set(used_kids) | {self.current}}
        self._store()


# ---------------------------------------------------------------- набір ключів сеансу
class KeySet:
    """KEK та всі версії DEK профілю; живе лише в пам'яті сеансу."""

    def __init__(self, kek, cur, deks):
        self.kek, self.cur, self.deks = kek, cur, deks

    def get(self, ver):
        try:
            return self.deks[int(ver)]
        except (KeyError, ValueError, TypeError):
            raise CryptoError("Версії ключа даних немає.")


class KeyManager:
    """Створення, розгортання й ротація ключів профілю. Метадані (meta) зберігаються в users.json
    лише у зашифрованому вигляді: DEK загорнуто (AES-256-GCM) під KEK."""

    def __init__(self, device_key_path):
        self.device = DeviceKey(device_key_path)

    @staticmethod
    def _aad(uid, ver, mode):
        return f"dek|v1|{uid}|{ver}|{mode}".encode()

    @staticmethod
    def _scrypt(password, kdf):
        return hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(kdf["salt"]), dklen=KEY_LEN,
                              maxmem=SCRYPT_MAXMEM, n=kdf["n"], r=kdf["r"], p=kdf["p"])

    def _new_kek(self, password):
        """Новий KEK: з пароля (нова сіль) або ключ пристрою, якщо пароля немає."""
        if password:
            kdf = {"alg": "scrypt", **KEK_SCRYPT, "salt": secrets.token_bytes(16).hex()}
            return self._scrypt(password, kdf), {"kdf": kdf}, "password"
        return self.device.get(), {"kid": self.device.current}, "device"

    def _build(self, uid, mode, ref, kek, deks, created, cur):
        keys = {str(v): {"created": created[v], **seal(kek, d, self._aad(uid, v, mode))} for v, d in deks.items()}
        return {"alg": ALG, "mode": mode, **ref, "cur": cur, "keys": keys}

    @staticmethod
    def _ref(meta):
        return {"kdf": meta["kdf"]} if meta["mode"] == "password" else {"kid": meta["kid"]}

    @staticmethod
    def _created(meta):
        return {int(v): k["created"] for v, k in meta["keys"].items()}

    # -- життєвий цикл
    def create(self, uid, password):
        kek, ref, mode = self._new_kek(password)
        dek = secrets.token_bytes(KEY_LEN)
        now = datetime.now().strftime(TS_FMT)
        return self._build(uid, mode, ref, kek, {1: dek}, {1: now}, 1), KeySet(kek, 1, {1: dek})

    def unlock(self, uid, meta, password):
        try:
            mode = meta["mode"]
            if mode == "password":
                if not password:
                    raise CryptoError("Для розшифрування потрібен пароль.")
                kek = self._scrypt(password, meta["kdf"])
            elif mode == "device":
                kek = self.device.get(meta["kid"])
            else:
                raise CryptoError("Невідомий режим захисту ключа.")
            deks = {int(v): open_sealed(kek, k, self._aad(uid, int(v), mode)) for v, k in meta["keys"].items()}
            cur = int(meta["cur"])
            if cur not in deks:
                raise ValueError
        except (KeyError, ValueError, TypeError, MemoryError):
            raise CryptoError("Метадані ключів пошкоджено.")
        return KeySet(kek, cur, deks)

    def rewrap(self, uid, meta, ks, new_password):
        """Зміна/зняття/встановлення пароля: нова сіль і KEK, DEK не змінюється, дані не чіпаються."""
        kek, ref, mode = self._new_kek(new_password)
        return self._build(uid, mode, ref, kek, ks.deks, self._created(meta), ks.cur), KeySet(kek, ks.cur, ks.deks)

    def add_version(self, uid, meta, ks):
        """Ротація DEK, крок 1: нова версія поруч зі старими (стара потрібна, доки дані не перешифровано)."""
        ver = max(ks.deks) + 1
        deks = {**ks.deks, ver: secrets.token_bytes(KEY_LEN)}
        created = {**self._created(meta), ver: datetime.now().strftime(TS_FMT)}
        return (self._build(uid, meta["mode"], self._ref(meta), ks.kek, deks, created, ver),
                KeySet(ks.kek, ver, deks))

    def prune(self, uid, meta, ks):
        """Ротація DEK, крок 3: після перешифрування лишається тільки поточна версія."""
        deks = {ks.cur: ks.deks[ks.cur]}
        return (self._build(uid, meta["mode"], self._ref(meta), ks.kek, deks, self._created(meta), ks.cur),
                KeySet(ks.kek, ks.cur, deks))

    @staticmethod
    def dek_due(meta, now=None):
        try:
            created = datetime.strptime(meta["keys"][str(meta["cur"])]["created"], TS_FMT)
        except (KeyError, ValueError, TypeError):
            return False
        return (now or datetime.now()) - created > timedelta(days=DEK_MAX_AGE_DAYS)

    def rotate_device(self, users):
        """Ротація ключа пристрою: нові обгортки DEK для всіх профілів без пароля.
        Повертає множину kid, що використовуються (решту можна прибрати через device.retire)."""
        new_kid = self.device.add()
        kek = self.device.get(new_kid)
        for u in users:
            meta = u.get("crypto")
            if meta and meta.get("mode") == "device":
                ks = self.unlock(u["id"], meta, None)          # старий ключ ще є у файлі
                u["crypto"] = self._build(u["id"], "device", {"kid": new_kid}, kek, ks.deks,
                                          self._created(meta), ks.cur)
        return {new_kid}


# ---------------------------------------------------------------- сховище задач
class VaultError(Exception):
    """tasks.json пошкоджено або не розшифровується (програма нічого не перезаписує)."""


class TaskVault:
    """tasks.json: зашифровані «відра» задач окремо для кожного профілю.
    Розшифрування — після входу (load_user), шифрування — при кожній зміні (save_user)."""

    VERSION = 2

    def __init__(self, path, seq_store=None):
        self.path = path
        self.seq_store = seq_store   # зберігає останній номер версії даних профілю (users.json, під HMAC)
        self.buckets = {}
        self.pending = []        # відкриті задачі старого формату: шифруються при вході власника
        self._read()

    def _read(self):
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(data, list):                               # формат до версії 1.3
                self.pending = [t for t in data if isinstance(t, dict)]
            elif isinstance(data, dict) and data.get("version") == self.VERSION \
                    and isinstance(data.get("buckets"), dict):
                self.buckets = data["buckets"]
                self.pending = [t for t in data.get("pending", []) if isinstance(t, dict)]
            else:
                raise ValueError
        except (OSError, ValueError):
            raise VaultError(f"Файл {self.path.name} пошкоджено або недоступний.\n"
                             "Відновіть його з резервної копії або перемістіть вручну.")

    @staticmethod
    def _aad(uid, ver, seq=None):
        if seq is None:                          # формат без номера версії (1.3)
            return f"tasks|v2|{uid}|{ver}".encode()
        return f"tasks|v3|{uid}|{ver}|{seq}".encode()

    def _flush(self):
        out = {"version": self.VERSION, "alg": ALG, "buckets": self.buckets}
        if self.pending:
            out["pending"] = self.pending
        write_json_private(self.path, out)

    def load_user(self, uid, keys, adopt_orphans=False):
        """Розшифровує задачі профілю. Відкриті задачі старого формату цього профілю
        (та без власника, якщо adopt_orphans) шифруються й зникають із відкритого вигляду."""
        tasks = []
        bucket = self.buckets.get(uid)
        expected = self.seq_store.get_seq(uid) if self.seq_store else None
        if bucket is None:
            if expected:
                raise VaultError("Задачі профілю зникли з tasks.json, хоча раніше були збережені "
                                 "(файл видалено або замінено).\nВідновіть tasks.json і users.json з однієї копії.")
        else:
            try:
                ver, seq = bucket["kver"], bucket.get("seq")
                tasks = json.loads(open_sealed(keys.get(ver), bucket, self._aad(uid, ver, seq)).decode("utf-8"))
                if not isinstance(tasks, list) or not (seq is None or isinstance(seq, int)):
                    raise ValueError
            except (CryptoError, KeyError, ValueError, TypeError):
                raise VaultError("Не вдалося розшифрувати задачі: файл пошкоджено, змінено або ключ невірний.")
            actual = seq or 0
            if expected is None or expected == actual:
                pass
            elif actual == expected + 1:               # збій між записом tasks.json і users.json: лікуємо
                self.seq_store.set_seq(uid, actual)
            else:
                raise VaultError("Версія задач не відповідає записаній: схоже на відкат tasks.json до старішої "
                                 "копії або підміну одного з файлів.\nВідновіть tasks.json і users.json з однієї копії.")
        mine = [t for t in self.pending
                if t.get("owner") == uid or (adopt_orphans and t.get("owner") is None)]
        if mine:
            tasks += mine
            self.pending = [t for t in self.pending if not any(t is m for m in mine)]
            self.save_user(uid, keys, tasks)
        return tasks

    def save_user(self, uid, keys, tasks):
        ver = keys.cur
        known = max((self.buckets.get(uid) or {}).get("seq", 0),
                    (self.seq_store.get_seq(uid) or 0) if self.seq_store else 0)
        seq = known + 1
        plain = json.dumps(tasks, ensure_ascii=False).encode("utf-8")
        self.buckets[uid] = {"kver": ver, "seq": seq, **seal(keys.get(ver), plain, self._aad(uid, ver, seq))}
        self._flush()
        if self.seq_store:
            self.seq_store.set_seq(uid, seq)
