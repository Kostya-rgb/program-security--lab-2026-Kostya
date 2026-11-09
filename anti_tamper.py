"""Захист критичних функцій від зміни в пам'яті процесу під час роботи.

Підпис файлів (integrity.py) перевіряється лише при запуску: він не бачить, якщо функцію
підмінили вже ПІСЛЯ старту (налагоджувач, стороннє розширення, виклик з іншого потоку чи
через ctypes). Цей модуль фіксує «відбиток» байткоду обраних функцій одразу після імпорту
(до взаємодії користувача) і звіряє його повторно перед кожною захищеною операцією.
Обирає не всі функції, а лише ті, чий патч реально дає перевагу без доступу до криптографічних
ключів: перевірки ліцензії, обмежень редакції та підписів (докладніше — zakhyst_vid_reversu.md).
"""
import hashlib


class TamperError(Exception):
    """Критичну функцію змінено в пам'яті процесу після старту програми."""


def _fingerprint(func):
    """Хеш байткоду та констант функції. Для staticmethod/bound method розгортає __func__."""
    raw = getattr(func, "__func__", func)
    code = raw.__code__
    consts = tuple(c for c in code.co_consts if isinstance(c, (str, int, float, bytes)))
    payload = code.co_code + repr(consts).encode("utf-8") + repr(code.co_names).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class Guard:
    """Реєстр еталонних відбитків. Перечитує поточний атрибут при кожній перевірці, тож
    бачить підміну через `Клас.метод = інша_функція`, а не лише зміну вже збереженого об'єкта."""

    def __init__(self):
        self._baseline = {}

    def watch(self, owner, attr):
        name = getattr(owner, "__qualname__", getattr(owner, "__name__", str(owner)))
        key = f"{getattr(owner, '__module__', name)}.{name}.{attr}"
        self._baseline[key] = (owner, attr, _fingerprint(getattr(owner, attr)))
        return self

    def watch_many(self, pairs):
        for owner, attr in pairs:
            self.watch(owner, attr)
        return self

    def check(self):
        for key, (owner, attr, expected) in self._baseline.items():
            current = getattr(owner, attr, None)
            if current is None or _fingerprint(current) != expected:
                raise TamperError(f"Критичну функцію {key} змінено під час роботи програми. "
                                  "Перезапустіть застосунок із довіреного джерела.")

    def __len__(self):
        return len(self._baseline)
