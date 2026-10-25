"""Керування доступом «Планувальника справ».

Модель: DAC (власник ресурсу) + контекстні умови сеансу (елемент ABAC).
Політика за замовчуванням — «заборонено»: дія без правила відхиляється.
Опис моделі та правил: model_keruvannia_dostupom.md
"""
import time


class AccessDenied(Exception):
    """Відмова у доступі. Текст безпечно показувати користувачу."""


class Session:
    """Сеанс у пам'яті. Після end() або спливу неактивності вважається недійсним."""

    def __init__(self, user_id, username, idle_limit=None, clock=time.monotonic):
        self.user_id = user_id
        self.username = username
        self.idle_limit = idle_limit        # секунд; None — без автовиходу
        self._clock = clock
        self._ended = False
        self._last = clock()
        self._keys = None                   # ключі шифрування: лише в пам'яті сеансу

    @property
    def active(self):
        if self._ended:
            return False
        return self.idle_limit is None or self._clock() - self._last <= self.idle_limit

    def touch(self):
        """Реєструє дію користувача. Прострочений сеанс не відновлюється."""
        if self.active:
            self._last = self._clock()

    def attach_keys(self, keys):
        self._keys = keys

    @property
    def keys(self):
        """Ключі доступні лише в активному сеансі."""
        if not self.active or self._keys is None:
            raise AccessDenied("Сеанс завершено. Увійдіть знову.")
        return self._keys

    def end(self):
        self._ended = True
        self._keys = None


def _active(session):
    return session is not None and session.active


def _owns(session, task):
    owner = task.get("owner") if isinstance(task, dict) else None
    return _active(session) and owner is not None and owner == session.user_id


# дія -> умова дозволу (session, resource, ctx) -> bool
RULES = {
    # до входу (суб'єкт без активного сеансу)
    "profile:register": lambda s, r, c: not _active(s),
    "profile:login": lambda s, r, c: not _active(s),
    # лише власник профілю
    "profile:password": lambda s, r, c: _active(s) and isinstance(r, dict) and r.get("id") == s.user_id,
    # задачі
    "task:create": lambda s, r, c: _active(s),
    "task:list": lambda s, r, c: _active(s),
    "task:read": lambda s, r, c: _owns(s, r),
    "task:update": lambda s, r, c: _owns(s, r),
    "task:toggle": lambda s, r, c: _owns(s, r),
    "task:delete": lambda s, r, c: _owns(s, r),
    "task:remind": lambda s, r, c: _owns(s, r),
    # перенесення задач старого формату (без owner) — лише першому створеному профілю
    "task:claim_legacy": lambda s, r, c: (_active(s) and isinstance(r, dict) and r.get("owner") is None
                                          and c.get("first_user_id") == s.user_id),
}


def is_allowed(session, action, resource=None, **ctx):
    rule = RULES.get(action)
    return bool(rule and rule(session, resource, ctx))


def authorize(session, action, resource=None, **ctx):
    """Викликається безпосередньо перед захищеною операцією."""
    if not is_allowed(session, action, resource, **ctx):
        if session is not None and not session.active:
            raise AccessDenied("Сеанс завершено. Увійдіть знову.")
        raise AccessDenied("Доступ заборонено.")
