"""Тести керування доступом (без GUI) з поясненням кожного кроку.
Запуск:  python test_access_control.py      (найчитабельніший вивід)
або:     python -m unittest -v test_access_control
"""
import sys
import tempfile
import types
import unittest
from pathlib import Path

try:
    import tkinter  # noqa: F401
except ImportError:                      # середовище без Tk: підставляємо заглушку
    class _Stub(types.ModuleType):
        def __getattr__(self, name):
            return type(name, (), {"__init__": lambda self, *a, **k: None})
    for n in ("tkinter", "tkinter.ttk", "tkinter.messagebox"):
        sys.modules[n] = _Stub(n)
    sys.modules["tkinter"].ttk = sys.modules["tkinter.ttk"]
    sys.modules["tkinter"].messagebox = sys.modules["tkinter.messagebox"]

import main
from access_control import AccessDenied, Session, authorize

TASK = {"title": "Звіт", "deadline": "2026-10-30 18:30", "priority": "Високий", "remind_minutes": 15}


class Clock:
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.auth = main.AuthService(self.dir / "users.json")
        self.tasks = main.TaskService([], save=lambda t: None)
        self.alice = self.auth.register("Alice", ""); self.alice.end()
        self.bob = self.auth.register("Bob", "bobpassword1"); self.bob.end()
        self.alice = self.auth.login("Alice")
        self.bob = self.auth.login("Bob", "bobpassword1")
        self.a_task = self.tasks.create(self.alice, TASK)
        self.b_task = self.tasks.create(self.bob, dict(TASK, title="Секрет Боба"))
        title = (self.shortDescription() or self._testMethodName)
        print(f"\n▶ {title}")
        self.say("Дано: Alice (без пароля) із задачею «Звіт», Bob (з паролем) із задачею «Секрет Боба»")

    # --- допоміжні функції виводу
    def say(self, text):
        print(f"     · {text}")

    def allowed(self, label, op):
        result = op()
        print(f"     ✔ {label} → ДОЗВОЛЕНО")
        return result

    def denied(self, label, op, exc=AccessDenied):
        try:
            op()
        except exc as e:
            print(f"     ✔ {label} → ВІДМОВА ({e})")
            return
        self.fail(f"{label}: очікувалась відмова, але дію виконано")


class TaskAccess(Base):
    def test_owner_allowed(self):
        """AT-22. Власник виконує всі операції над своєю задачею"""
        i = self.a_task["id"]
        t = self.allowed("Alice читає свою задачу", lambda: self.tasks.get(self.alice, i))
        self.assertEqual(t["owner"], self.alice.user_id)
        t = self.allowed("Alice відмічає її виконаною", lambda: self.tasks.toggle_done(self.alice, i))
        self.assertTrue(t["done"])
        self.allowed("Alice змінює назву", lambda: self.tasks.update(self.alice, i, dict(TASK, title="Нова")))
        self.allowed("Alice позначає нагадування показаним", lambda: self.tasks.mark_reminded(self.alice, i))
        self.allowed("Alice видаляє задачу", lambda: self.tasks.delete(self.alice, i))
        self.assertEqual(self.tasks.list(self.alice), [])
        self.say("Список Alice тепер порожній, як і очікувалось")

    def test_list_isolated(self):
        """AT-23a. Кожен бачить у списку лише свої задачі"""
        a = [t["title"] for t in self.tasks.list(self.alice)]
        b = [t["title"] for t in self.tasks.list(self.bob)]
        self.say(f"Alice бачить: {a}")
        self.say(f"Bob бачить:   {b}")
        self.assertEqual(a, ["Звіт"])
        self.assertEqual(b, ["Секрет Боба"])

    def test_foreign_task_denied_for_every_operation(self):
        """AT-23. Alice не може виконати жодну операцію над задачею Bob"""
        bid = self.b_task["id"]
        self.say(f"Задача Bob має id={bid}; Alice викликає сервіс напряму, без інтерфейсу")
        self.denied("Alice читає задачу Bob", lambda: self.tasks.get(self.alice, bid))
        self.denied("Alice змінює задачу Bob", lambda: self.tasks.update(self.alice, bid, TASK))
        self.denied("Alice відмічає задачу Bob виконаною", lambda: self.tasks.toggle_done(self.alice, bid))
        self.denied("Alice позначає нагадування в задачі Bob", lambda: self.tasks.mark_reminded(self.alice, bid))
        self.denied("Alice видаляє задачу Bob", lambda: self.tasks.delete(self.alice, bid))
        after = self.tasks.get(self.bob, bid)
        self.say(f"Перевірка даних Bob після спроб: назва «{after['title']}», виконана={after['done']}")
        self.assertEqual(after["title"], "Секрет Боба")
        self.assertFalse(after["done"])

    def test_missing_task_indistinguishable(self):
        """AT-23b. Неіснуюча задача дає ту саму відмову, що й чужа"""
        self.denied("Alice видаляє задачу id=9999 (такої немає)", lambda: self.tasks.delete(self.alice, 9999))

    def test_owner_cannot_be_forged(self):
        """AT-25. Підроблені owner/id/done у вхідних даних ігноруються"""
        self.say(f"Alice створює задачу з owner=Bob, id=1, done=True у вхідних даних")
        t = self.tasks.create(self.alice, dict(TASK, owner=self.bob.user_id, id=1, done=True))
        self.say(f"Результат: owner=Alice? {t['owner'] == self.alice.user_id}; id={t['id']}; done={t['done']}")
        self.assertEqual(t["owner"], self.alice.user_id)
        self.assertFalse(t["done"])
        self.tasks.update(self.alice, t["id"], dict(TASK, owner=self.bob.user_id))
        owner = self.tasks.get(self.alice, t["id"])["owner"]
        self.say(f"Після update з owner=Bob власник лишився Alice: {owner == self.alice.user_id}")
        self.assertEqual(owner, self.alice.user_id)

    def test_returned_copies_do_not_bypass(self):
        """AT-25b. Зміна отриманої копії не змінює справжніх даних"""
        copy = self.tasks.list(self.alice)[0]
        copy["title"] = "підмінено"
        real = self.tasks.list(self.alice)[0]["title"]
        self.say(f"Копію змінили на «підмінено», у сервісі лишилось «{real}»")
        self.assertEqual(real, "Звіт")

    def test_no_session_denied(self):
        """AT-24a. Без сеансу всі операції заборонені"""
        self.denied("list без сеансу", lambda: self.tasks.list(None))
        self.denied("create без сеансу", lambda: self.tasks.create(None, TASK))
        self.denied("delete без сеансу", lambda: self.tasks.delete(None, self.a_task["id"]))

    def test_ended_session_denied(self):
        """AT-24b. Після завершення сеансу (вихід) операції заборонені"""
        self.alice.end()
        self.say("Alice натиснула «Вийти» (сеанс завершено), але старий об'єкт сеансу ще є в коді")
        self.denied("list зі старим сеансом", lambda: self.tasks.list(self.alice))
        self.denied("create зі старим сеансом", lambda: self.tasks.create(self.alice, TASK))
        self.denied("toggle зі старим сеансом", lambda: self.tasks.toggle_done(self.alice, self.a_task["id"]))

    def test_validation(self):
        """Некоректні дані відхиляються до запису"""
        cases = {"порожня назва": dict(TASK, title="  "), "дата «завтра»": dict(TASK, deadline="завтра"),
                 "невідомий пріоритет": dict(TASK, priority="Критичний"),
                 "нагадування 7 хв (немає в списку)": dict(TASK, remind_minutes=7)}
        for label, bad in cases.items():
            self.denied(f"create: {label}", lambda b=bad: self.tasks.create(self.alice, b), exc=ValueError)

    def test_legacy_tasks_ownerless_denied_and_claim(self):
        """AT-28. Задача без owner недоступна; забрати її може лише перший профіль"""
        legacy = {"id": 50, "title": "старе", "deadline": "2026-10-30 10:00", "priority": "Низький",
                  "remind_minutes": None, "reminded": False, "done": False}
        svc = main.TaskService([legacy], save=lambda t: None)
        self.denied("Alice читає задачу без owner", lambda: svc.get(self.alice, 50))
        n = svc.claim_legacy(self.bob, self.auth.first_user_id())
        self.say(f"Bob (не перший профіль) намагається забрати старі задачі: перенесено {n}")
        self.assertEqual(n, 0)
        n = svc.claim_legacy(self.alice, self.auth.first_user_id())
        self.say(f"Alice (перший профіль) забирає старі задачі: перенесено {n}")
        self.assertEqual(n, 1)
        self.assertEqual(svc.get(self.alice, 50)["owner"], self.alice.user_id)


class SessionContext(Base):
    def test_idle_timeout_enforced_at_operation(self):
        """AT-24c. Прострочений сеанс відхиляється в самій операції"""
        clock = Clock()
        s = Session(self.alice.user_id, "Alice", idle_limit=900, clock=clock)
        self.allowed("Через 0 с неактивності: list", lambda: self.tasks.list(s))
        clock.t += 901
        self.say("Минуло 901 с без дій (ліміт 900 с); таймер інтерфейсу не потрібен")
        self.denied("list після спливу ліміту", lambda: self.tasks.list(s))
        s.touch()
        self.say(f"Спроба «оживити» сеанс активністю: сеанс активний? {s.active}")
        self.assertFalse(s.active)

    def test_activity_extends_session(self):
        """Активність продовжує сеанс, поки ліміт не сплив"""
        clock = Clock()
        s = Session("x", "x", idle_limit=900, clock=clock)
        clock.t += 800; s.touch(); clock.t += 800
        self.say(f"800 с, дія, ще 800 с (разом 1600 с, але не більше 900 с поспіль): активний? {s.active}")
        self.assertTrue(s.active)

    def test_passwordless_has_no_idle_limit(self):
        """Автовихід діє лише для профілів із паролем"""
        self.say(f"Alice (без пароля): ліміт = {self.alice.idle_limit}")
        self.say(f"Bob (з паролем): ліміт = {self.bob.idle_limit} с")
        self.assertIsNone(self.alice.idle_limit)
        self.assertEqual(self.bob.idle_limit, main.IDLE_SECONDS)

    def test_unknown_action_denied(self):
        """AT-29. Дія без правила заборонена (deny by default)"""
        self.denied("authorize(Alice, 'task:export')", lambda: authorize(self.alice, "task:export"))


class ProfileAccess(Base):
    def test_change_own_password(self):
        """Користувач змінює пароль лише свого профілю"""
        self.allowed("Alice задає пароль", lambda: self.auth.change_password(self.alice, "", "alicepass123"))
        self.say(f"Автовихід тепер увімкнено: ліміт = {self.alice.idle_limit} с")
        self.assertEqual(self.alice.idle_limit, main.IDLE_SECONDS)
        self.allowed("Alice прибирає пароль", lambda: self.auth.change_password(self.alice, "alicepass123", ""))
        self.assertIsNone(self.alice.idle_limit)

    def test_wrong_current_password_denied(self):
        """Невірний поточний пароль не дозволяє змінити пароль"""
        self.denied("Bob змінює пароль із помилковим поточним",
                    lambda: self.auth.change_password(self.bob, "wrong", "newpassword1"), exc=main.AuthError)

    def test_no_session_cannot_change_password(self):
        """AT-26a. Без сеансу пароль змінити не можна"""
        self.denied("change_password(None, …) для Alice", lambda: self.auth.change_password(None, "", "hackedpass1"))
        self.say(f"У Alice і далі немає пароля: {not self.auth.has_password('Alice')}")
        self.assertFalse(self.auth.has_password("Alice"))

    def test_ended_session_cannot_change_password(self):
        """AT-26b. Із завершеним сеансом пароль змінити не можна"""
        self.bob.end()
        self.denied("Bob змінює пароль після виходу",
                    lambda: self.auth.change_password(self.bob, "bobpassword1", "newpassword1"))

    def test_login_and_register_denied_during_session(self):
        """AT-27. Вхід і реєстрація заборонені, поки сеанс активний"""
        self.denied("Alice (в сеансі) входить як Bob",
                    lambda: self.auth.login("Bob", "bobpassword1", session=self.alice))
        self.denied("Alice (в сеансі) реєструє Carol",
                    lambda: self.auth.register("Carol", "", session=self.alice))
        self.say(f"Профілю Carol не створено: {self.auth.find('Carol') is None}")
        self.assertIsNone(self.auth.find("Carol"))

    def test_login_register_allowed_without_session(self):
        """Вхід і реєстрація дозволені без активного сеансу"""
        self.assertTrue(self.allowed("Вхід Alice без сеансу", lambda: self.auth.login("Alice")).active)
        self.assertTrue(self.allowed("Реєстрація Carol без сеансу", lambda: self.auth.register("Carol", "")).active)
        ended = self.auth.login("Alice"); ended.end()
        self.assertTrue(self.allowed("Вхід Bob із завершеним попереднім сеансом",
                                     lambda: self.auth.login("Bob", "bobpassword1", session=ended)).active)


if __name__ == "__main__":
    unittest.main(verbosity=1)
