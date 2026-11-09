"""Тести захисту від реверс-інжинірингу: вартовий під час виконання та байткодовий дистрибутив.
Запуск:  python test_anti_tamper.py      або:  python -m unittest -v test_anti_tamper
"""
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path

try:
    import tkinter  # noqa: F401
except ImportError:
    class _Stub(types.ModuleType):
        def __getattr__(self, name):
            return type(name, (), {"__init__": lambda self, *a, **k: None})
    for n in ("tkinter", "tkinter.ttk", "tkinter.messagebox", "tkinter.filedialog"):
        sys.modules[n] = _Stub(n)
    sys.modules["tkinter"].ttk = sys.modules["tkinter.ttk"]
    sys.modules["tkinter"].messagebox = sys.modules["tkinter.messagebox"]
    sys.modules["tkinter"].filedialog = sys.modules["tkinter.filedialog"]

import build_release
import licensing
import main
from anti_tamper import Guard, TamperError

HERE = Path(__file__).resolve().parent


def say(t): print(f"     · {t}")
def ok(t): print(f"     ✔ {t}")


class RuntimeSelfCheck(unittest.TestCase):
    def setUp(self):
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")

    def test_unchanged_function_passes(self):
        """AT-67. Незмінена функція проходить перевірку"""
        g = Guard().watch(main.TaskService, "create")
        g.check()
        ok("Відбиток збігається, виключення не виникло")

    def test_patched_method_detected(self):
        """AT-68. Підміна методу класу під час роботи виявляється"""
        original = main.TaskService.create
        g = Guard().watch(main.TaskService, "create")
        main.TaskService.create = lambda self, session, data: {"id": 999, "forged": True}
        try:
            with self.assertRaises(TamperError) as cm:
                g.check()
            ok(f"Підміну виявлено: {cm.exception}")
        finally:
            main.TaskService.create = original
        g.check()
        ok("Після відновлення оригіналу перевірка знову проходить")

    def test_patched_module_function_detected(self):
        """AT-69. Підміна функції модуля (не лише методу класу) виявляється"""
        import access_control
        original = access_control.authorize
        g = Guard().watch(access_control, "authorize")
        access_control.authorize = lambda *a, **k: None   # «авторизує» все без перевірки
        try:
            with self.assertRaises(TamperError):
                g.check()
            ok("Підміну access_control.authorize виявлено")
        finally:
            access_control.authorize = original

    def test_real_guard_wired_into_main_watches_gated_operations(self):
        """AT-70. Вартовий у main.py стежить саме за операціями, що визначають редакцію й доступ"""
        watched = set(main.GUARD._baseline)
        say(f"Під наглядом: {len(watched)} функцій")
        for expected in ("TaskService.create", "AuthService.register", "verify_license",
                         "LicenseManager.status", "authorize", "mac_check", "verify_release"):
            self.assertTrue(any(expected in k for k in watched), f"{expected} не під наглядом")
        ok("Створення задачі, реєстрація профілю, ліцензія, доступ і підписи — під наглядом")

    def test_full_method_replacement_caught_on_next_watched_call(self):
        """AT-71. Чесна межа: повна підміна create() (разом із вбудованим check) обходить ЦЕЙ
        виклик, але виявляється вже наступним зверненням до будь-якої функції під наглядом"""
        original = main.TaskService.create

        def forged(self, session, data):          # підміна прибирає і GUARD.check() разом з тілом
            return {"id": 1, "owner": session.user_id, "title": data.get("title"), "done": False}
        main.TaskService.create = forged
        try:
            svc = main.TaskService([], save=lambda t: None)
            s = type("S", (), {"user_id": "u"})()
            result = svc.create(s, {"title": "x"})   # сам цей виклик підміну НЕ бачить
            self.assertEqual(result["id"], 1)
            say("Підмінений create() відпрацював непоміченим — очікувана межа захисту")
            with self.assertRaises(TamperError):
                main.GUARD.check()                   # але вже наступна перевірка (вхід, періодичний
            ok("тик, реєстрація) бачить підміну create(), бо вартовий перечитує баланс при кожному check()")
        finally:
            main.TaskService.create = original
        main.GUARD.check()
        ok("Після відновлення оригіналу вартовий знову чистий")

    def test_fingerprint_insensitive_to_object_identity_but_sensitive_to_logic(self):
        """AT-72. Відбиток залежить від логіки функції, а не від того, яка це конкретно копія об'єкта"""
        def f(x):
            return x + 1
        def g(x):
            return x + 1
        def h(x):
            return x + 2
        from anti_tamper import _fingerprint
        self.assertEqual(_fingerprint(f), _fingerprint(g))
        self.assertNotEqual(_fingerprint(f), _fingerprint(h))
        ok("Однакова логіка → однаковий відбиток; інша логіка → інший")


class EditionTokenHiding(unittest.TestCase):
    def setUp(self):
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")

    def test_pro_literal_not_in_editions_table(self):
        """AT-73. Рядок «pro» не лежить відкритим текстом у таблиці редакцій"""
        for key in licensing.EDITIONS:
            self.assertNotIn("pro", key.lower())
        ok(f"Ключ(і) таблиці EDITIONS: {list(licensing.EDITIONS)} — похідні, не самі рядки")

    def test_token_lookup_still_resolves_correct_edition(self):
        """AT-73b. Похідний ключ усе ще коректно відкриває Pro для правильного значення"""
        self.assertIs(licensing.EDITIONS[licensing._token("pro")], licensing.PRO)
        self.assertNotIn(licensing._token("free"), licensing.EDITIONS)
        ok("'pro' → Pro; будь-яке інше значення редакції в таблиці відсутнє")

    def test_verify_license_dispatch_covers_all_states(self):
        """AT-74. Усі стани диспетчера перевірки сягають DONE (жодного «висячого» переходу)"""
        import licensing as lic
        state = lic._V_LOAD
        seen = set()
        while state != lic._V_DONE:
            self.assertIn(state, lic._STEPS, f"Стан {state} не має обробника")
            self.assertNotIn(state, seen, "Цикл у графі станів")
            seen.add(state)
            state = {lic._V_LOAD: lic._V_SIG, lic._V_SIG: lic._V_PRODUCT, lic._V_PRODUCT: lic._V_EDITION,
                     lic._V_EDITION: lic._V_DEVICE, lic._V_DEVICE: lic._V_VERSION,
                     lic._V_VERSION: lic._V_DONE}[state]
        ok(f"Пройдено станів: {len(seen)}, усі ведуть до DONE")


def _tkinter_available():
    r = subprocess.run([sys.executable, "-c", "import tkinter"], capture_output=True)
    return r.returncode == 0


class BytecodeOnlyDistribution(unittest.TestCase):
    def setUp(self):
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")
        self.out = Path(tempfile.mkdtemp())

    def test_build_contains_no_py_source_for_protected_modules(self):
        """AT-75. Зібраний дистрибутив не містить .py для захищених модулів"""
        dist, compiled, copied = build_release.build(HERE, self.out)
        py_files = sorted(p.name for p in dist.glob("*.py"))
        say(f"У дистрибутиві .py: {py_files}; .pyc: {len(compiled)} файлів")
        self.assertEqual(py_files, ["run.py"])
        for name in ("main.pyc", "licensing.py".replace(".py", ".pyc"), "anti_tamper.pyc"):
            self.assertIn(name, compiled)
        ok("Лише launcher лишився читабельним текстом")

    @unittest.skipUnless(_tkinter_available(), "у цьому середовищі немає системного tkinter")
    def test_bytecode_only_package_runs(self):
        """AT-76. Пакет без .py реально запускається (--version, --device-id)"""
        dist, _, _ = build_release.build(HERE, self.out)
        for args, needle in ((["--version"], "1."), (["--device-id"], "-")):
            r = subprocess.run([sys.executable, str(dist / "run.py"), *args],
                               capture_output=True, text=True, timeout=20)
            say(f"run.py {' '.join(args)} → {r.stdout.strip()!r} (код {r.returncode})")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn(needle, r.stdout)
        ok("Програма виконується, маючи на диску лише байткод і запускач")

    def test_missing_source_file_fails_closed(self):
        """AT-76b. Відсутність джерела для захищеного модуля зупиняє збирання, а не пропускає його"""
        stage = Path(tempfile.mkdtemp())
        for n in build_release.COMPILED:
            (stage / n).write_text((HERE / n).read_text(encoding="utf-8"), encoding="utf-8")
        (stage / "version.py").unlink()
        with self.assertRaises(SystemExit):
            build_release.build(stage, self.out)
        ok("Збирання без version.py відхилено, а не мовчки пропустило модуль")


if __name__ == "__main__":
    unittest.main(verbosity=1)
