"""Тести ліцензування та безпечного оновлення з поясненням кроків.
Запуск:  python test_licensing.py      або:  python -m unittest -v test_licensing
"""
import json
import re
import shutil
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

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

import integrity
import issue_license
import licensing
import main
import sign_release
import updater
from licensing import FREE, PRO, LicenseError, LicenseLimit, LicenseManager

HERE = Path(__file__).resolve().parent
TASK = {"title": "Звіт", "deadline": "2026-10-30 18:30", "priority": "Високий", "remind_minutes": 15}
DEVICE_A = "aaaa-bbbb-cccc-dddd-eeee-ffff"
DEVICE_B = "1111-2222-3333-4444-5555-6666"


def say(t): print(f"     · {t}")
def ok(t): print(f"     ✔ {t}")


class Base(unittest.TestCase):
    def setUp(self):
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")


class DeviceCode(Base):
    def test_device_code_format_and_stability(self):
        """AT-51. Код пристрою: стабільний, у стандартному форматі, не містить сирого ідентифікатора"""
        a, b = licensing.device_id(), licensing.device_id()
        say(f"Код цього пристрою: {a}")
        self.assertEqual(a, b)
        self.assertRegex(a, r"^[0-9a-f]{4}(-[0-9a-f]{4}){5}$")
        with mock.patch.object(licensing, "_machine_id", return_value="MACHINE-X"):
            code = licensing.device_id()
        self.assertNotIn("MACHINE", code)
        ok("Відбиток від ідентифікатора машини: сам ідентифікатор нікуди не передається")


class Editions(Base):
    def setUp(self):
        super().setUp()
        self.dir = Path(tempfile.mkdtemp())
        self.auth = main.AuthService(self.dir / "users.json", self.dir / "device.key")   # за замовчуванням Free

    def test_free_profile_limit(self):
        """AT-52. Free: не більше 3 профілів"""
        for name in ("User1", "User2", "User3"):
            s = self.auth.register(name, ""); s.end()
        with self.assertRaises(main.AuthError) as cm:
            self.auth.register("User4", "")
        self.assertIsNone(self.auth.find("User4"))
        ok(f"Четвертий профіль → відмова: {cm.exception}")

    def test_free_task_limit_and_release(self):
        """AT-53. Free: не більше 30 задач на профіль; видалення звільняє місце; Pro знімає ліміт"""
        s = self.auth.register("Alice", "")
        svc = main.TaskService([], save=lambda t: None)               # редакція за замовчуванням — Free
        for i in range(30):
            svc.create(s, dict(TASK, title=f"Задача {i}"))
        say("Створено 30 задач")
        with self.assertRaises(LicenseLimit) as cm:
            svc.create(s, TASK)
        ok(f"31-ша задача → відмова: {cm.exception}")
        svc.delete(s, svc.list(s)[0]["id"])
        svc.create(s, TASK)
        ok("Після видалення однієї задачі створення знову можливе")
        pro = main.TaskService(svc._tasks, save=lambda t: None, entitlements=lambda: PRO)
        pro.create(s, TASK)
        ok("З редакцією Pro ліміт не діє")

    def test_other_profiles_do_not_share_task_limit(self):
        """AT-53b. Ліміт задач рахується окремо для кожного профілю"""
        a = self.auth.register("Alice", ""); a.end()
        b = self.auth.register("Bob", "")
        svc = main.TaskService([], save=lambda t: None)
        a2 = self.auth.login("Alice")
        for i in range(30):
            svc.create(a2, dict(TASK, title=f"A{i}"))
        svc.create(b, TASK)
        ok("Bob створює задачу, хоча Alice досягла ліміту")


class LicenseFiles(Base):
    def setUp(self):
        super().setUp()
        self.app = Path(tempfile.mkdtemp())
        self.key = self.app.parent / (self.app.name + "_lic.pem")
        self.fp = issue_license.init_keys(self.app, self.key)
        self.lic = LicenseManager(self.app, device_fn=lambda: DEVICE_A)
        self.file = self.app / "license.lic"

    def issue(self, device=DEVICE_A, major=None, out=None):
        return issue_license.issue(self.key, device, "Іван Петренко", "PL-2026-0001", major, out or self.file)

    def test_no_license_is_free(self):
        """AT-54. Без ліцензії — редакція Free"""
        ent, err, _ = self.lic.status()
        self.assertEqual((ent, err), (FREE, None))
        ok(self.lic.summary())

    def test_valid_license_gives_pro(self):
        """AT-54b. Дійсна ліцензія для цього пристрою дає Pro"""
        self.issue()
        ent, err, payload = self.lic.status()
        say(f"Ліцензіат: {payload['licensee']}, серійний номер {payload['serial']}, пристрій {payload['device']}")
        self.assertEqual((ent, err), (PRO, None))
        ok(self.lic.summary())

    def test_activation_copies_only_valid_file(self):
        """AT-55. Активація зберігає license.lic лише після успішної перевірки"""
        incoming = self.app.parent / (self.app.name + "_in.lic")
        self.issue(out=incoming)
        self.assertFalse(self.file.exists())
        ent, _ = self.lic.activate(incoming)
        self.assertTrue(self.file.exists())
        self.assertEqual(self.lic.entitlements(), PRO)
        ok("Файл прийнято й збережено")
        self.file.unlink()
        bad = self.app.parent / (self.app.name + "_bad.lic")
        bad.write_text(incoming.read_text(encoding="utf-8").replace("Іван", "Хакер"), encoding="utf-8")
        with self.assertRaises(LicenseError):
            self.lic.activate(bad)
        self.assertFalse(self.file.exists())
        ok("Змінений файл відхилено, license.lic не створено")

    def test_tampering_falls_back_to_free(self):
        """AT-56. Підміна ліцензії: підпис недійсний, редакція Free, дані не втрачаються"""
        self.issue()
        doc = json.loads(self.file.read_text(encoding="utf-8"))
        cases = {
            "змінено ліцензіата": lambda d: d["payload"].update(licensee="Інший"),
            "змінено пристрій": lambda d: d["payload"].update(device=DEVICE_B),
            "змінено major на вищий": lambda d: d["payload"].update(major=9),
            "підпис обнулено": lambda d: d.update(sig="A" * 86 + "=="),
        }
        for label, fn in cases.items():
            d = json.loads(json.dumps(doc)); fn(d)
            self.file.write_text(json.dumps(d), encoding="utf-8")
            ent, err, _ = self.lic.status()
            self.assertEqual(ent, FREE)
            self.assertIsNotNone(err)
            ok(f"{label} → Free ({err})")

    def test_license_for_other_device_rejected(self):
        """AT-57. Ліцензія, видана для іншого пристрою, не діє"""
        self.issue(device=DEVICE_B)
        ent, err, _ = self.lic.status()
        self.assertEqual(ent, FREE)
        ok(f"Free: {err}")

    def test_license_covers_only_licensed_major(self):
        """AT-58. Ліцензія 1.x не діє на версію 2.x"""
        self.issue(major=1)
        newer = LicenseManager(self.app, device_fn=lambda: DEVICE_A, app_version="2.0.0")
        self.assertEqual(newer.entitlements(), FREE)
        self.assertEqual(self.lic.entitlements(), PRO)
        ok("1.5.0 → Pro; 2.0.0 → Free")

    def test_foreign_signer_rejected(self):
        """AT-59. Ліцензія, підписана чужим ключем, не діє"""
        evil = self.app.parent / (self.app.name + "_evil.pem")
        other_dir = Path(tempfile.mkdtemp())
        issue_license.init_keys(other_dir, evil)
        issue_license.issue(evil, DEVICE_A, "Хакер", "FAKE", None, self.file)
        ent, err, _ = self.lic.status()
        self.assertEqual(ent, FREE)
        ok(f"Підпис від іншого ключа відхилено: {err}")

    def test_garbage_and_missing_key(self):
        """AT-59b. Пошкоджений файл або відсутній відкритий ключ → Free без винятків"""
        self.file.write_text("не json", encoding="utf-8")
        self.assertEqual(self.lic.entitlements(), FREE)
        self.issue()
        (self.app / "license_public.key").unlink()
        ent, err, _ = self.lic.status()
        self.assertEqual(ent, FREE)
        ok(f"Free: {err}")

    def test_downgrade_keeps_data(self):
        """AT-60. Втрата ліцензії не блокує дані: усі задачі читаються й видаляються, нові — у межах Free"""
        d = Path(tempfile.mkdtemp())
        auth = main.AuthService(d / "users.json", d / "device.key", entitlements=lambda: PRO)
        s = auth.register("Alice", "")
        svc = main.TaskService([], save=lambda t: None, entitlements=lambda: PRO)
        for i in range(35):
            svc.create(s, dict(TASK, title=f"T{i}"))
        free_svc = main.TaskService(svc._tasks, save=lambda t: None)
        self.assertEqual(len(free_svc.list(s)), 35)
        with self.assertRaises(LicenseLimit):
            free_svc.create(s, TASK)
        free_svc.delete(s, free_svc.list(s)[0]["id"])
        ok("35 наявних задач доступні; нові додати не можна, доки їх ≥ 30; видалення працює")


class Updates(Base):
    """Пакет оновлення перевіряється ВСТАНОВЛЕНИМ ключем випуску."""

    def setUp(self):
        super().setUp()
        self.app = Path(tempfile.mkdtemp())
        for n in integrity.PROTECTED:
            shutil.copy(HERE / n, self.app / n)
        self.key = self.app.parent / (self.app.name + "_rel.pem")
        self.fp = sign_release.init_keys(self.app, self.key)
        sign_release.sign(self.app, self.key)
        self.out = Path(tempfile.mkdtemp())

    def build(self, version="1.6.0", mutate=None, key=None):
        """Збирає пакет із версією version в окремій копії, не чіпаючи встановленої програми."""
        stage = Path(tempfile.mkdtemp())
        for n in integrity.PROTECTED:
            shutil.copy(self.app / n, stage / n)
        (stage / "version.py").write_text(
            re.sub(r'APP_VERSION = "[\d.]+"', f'APP_VERSION = "{version}"', (stage / "version.py").read_text(encoding="utf-8")),
            encoding="utf-8")
        shutil.copy(self.app / "release_public.key", stage / "release_public.key")
        if mutate:
            mutate(stage)
        zip_path, _ = sign_release.package(stage, key or self.key, self.out)
        return zip_path

    def installed_version(self):
        return integrity.read_version(self.app)

    def test_valid_update_applied(self):
        """AT-61. Правильно підписане новіше оновлення встановлюється; після нього випуск перевіряється"""
        pkg = self.build("1.6.0", mutate=lambda d: (d / "main.py").write_text(
            (d / "main.py").read_text(encoding="utf-8") + "\n# нова функція\n", encoding="utf-8"))
        new = updater.apply_update(pkg, self.app)
        say(f"Версія після оновлення: {new}")
        self.assertEqual(self.installed_version(), "1.6.0")
        self.assertIn("нова функція", (self.app / "main.py").read_text(encoding="utf-8"))
        self.assertEqual(integrity.verify_release(self.app)[0], "ok")
        ok("Файли замінено, підпис і хеші нового випуску вірні")

    def test_tampered_file_rejected(self):
        """AT-62. Файл у пакеті змінено після підпису → відхилено, встановлена програма не змінена"""
        pkg = self.build()
        tampered = self.out / "tampered.zip"
        with zipfile.ZipFile(pkg) as zin, zipfile.ZipFile(tampered, "w") as zout:
            for info in zin.infolist():
                data = zin.read(info.filename)
                if info.filename == "crypto_store.py":
                    data += b"\nimport os; os.system('evil')\n"
                zout.writestr(info.filename, data)
        before = (self.app / "crypto_store.py").read_bytes()
        with self.assertRaises(updater.UpdateError) as cm:
            updater.apply_update(tampered, self.app)
        self.assertEqual((self.app / "crypto_store.py").read_bytes(), before)
        self.assertEqual(self.installed_version(), "1.5.0")
        ok(f"{cm.exception}")

    def test_foreign_signature_rejected_even_with_own_key_inside(self):
        """AT-63. Пакет, підписаний чужим ключем (навіть із його відкритим ключем у пакеті), відхиляється"""
        evil = self.app.parent / (self.app.name + "_evil.pem")
        other = Path(tempfile.mkdtemp())
        sign_release.init_keys(other, evil)
        pkg = self.build(key=evil)
        with zipfile.ZipFile(pkg) as z:
            self.assertNotIn("release_public.key", z.namelist())
        with self.assertRaises(updater.UpdateError) as cm:
            updater.apply_update(pkg, self.app)
        ok(f"{cm.exception}")

    def test_rollback_and_same_version_rejected(self):
        """AT-64. Оновлення на старішу або ту саму версію заборонено"""
        for v in ("1.5.0", "1.4.9", "1.0.0"):
            with self.assertRaises(updater.UpdateError) as cm:
                updater.apply_update(self.build(v), self.app)
            ok(f"Версія {v} → {cm.exception}")

    def test_malicious_archive_structure_rejected(self):
        """AT-65. Zip-slip, зайві файли, підпис без маніфесту, сміття, надмірні розміри"""
        pkg = self.build()
        def rebuilt(name, edit):
            out = self.out / name
            with zipfile.ZipFile(pkg) as zin, zipfile.ZipFile(out, "w") as zout:
                edit(zin, zout)
            return out
        def copy_all(zin, zout, skip=()):
            for i in zin.infolist():
                if i.filename not in skip:
                    zout.writestr(i.filename, zin.read(i.filename))
        cases = {
            "шлях виходить за межі папки": lambda zin, zout: (copy_all(zin, zout), zout.writestr("../evil.py", b"x")),
            "зайвий файл поза маніфестом": lambda zin, zout: (copy_all(zin, zout), zout.writestr("extra.py", b"x")),
            "підпис без маніфесту": lambda zin, zout: copy_all(zin, zout, skip=("MANIFEST.json",)),
            "підміна ключа випуску": lambda zin, zout: (copy_all(zin, zout), zout.writestr("release_public.key", b"x")),
            "підкаталог": lambda zin, zout: (copy_all(zin, zout), zout.writestr("sub/a.py", b"x")),
        }
        for label, edit in cases.items():
            with self.assertRaises(updater.UpdateError):
                updater.apply_update(rebuilt(label.replace(" ", "_") + ".zip", edit), self.app)
            ok(f"{label} → відхилено")
        junk = self.out / "junk.zip"; junk.write_bytes(b"not a zip")
        with self.assertRaises(updater.UpdateError):
            updater.apply_update(junk, self.app)
        ok("Не архів → відхилено")
        self.assertEqual(self.installed_version(), "1.5.0")

    def test_failure_during_install_rolls_back(self):
        """AT-66. Збій під час встановлення повертає попередню версію"""
        pkg = self.build("1.6.0", mutate=lambda d: (d / "access_control.py").write_text(
            (d / "access_control.py").read_text(encoding="utf-8") + "\n# v1.6\n", encoding="utf-8"))
        before = {n: (self.app / n).read_bytes() for n in integrity.PROTECTED}
        real = updater.os.replace
        calls = {"n": 0}
        def flaky(src, dst):
            calls["n"] += 1
            if calls["n"] == 3:
                raise OSError("диск недоступний")
            return real(src, dst)
        with mock.patch.object(updater.os, "replace", side_effect=flaky):
            with self.assertRaises(updater.UpdateError) as cm:
                updater.apply_update(pkg, self.app)
        self.assertEqual({n: (self.app / n).read_bytes() for n in integrity.PROTECTED}, before)
        self.assertEqual(integrity.verify_release(self.app)[0], "ok")
        ok(f"{cm.exception} Файли ідентичні початковим, випуск проходить перевірку")

    def test_post_install_verification_failure_rolls_back(self):
        """AT-66b. Підсумкова перевірка після встановлення не пройшла → відкат"""
        pkg = self.build("1.6.0")
        with mock.patch.object(updater, "verify_release", side_effect=integrity.IntegrityError("x")):
            with self.assertRaises(updater.UpdateError):
                updater.apply_update(pkg, self.app)
        self.assertEqual(self.installed_version(), "1.5.0")
        ok("Версія лишилась 1.5.0")


if __name__ == "__main__":
    unittest.main(verbosity=1)
