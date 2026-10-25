"""Тести контролю цілісності й автентичності з поясненням кроків.
Запуск:  python test_integrity.py      або:  python -m unittest -v test_integrity
"""
import base64
import json
import shutil
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

import integrity
import main
import sign_release
from crypto_store import TaskVault, VaultError

HERE = Path(__file__).resolve().parent
TASK = {"title": "Звіт", "deadline": "2026-10-30 18:30", "priority": "Високий", "remind_minutes": 15}
PW = "bobpassword1"


def say(text): print(f"     · {text}")
def ok(text): print(f"     ✔ {text}")


class DataBase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.users, self.tasks_file, self.devkey = self.dir / "users.json", self.dir / "tasks.json", self.dir / "device.key"
        self.reload()
        self.alice = self.auth.register("Alice", ""); self.alice.end()
        self.bob = self.auth.register("Bob", PW); self.bob.end()
        self.alice, self.bob = self.auth.login("Alice"), self.auth.login("Bob", PW)
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")

    def reload(self):
        self.auth = main.AuthService(self.users, self.devkey)
        self.vault = TaskVault(self.tasks_file, seq_store=self.auth)

    def put(self, session, title="Задача"):
        svc = main.TaskService(self.vault.load_user(session.user_id, session.keys),
                               save=lambda t: self.vault.save_user(session.user_id, session.keys, t))
        svc.create(session, dict(TASK, title=title))
        return svc

    def edit_users(self, fn):
        data = json.loads(self.users.read_text(encoding="utf-8"))
        fn(data)
        self.users.write_text(json.dumps(data), encoding="utf-8")


class UsersJsonAuthenticity(DataBase):
    def test_file_is_signed(self):
        """AT-40. users.json підписано HMAC-SHA256"""
        mac = json.loads(self.users.read_text(encoding="utf-8"))["mac"]
        say(f"mac: алгоритм={mac['alg']}, ключ={mac['kid']}, тег={mac['tag'][:16]}…")
        self.assertEqual(mac["alg"], "HMAC-SHA256")
        self.assertTrue(json.loads(self.devkey.read_text())["users_mac"])
        ok("Підпис є, вимогу підпису зафіксовано у device.key")

    def test_tampering_detected(self):
        """AT-41. Будь-яка зміна users.json поза застосунком виявляється при запуску"""
        cases = {
            "скинути лічильник блокування": lambda d: d["users"][1].update(failed=0, locked_until=0, data_seq=999),
            "перейменувати профіль": lambda d: d["users"][0].update(username="Mallory"),
            "замінити хеш пароля": lambda d: d["users"][1]["password"].update(hash="00" * 32),
            "видалити профіль": lambda d: d["users"].pop(0),
            "знизити параметри KDF": lambda d: d["users"][1]["crypto"]["kdf"].update(n=2),
        }
        original = self.users.read_bytes()
        for label, fn in cases.items():
            self.users.write_bytes(original)
            self.edit_users(fn)
            with self.assertRaises(main.AuthFileError):
                self.reload()
            ok(f"{label} → запуск відхилено (AuthFileError)")

    def test_signature_cannot_be_stripped_or_forged(self):
        """AT-41b. Видалення підпису, підробка підпису, видалення файлу"""
        original = self.users.read_bytes()
        self.edit_users(lambda d: d.pop("mac"))
        with self.assertRaises(main.AuthFileError):
            self.reload()
        ok("Підпис видалено (спроба «старого формату») → відхилено, бо підпис уже обов'язковий")
        self.users.write_bytes(original)
        self.edit_users(lambda d: d["mac"].update(tag="0" * 64))
        with self.assertRaises(main.AuthFileError):
            self.reload()
        ok("Підроблений тег → відхилено")
        self.users.unlink()
        with self.assertRaises(main.AuthFileError) as cm:
            self.reload()
        ok(f"Файл видалено → відхилено: {str(cm.exception).splitlines()[0]}")

    def test_legacy_file_is_signed_on_first_start(self):
        """AT-42. users.json без підпису (до версії 1.4) приймається один раз і підписується"""
        self.edit_users(lambda d: d.pop("mac"))
        flag = json.loads(self.devkey.read_text())
        flag["users_mac"] = False
        self.devkey.write_text(json.dumps(flag))
        self.reload()
        self.assertIn("mac", json.loads(self.users.read_text(encoding="utf-8")))
        ok("Файл старого формату підписано при першому запуску; далі підпис обов'язковий")

    def test_key_rotation_resigns(self):
        """AT-43. Після ротації ключа пристрою users.json підписаний новим ключем"""
        old = json.loads(self.users.read_text(encoding="utf-8"))["mac"]["kid"]
        self.auth.rotate_device_key()
        new = json.loads(self.users.read_text(encoding="utf-8"))["mac"]["kid"]
        say(f"kid підпису: {old} → {new}")
        self.assertNotEqual(old, new)
        self.reload()
        ok("users.json успішно перевіряється новим ключем")

    def test_no_silent_key_creation(self):
        """AT-43b. Підпис із невідомим kid не призводить до створення нового ключа"""
        self.edit_users(lambda d: d["mac"].update(kid="k99"))
        with self.assertRaises(main.AuthFileError):
            self.reload()
        self.assertEqual(list(json.loads(self.devkey.read_text())["keys"]), ["k1"])
        ok("Ключів у device.key не додалось")


class TasksFreshness(DataBase):
    def test_rollback_detected(self):
        """AT-44. Відкат tasks.json до старішої коректної копії виявляється"""
        self.put(self.alice, "Перша")
        old_copy = self.tasks_file.read_bytes()
        self.put(self.alice, "Друга")
        say(f"Номер версії даних Alice у users.json: {self.auth.get_seq(self.alice.user_id)}")
        self.tasks_file.write_bytes(old_copy)
        self.reload()
        with self.assertRaises(VaultError) as cm:
            self.vault.load_user(self.alice.user_id, self.alice.keys)
        ok(f"Підставлено стару копію → відмова: {str(cm.exception).splitlines()[0]}")

    def test_deleted_bucket_detected(self):
        """AT-45. Видалення даних профілю з tasks.json не маскується порожнім списком"""
        self.put(self.alice, "Важлива")
        data = json.loads(self.tasks_file.read_text())
        data["buckets"].pop(self.alice.user_id)
        self.tasks_file.write_text(json.dumps(data))
        self.reload()
        with self.assertRaises(VaultError) as cm:
            self.vault.load_user(self.alice.user_id, self.alice.keys)
        ok(f"Відро зникло → відмова: {str(cm.exception).splitlines()[0]}")
        self.tasks_file.unlink()
        self.reload()
        with self.assertRaises(VaultError):
            self.vault.load_user(self.alice.user_id, self.alice.keys)
        ok("Файл tasks.json видалено → відмова")

    def test_seq_header_cannot_be_edited(self):
        """AT-45b. Зміна номера версії у відрі виявляється (номер входить у AAD)"""
        self.put(self.alice)
        data = json.loads(self.tasks_file.read_text())
        data["buckets"][self.alice.user_id]["seq"] += 5
        self.tasks_file.write_text(json.dumps(data))
        self.reload()
        with self.assertRaises(VaultError):
            self.vault.load_user(self.alice.user_id, self.alice.keys)
        ok("Підроблений номер версії → розшифрування відхилено")

    def test_crash_between_files_heals(self):
        """AT-46. Збій між записом tasks.json і users.json не втрачає даних"""
        self.put(self.alice, "Перша")
        before = self.auth.get_seq(self.alice.user_id)
        real = self.auth.set_seq
        self.auth.set_seq = lambda uid, seq: None           # «збій»: users.json не оновлено
        self.put(self.alice, "Друга")
        self.auth.set_seq = real
        say(f"tasks.json має версію {before + 1}, users.json — {self.auth.get_seq(self.alice.user_id)}")
        self.reload()
        tasks = self.vault.load_user(self.alice.user_id, self.alice.keys)
        self.assertEqual([t["title"] for t in tasks], ["Перша", "Друга"])
        self.assertEqual(self.auth.get_seq(self.alice.user_id), before + 1)
        ok("Дані прочитано, users.json вирівняно")

    def test_accept_state_recovery(self):
        """AT-47. Свідоме прийняття стану після відкату (--accept-tasks-state)"""
        self.put(self.alice, "Перша")
        old = self.tasks_file.read_bytes()
        self.put(self.alice, "Друга")
        self.tasks_file.write_bytes(old)
        self.reload()
        main.accept_tasks_state(self.auth, self.vault)
        self.reload()
        tasks = self.vault.load_user(self.alice.user_id, self.alice.keys)
        self.assertEqual([t["title"] for t in tasks], ["Перша"])
        ok("Після підтвердження користувача стан прийнято, дані читаються")

    def test_per_user_seq_independent(self):
        """AT-47b. Відкат даних одного профілю не зачіпає інший"""
        self.put(self.alice); self.put(self.bob, "Bob")
        self.assertEqual(len(self.vault.load_user(self.bob.user_id, self.bob.keys)), 1)
        ok("Номери версій ведуться окремо для кожного профілю")


class ReleaseSignature(unittest.TestCase):
    def setUp(self):
        self.app = Path(tempfile.mkdtemp())
        for n in integrity.PROTECTED:
            shutil.copy(HERE / n, self.app / n)
        self.key = self.app.parent / (self.app.name + "_private.pem")
        self.fp = sign_release.init_keys(self.app, self.key)
        sign_release.sign(self.app, self.key)
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")

    def test_valid_release(self):
        """AT-48. Правильно підписаний випуск проходить перевірку"""
        status, fp = integrity.verify_release(self.app)
        say(f"Статус: {status}; відбиток ключа: {fp}")
        self.assertEqual((status, fp), ("ok", self.fp))
        self.assertFalse((self.app / "release_private.pem").exists())
        ok("Приватного ключа в папці програми немає (він зберігається окремо)")

    def test_unsigned_release_reported(self):
        """AT-48b. Без файлів підпису — статус unsigned (користувача попереджають)"""
        for n in (integrity.MANIFEST, integrity.SIGNATURE, integrity.PUBLIC_KEY):
            (self.app / n).unlink()
        self.assertEqual(integrity.verify_release(self.app), ("unsigned", None))
        ok("unsigned")

    def test_modified_file_detected(self):
        """AT-49. Зміна, видалення будь-якого файлу програми виявляється"""
        for name in integrity.PROTECTED:
            path = self.app / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n# backdoor\n")
            with self.assertRaises(integrity.IntegrityError):
                integrity.verify_release(self.app)
            ok(f"{name}: дописано код → відхилено")
            path.unlink()
            with self.assertRaises(integrity.IntegrityError):
                integrity.verify_release(self.app)
            ok(f"{name}: видалено → відхилено")
            path.write_bytes(original)
        self.assertEqual(integrity.verify_release(self.app)[0], "ok")

    def test_manifest_and_signature_tampering(self):
        """AT-50. Підміна маніфесту, підпису, ключа; видалення частини файлів підпису"""
        man = self.app / integrity.MANIFEST
        original = man.read_bytes()
        data = json.loads(original); data["files"]["main.py"] = "0" * 64
        man.write_text(json.dumps(data))
        with self.assertRaises(integrity.IntegrityError):
            integrity.verify_release(self.app)
        ok("Маніфест змінено без підпису → відхилено")
        man.write_bytes(original)

        # зловмисник хешує свій код і підписує власним ключем, підставивши власний відкритий ключ
        (self.app / "main.py").write_bytes(b"print('evil')\n")
        other_key = self.app.parent / (self.app.name + "_evil.pem")
        sign_release.init_keys(self.app, other_key)
        sign_release.sign(self.app, other_key)
        status, fp = integrity.verify_release(self.app)
        say(f"Підпис зловмисника формально коректний (статус {status}), але відбиток ключа інший: "
            f"{fp != self.fp}")
        self.assertNotEqual(fp, self.fp)
        ok("Підміна ключа ловиться лише звіркою відбитка з опублікованим окремо (--verify)")

    def test_partial_signature_files(self):
        """AT-50b. Якщо є хоч один файл підпису, потрібні всі"""
        (self.app / integrity.SIGNATURE).unlink()
        with self.assertRaises(integrity.IntegrityError):
            integrity.verify_release(self.app)
        ok("Видалено MANIFEST.sig → відхилено, а не «unsigned»")

    def test_corrupt_signature_files(self):
        """AT-50c. Пошкоджені файли підпису відхиляються без винятків"""
        sig = self.app / integrity.SIGNATURE
        sig.write_text("не base64!!")
        with self.assertRaises(integrity.IntegrityError):
            integrity.verify_release(self.app)
        sig.write_text(base64.b64encode(b"x" * 64).decode())
        with self.assertRaises(integrity.IntegrityError):
            integrity.verify_release(self.app)
        ok("Сміття замість підпису → IntegrityError")


if __name__ == "__main__":
    unittest.main(verbosity=1)
