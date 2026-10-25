"""Тести симетричного захисту даних з поясненням кроків.
Запуск:  python test_crypto.py      або:  python -m unittest -v test_crypto
"""
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta
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
from access_control import AccessDenied, Session
from crypto_store import CryptoError, KeyManager, TaskVault, VaultError, open_sealed, seal

TASK = {"title": "Секретна зустріч", "deadline": "2026-10-30 18:30", "priority": "Високий", "remind_minutes": 15}
PW = "bobpassword1"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.users, self.tasks_file, self.devkey = self.dir / "users.json", self.dir / "tasks.json", self.dir / "device.key"
        self.auth = main.AuthService(self.users, self.devkey)
        self.vault = TaskVault(self.tasks_file, seq_store=self.auth)
        self.alice = self.auth.register("Alice", ""); self.alice.end()      # без пароля -> ключ пристрою
        self.bob = self.auth.register("Bob", PW); self.bob.end()            # з паролем -> ключ із пароля
        self.alice = self.auth.login("Alice")
        self.bob = self.auth.login("Bob", PW)
        print(f"\n▶ {self.shortDescription() or self._testMethodName}")

    def say(self, text):
        print(f"     · {text}")

    def ok(self, text):
        print(f"     ✔ {text}")

    def add_task(self, session, title="Секретна зустріч"):
        svc = main.TaskService([], save=lambda t: self.vault.save_user(session.user_id, session.keys, t))
        svc.create(session, dict(TASK, title=title))
        return svc

    def raw(self):
        return self.tasks_file.read_bytes()

    def reload(self):
        self.auth = main.AuthService(self.users, self.devkey)
        self.vault = TaskVault(self.tasks_file, seq_store=self.auth)


class Encryption(Base):
    def test_file_has_no_plaintext(self):
        """AT-30. У tasks.json немає відкритого тексту задач"""
        self.add_task(self.alice, "Лікар у п'ятницю"); self.add_task(self.bob, "Пароль від сейфа")
        data = self.raw()
        self.say(f"Розмір tasks.json: {len(data)} байт; алгоритм у файлі: {json.loads(data)['alg']}")
        for secret in ("Лікар", "п'ятницю", "Пароль від сейфа", "2026-10-30", "Високий"):
            self.assertNotIn(secret.encode("utf-8"), data)
        self.ok("Назв, дат і пріоритетів у файлі немає; видно лише ідентифікатори профілів і шифртекст")
        self.assertNotIn(b"Alice", data)

    def test_roundtrip_after_restart(self):
        """AT-31. Після перезапуску задачі розшифровуються тими самими ключами"""
        self.add_task(self.alice, "Задача A")
        self.reload()
        alice = self.auth.login("Alice")
        tasks = self.vault.load_user(alice.user_id, alice.keys)
        self.say(f"Розшифровано: {[t['title'] for t in tasks]}")
        self.assertEqual([t["title"] for t in tasks], ["Задача A"])

    def test_nonce_is_fresh(self):
        """AT-31. Кожне шифрування має новий nonce (однакові дані -> різний шифртекст)"""
        svc = self.add_task(self.alice)
        b1 = dict(self.vault.buckets[self.alice.user_id])
        self.vault.save_user(self.alice.user_id, self.alice.keys, svc.list(self.alice))
        b2 = self.vault.buckets[self.alice.user_id]
        self.say(f"nonce 1 ≠ nonce 2: {b1['nonce'] != b2['nonce']}; шифртекст різний: {b1['ct'] != b2['ct']}")
        self.assertNotEqual(b1["nonce"], b2["nonce"])
        self.assertNotEqual(b1["ct"], b2["ct"])

    def test_tampering_detected(self):
        """AT-32. Зміна шифртексту виявляється (GCM), програма не віддає підміну"""
        self.add_task(self.alice)
        data = json.loads(self.raw())
        ct = data["buckets"][self.alice.user_id]["ct"]
        data["buckets"][self.alice.user_id]["ct"] = ("A" if ct[0] != "A" else "B") + ct[1:]
        self.tasks_file.write_text(json.dumps(data), encoding="utf-8")
        self.reload()
        with self.assertRaises(VaultError) as cm:
            self.vault.load_user(self.alice.user_id, self.alice.keys)
        self.ok(f"Підміну виявлено → VaultError: {cm.exception}")

    def test_bucket_cannot_be_moved_between_users(self):
        """AT-32. Відро Alice, підкладене під id Bob, не розшифровується (AAD)"""
        self.add_task(self.alice)
        data = json.loads(self.raw())
        data["buckets"][self.bob.user_id] = data["buckets"][self.alice.user_id]
        self.tasks_file.write_text(json.dumps(data), encoding="utf-8")
        self.reload()
        with self.assertRaises(VaultError):
            self.vault.load_user(self.bob.user_id, self.bob.keys)
        self.ok("Підкладене відро відхилено")

    def test_other_users_key_cannot_decrypt(self):
        """AT-32. Ключ Bob не розшифровує задачі Alice"""
        self.add_task(self.alice)
        with self.assertRaises(VaultError):
            self.vault.load_user(self.alice.user_id, self.bob.keys)
        self.ok("Криптографічна ізоляція профілів: чужий ключ → відмова")

    def test_corrupt_file_not_overwritten(self):
        """AT-33. Пошкоджений tasks.json: помилка, файл не перезаписується"""
        self.tasks_file.write_text("{ це не json", encoding="utf-8")
        before = self.raw()
        with self.assertRaises(VaultError):
            TaskVault(self.tasks_file)
        self.assertEqual(self.raw(), before)
        self.ok("VaultError, вміст файлу не змінено")

    @unittest.skipIf(os.name == "nt", "POSIX-права")
    def test_file_permissions(self):
        """AT-34. Файли даних і ключів мають права 0600"""
        self.add_task(self.alice)
        for p in (self.tasks_file, self.users, self.devkey):
            mode = p.stat().st_mode & 0o777
            self.say(f"{p.name}: {oct(mode)}")
            self.assertEqual(mode, 0o600)


class KeyProtection(Base):
    def test_users_json_has_no_raw_keys(self):
        """AT-35. У users.json лише загорнуті ключі; сирого DEK немає"""
        data = self.users.read_text(encoding="utf-8")
        import base64
        for s in (self.alice, self.bob):
            raw_b64 = base64.b64encode(s.keys.deks[1]).decode()
            self.assertNotIn(raw_b64, data)
            self.assertNotIn(s.keys.deks[1].hex(), data)
        meta = json.loads(data)["users"][1]["crypto"]
        self.say(f"Bob: режим={meta['mode']}, KDF={meta['kdf']['alg']}, версій DEK={len(meta['keys'])}")
        self.assertEqual(meta["mode"], "password")
        self.assertEqual(json.loads(data)["users"][0]["crypto"]["mode"], "device")

    def test_kek_salt_differs_from_login_hash_salt(self):
        """AT-35. KEK і хеш пароля для входу використовують різні солі"""
        u = json.loads(self.users.read_text(encoding="utf-8"))["users"][1]
        self.say("Хеш для входу не розкриває ключ шифрування")
        self.assertNotEqual(u["password"]["salt"], u["crypto"]["kdf"]["salt"])

    def test_wrong_password_cannot_unlock(self):
        """AT-35. Без правильного пароля DEK не розгортається"""
        meta = self.auth.find("Bob")["crypto"]
        for pw in ("", "wrongpass123"):
            with self.assertRaises(CryptoError):
                self.auth.km.unlock(self.bob.user_id, meta, pw)
        self.ok("Порожній і хибний пароль → CryptoError")

    def test_password_change_rewraps_without_reencrypting(self):
        """AT-36. Зміна пароля: новий KEK і сіль, DEK і дані ті самі"""
        self.add_task(self.bob, "Дані Bob")
        data_before = self.raw()
        salt_before = self.auth.find("Bob")["crypto"]["kdf"]["salt"]
        dek_before = self.bob.keys.deks[1]
        self.auth.change_password(self.bob, PW, "newpassword22")
        self.say(f"Сіль KEK змінилась: {self.auth.find('Bob')['crypto']['kdf']['salt'] != salt_before}")
        self.assertNotEqual(self.auth.find("Bob")["crypto"]["kdf"]["salt"], salt_before)
        self.assertEqual(self.raw(), data_before)
        self.say("tasks.json не змінювався (дані не перешифровувались)")
        self.reload()
        with self.assertRaises(main.AuthError):
            self.auth.login("Bob", PW)
        bob = self.auth.login("Bob", "newpassword22")
        self.assertEqual(bob.keys.deks[1], dek_before)
        self.assertEqual([t["title"] for t in self.vault.load_user(bob.user_id, bob.keys)], ["Дані Bob"])
        self.ok("Старий пароль відхилено, новий відкриває ті самі дані")

    def test_password_set_and_removed_switches_mode(self):
        """AT-36. Задання/зняття пароля перемикає режим захисту DEK (device ↔ password)"""
        self.add_task(self.alice, "Дані Alice")
        self.auth.change_password(self.alice, "", "alicepass123")
        self.say(f"Alice з паролем: режим = {self.auth.find('Alice')['crypto']['mode']}")
        self.assertEqual(self.auth.find("Alice")["crypto"]["mode"], "password")
        self.auth.change_password(self.alice, "alicepass123", "")
        self.say(f"Пароль знято: режим = {self.auth.find('Alice')['crypto']['mode']}")
        self.assertEqual(self.auth.find("Alice")["crypto"]["mode"], "device")
        self.reload()
        a = self.auth.login("Alice")
        self.assertEqual([t["title"] for t in self.vault.load_user(a.user_id, a.keys)], ["Дані Alice"])

    def test_keys_unavailable_after_session_end(self):
        """AT-37. Після виходу або спливу неактивності ключі недоступні"""
        s = self.alice
        s.end()
        with self.assertRaises(AccessDenied):
            s.keys
        self.ok("Завершений сеанс: keys → AccessDenied")
        t = [0.0]
        s2 = Session("x", "x", idle_limit=10, clock=lambda: t[0]); s2.attach_keys(object())
        t[0] = 11
        with self.assertRaises(AccessDenied):
            s2.keys
        self.ok("Прострочений сеанс: keys → AccessDenied")

    def test_missing_device_key_is_not_silently_recreated(self):
        """AT-37. Втрата device.key не призводить до тихого створення нового ключа"""
        self.devkey.unlink()
        with self.assertRaises(main.AuthFileError) as cm:
            self.reload()
        self.assertFalse(self.devkey.exists())
        self.ok(f"Запуск відхилено, нового ключа не створено: {str(cm.exception).splitlines()[0]}")


class Rotation(Base):
    def test_dek_rotation_with_crash_points(self):
        """AT-38. Ротація DEK: дані читаються після кожного кроку, навіть при збої між ними"""
        svc = self.add_task(self.bob, "Дані Bob")
        tasks = svc.list(self.bob)
        old_dek = self.bob.keys.deks[1]

        keys = self.auth.rotate_dek(self.bob)                       # крок 1
        self.say(f"Крок 1: версій DEK = {sorted(keys.deks)}, поточна = {keys.cur}; tasks.json ще зі старим ключем")
        self.reload(); b = self.auth.login("Bob", PW)
        self.assertEqual(len(self.vault.load_user(b.user_id, b.keys)), 1)
        self.ok("Збій після кроку 1: дані читаються")

        self.vault.save_user(self.bob.user_id, self.bob.keys, tasks)  # крок 2
        self.assertEqual(self.vault.buckets[self.bob.user_id]["kver"], 2)
        self.reload(); b = self.auth.login("Bob", PW)
        self.assertEqual(len(self.vault.load_user(b.user_id, b.keys)), 1)
        self.ok("Збій після кроку 2: дані читаються")

        self.auth.finish_dek_rotation(self.bob)                     # крок 3
        self.reload(); b = self.auth.login("Bob", PW)
        self.say(f"Крок 3: лишилась версія DEK {sorted(b.keys.deks)}")
        self.assertEqual(sorted(b.keys.deks), [2])
        self.assertEqual(len(self.vault.load_user(b.user_id, b.keys)), 1)
        bucket = self.vault.buckets[b.user_id]
        with self.assertRaises(CryptoError):
            open_sealed(old_dek, bucket, TaskVault._aad(b.user_id, 2))
        self.ok("Старий DEK більше не розшифровує дані")

    def test_rotate_dek_helper(self):
        """AT-38. Повна ротація DEK одним викликом"""
        svc = self.add_task(self.alice, "X")
        main.rotate_dek(self.auth, self.vault, self.alice, svc.list(self.alice))
        self.assertEqual(sorted(self.alice.keys.deks), [2])
        self.assertEqual(self.vault.buckets[self.alice.user_id]["kver"], 2)
        self.ok("Версія DEK 1 → 2, дані перешифровано")

    def test_dek_due_by_age(self):
        """AT-38. Строк життя DEK: ротація потрібна через 365 днів"""
        meta = self.auth.find("Alice")["crypto"]
        now = datetime.now()
        self.assertFalse(KeyManager.dek_due(meta, now + timedelta(days=364)))
        self.assertTrue(KeyManager.dek_due(meta, now + timedelta(days=366)))
        self.ok("364 дні — ще ні, 366 днів — так")

    def test_device_key_rotation(self):
        """AT-38. Ротація ключа пристрою: профіль без пароля читає дані, старий ключ видалено"""
        self.add_task(self.alice, "Дані Alice")
        old_kid = json.loads(self.devkey.read_text())["current"]
        self.auth.rotate_device_key()
        info = json.loads(self.devkey.read_text())
        self.say(f"Ключ пристрою: {old_kid} → {info['current']}; у файлі ключів: {list(info['keys'])}")
        self.assertNotEqual(info["current"], old_kid)
        self.assertEqual(list(info["keys"]), [info["current"]])
        self.reload()
        a = self.auth.login("Alice")
        self.assertEqual(self.auth.find("Alice")["crypto"]["kid"], info["current"])
        self.assertEqual([t["title"] for t in self.vault.load_user(a.user_id, a.keys)], ["Дані Alice"])
        b = self.auth.login("Bob", PW)
        self.ok("Alice читає дані; профіль Bob (пароль) не зачеплено")


class Migration(Base):
    def test_plaintext_tasks_encrypted_on_login(self):
        """AT-39. Відкритий tasks.json старого формату шифрується при вході власника"""
        legacy = [dict(TASK, id=1, owner=self.alice.user_id, done=False, reminded=False, title="Старе Alice"),
                  dict(TASK, id=2, owner=self.bob.user_id, done=False, reminded=False, title="Старе Bob"),
                  dict(TASK, id=3, owner=None, done=False, reminded=False, title="Без власника")]
        self.tasks_file.write_text(json.dumps(legacy, ensure_ascii=False), encoding="utf-8")
        self.reload()
        self.say("У файлі зараз відкритий список задач (формат до шифрування)")
        a = self.auth.login("Alice")
        tasks = self.vault.load_user(a.user_id, a.keys, adopt_orphans=True)
        self.say(f"Alice (перший профіль) отримала: {sorted(t['title'] for t in tasks)}")
        self.assertEqual(sorted(t["title"] for t in tasks), ["Без власника", "Старе Alice"])
        data = self.raw()
        self.assertNotIn("Старе Alice".encode(), data)
        self.assertNotIn("Без власника".encode(), data)
        self.say("Задачі Alice й безхазяйна в файлі вже зашифровані; задача Bob чекає на його вхід")
        b = self.auth.login("Bob", PW)
        tasks_b = self.vault.load_user(b.user_id, b.keys)
        self.assertEqual([t["title"] for t in tasks_b], ["Старе Bob"])
        self.assertNotIn("Старе Bob".encode(), self.raw())
        self.assertNotIn("pending", json.loads(self.raw()))
        self.ok("Після входу обох профілів відкритого тексту у файлі не лишилось")

    def test_legacy_profile_gets_keys_on_login(self):
        """AT-39. Профіль зі старого users.json (без ключів) отримує ключі при першому вході"""
        for u in self.auth.users:                       # імітуємо профілі до версії 1.3
            u.pop("crypto")
        self.auth._save()
        self.reload()
        self.assertIsNone(self.auth.find("Alice").get("crypto"))
        a = self.auth.login("Alice"); b = self.auth.login("Bob", PW)
        self.assertEqual(self.auth.find("Alice")["crypto"]["mode"], "device")
        self.assertEqual(self.auth.find("Bob")["crypto"]["mode"], "password")
        self.ok("Ключі створено: Alice — device, Bob — password")


class AppGlue(Base):
    def _app(self):
        app = object.__new__(main.TodoApp)       # без Tk: перевіряємо лише зв'язок входу з сховищем
        app.auth, app.vault = self.auth, self.vault
        return app

    def test_login_flow_opens_vault_and_rotates(self):
        """AT-39b. Вхід у застосунку: розшифрування задач і автоматична ротація DEK за строком"""
        self.add_task(self.alice, "Задача входу")
        self.reload()
        app = self._app()
        a = self.auth.login("Alice")
        tasks = app._open_vault(a)
        self.say(f"_open_vault повернув: {[t['title'] for t in tasks]}")
        self.assertEqual([t["title"] for t in tasks], ["Задача входу"])
        self.auth.dek_due = lambda s: True            # імітуємо, що строк DEK минув
        app._rotate_dek_if_due(a, tasks)
        self.say(f"Після входу версії DEK: {sorted(a.keys.deks)}, відро у версії {self.vault.buckets[a.user_id]['kver']}")
        self.assertEqual(sorted(a.keys.deks), [2])
        self.reload()
        a2 = self.auth.login("Alice")
        self.assertEqual(len(self.vault.load_user(a2.user_id, a2.keys)), 1)
        self.ok("Після ротації й перезапуску дані читаються")


if __name__ == "__main__":
    unittest.main(verbosity=1)
