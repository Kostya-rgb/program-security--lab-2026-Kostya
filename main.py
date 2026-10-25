import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from pathlib import Path

from access_control import AccessDenied, Session, authorize, is_allowed
from crypto_store import CryptoError, KeyManager, TaskVault, VaultError, write_json_private

DATA_FILE = Path(__file__).with_name("tasks.json")
USERS_FILE = Path(__file__).with_name("users.json")
DEVICE_KEY_FILE = Path(__file__).with_name("device.key")
DT_FMT = "%Y-%m-%d %H:%M"

PRIORITIES = {"Високий": 0, "Середній": 1, "Низький": 2}
REMINDERS = {
    "Без нагадування": None,
    "За 5 хв": 5,
    "За 15 хв": 15,
    "За 30 хв": 30,
    "За 1 год": 60,
    "За 1 день": 1440,
}
REMINDER_BY_VALUE = {v: k for k, v in REMINDERS.items()}

# ---------------------------------------------------------------- параметри автентифікації
USERNAME_RE = re.compile(r"[\w.\-]{3,32}")   # літери, цифри, _ - .
PASSWORD_MIN, PASSWORD_MAX = 8, 128
MAX_FAILED = 5            # невдалих спроб до блокування
LOCK_SECONDS = 60         # тривалість блокування
IDLE_SECONDS = 15 * 60    # автовихід для облікових записів із паролем
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
SCRYPT_MAXMEM = 64 * 1024 * 1024


# ---------------------------------------------------------------- сховище
def write_json_atomic(path, data):
    """Атомарний запис: тимчасовий файл (одразу з правами 0600) + заміна."""
    write_json_private(path, data)


# ---------------------------------------------------------------- операції над задачами (з перевіркою прав)
class TaskService:
    """Єдина точка доступу до задач. Кожна операція викликає authorize() безпосередньо
    перед виконанням; назовні віддаються лише копії, тож змінити дані в обхід
    операцій неможливо. Поле owner задає лише сервіс (із сеансу), а не введення."""

    def __init__(self, tasks, save=None):
        self._tasks = tasks
        self._save = save or (lambda tasks: None)   # save: шифрує й записує задачі профілю

    @staticmethod
    def _clean(data):
        title = str(data.get("title", "")).strip()
        if not title:
            raise ValueError("Введіть назву завдання.")
        try:
            deadline = datetime.strptime(str(data.get("deadline", "")), DT_FMT)
        except ValueError:
            raise ValueError("Невірний формат дати або часу.")
        priority = data.get("priority")
        if not (isinstance(priority, str) and priority in PRIORITIES):
            raise ValueError("Невірний пріоритет.")
        remind = data.get("remind_minutes")
        if remind not in REMINDERS.values():
            raise ValueError("Невірне значення нагадування.")
        return {"title": title, "deadline": deadline.strftime(DT_FMT),
                "priority": priority, "remind_minutes": remind}

    def _get(self, session, task_id, action):
        task = next((t for t in self._tasks if isinstance(t, dict) and t.get("id") == task_id), None)
        authorize(session, action, task)   # відсутня й чужа задачі невідрізнимі: існування не розкривається
        return task

    def list(self, session):
        authorize(session, "task:list")
        return [dict(t) for t in self._tasks if is_allowed(session, "task:read", t)]

    def get(self, session, task_id):
        return dict(self._get(session, task_id, "task:read"))

    def create(self, session, data):
        authorize(session, "task:create")
        task = self._clean(data)
        task.update(id=max((t.get("id", 0) for t in self._tasks if isinstance(t, dict)), default=0) + 1,
                    owner=session.user_id, done=False, reminded=False)
        self._tasks.append(task)
        self._save(self._tasks)
        return dict(task)

    def update(self, session, task_id, data):
        task = self._get(session, task_id, "task:update")
        task.update(self._clean(data))
        task["reminded"] = False
        self._save(self._tasks)
        return dict(task)

    def toggle_done(self, session, task_id):
        task = self._get(session, task_id, "task:toggle")
        task["done"] = not task["done"]
        self._save(self._tasks)
        return dict(task)

    def delete(self, session, task_id):
        task = self._get(session, task_id, "task:delete")
        self._tasks.remove(task)
        self._save(self._tasks)

    def mark_reminded(self, session, task_id):
        task = self._get(session, task_id, "task:remind")
        task["reminded"] = True
        self._save(self._tasks)

    def claim_legacy(self, session, first_user_id):
        """Задачі старого формату (без owner) отримує лише перший створений профіль."""
        claimed = 0
        for t in self._tasks:
            if is_allowed(session, "task:claim_legacy", t, first_user_id=first_user_id):
                t["owner"] = session.user_id
                claimed += 1
        if claimed:
            self._save(self._tasks)
        return claimed


# ---------------------------------------------------------------- ідентифікація та автентифікація
class AuthError(Exception):
    """Помилка, текст якої безпечно показувати користувачу."""


class AuthFileError(Exception):
    """users.json пошкоджено або недоступний (програма не запускається: fail-closed)."""


class AuthService:
    """Користувачі: ідентифікація за іменем, необов'язковий пароль (scrypt + сіль)."""

    def __init__(self, path, device_key_path=None):
        self.path = path
        self.km = KeyManager(device_key_path or path.with_name("device.key"))
        self.users = self._load()

    def _load(self):
        if not self.path.exists():
            return []
        try:
            users = json.loads(self.path.read_text(encoding="utf-8"))["users"]
            if not isinstance(users, list) or not all(
                    isinstance(u, dict) and isinstance(u["id"], str) and isinstance(u["username"], str)
                    for u in users):
                raise ValueError
            return users
        except (OSError, ValueError, KeyError, TypeError):
            raise AuthFileError(
                f"Файл {self.path.name} пошкоджено або недоступний.\n"
                "Відновіть його з резервної копії або перемістіть вручну, щоб створити нових користувачів.")

    def _save(self):
        write_json_atomic(self.path, {"version": 1, "users": self.users})

    # -- допоміжні
    def usernames(self):
        return sorted((u["username"] for u in self.users), key=str.casefold)

    def find(self, username):
        key = (username or "").strip().casefold()
        return next((u for u in self.users if u["username"].casefold() == key), None)

    def has_password(self, username):
        user = self.find(username)
        return bool(user and user.get("password"))

    @staticmethod
    def _session(user, keys):
        limit = IDLE_SECONDS if user.get("password") else None
        session = Session(user["id"], user["username"], idle_limit=limit)
        session.attach_keys(keys)
        return session

    def _unlock(self, user, password):
        """Ключі профілю; для профілю зі старої версії (без ключів) створюються при першому вході."""
        try:
            if user.get("crypto") is None:
                user["crypto"], keys = self.km.create(user["id"], password if user.get("password") else "")
                self._save()
                return keys
            return self.km.unlock(user["id"], user["crypto"], password if user.get("password") else "")
        except CryptoError as e:
            raise AuthError(f"Ключі шифрування недоступні: {e}")

    def first_user_id(self):
        return self.users[0]["id"] if self.users else None

    @staticmethod
    def _make_hash(password):
        if not PASSWORD_MIN <= len(password) <= PASSWORD_MAX:
            raise AuthError(f"Пароль: від {PASSWORD_MIN} до {PASSWORD_MAX} символів.")
        salt = secrets.token_bytes(16)
        digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32,
                                maxmem=SCRYPT_MAXMEM, **SCRYPT)
        return {"alg": "scrypt", **SCRYPT, "salt": salt.hex(), "hash": digest.hex()}

    @staticmethod
    def _verify(password, rec):
        try:
            salt, expected = bytes.fromhex(rec["salt"]), bytes.fromhex(rec["hash"])
            actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=rec["n"], r=rec["r"],
                                    p=rec["p"], dklen=len(expected), maxmem=SCRYPT_MAXMEM)
        except (KeyError, ValueError, TypeError, MemoryError):
            return False
        return hmac.compare_digest(actual, expected)

    # -- сценарії
    def register(self, username, password="", session=None):
        authorize(session, "profile:register")
        username = (username or "").strip()
        if not USERNAME_RE.fullmatch(username):
            raise AuthError("Ім'я: 3–32 символи — літери, цифри, «_», «-», «.».")
        if self.find(username):
            raise AuthError("Користувач із таким іменем уже існує.")
        record = {
            "id": secrets.token_hex(8),   # випадковий: не використовується повторно
            "username": username,
            "created": datetime.now().strftime(DT_FMT),
            "password": self._make_hash(password) if password else None,
            "failed": 0,
            "locked_until": 0,
        }
        try:
            record["crypto"], keys = self.km.create(record["id"], password)
        except CryptoError as e:
            raise AuthError(f"Не вдалося створити ключі шифрування: {e}")
        self.users.append(record)
        self._save()
        return self._session(record, keys)

    def _check_password(self, user, password):
        """Перевірка пароля з лічильником спроб і блокуванням (без пароля — пропускає)."""
        rec = user.get("password")
        if not rec:
            return
        now = time.time()
        if user.get("locked_until", 0) > now:
            raise AuthError(f"Забагато невдалих спроб. Спробуйте через {int(user['locked_until'] - now) + 1} с.")

        if self._verify(password or "", rec):
            if user.get("failed") or user.get("locked_until"):
                user["failed"], user["locked_until"] = 0, 0
                self._save()
            return

        user["failed"] = user.get("failed", 0) + 1
        if user["failed"] >= MAX_FAILED:
            user["failed"], user["locked_until"] = 0, now + LOCK_SECONDS
        self._save()
        raise AuthError("Невірний пароль.")

    def login(self, username, password="", session=None):
        authorize(session, "profile:login")
        user = self.find(username)
        if user is None:
            raise AuthError("Виберіть користувача зі списку.")
        self._check_password(user, password)
        return self._session(user, self._unlock(user, password))

    def change_password(self, session, current, new):
        """Задати, змінити (new непорожній) або прибрати (new порожній) пароль. Лише власник профілю."""
        user = next((u for u in self.users if session is not None and u["id"] == session.user_id), None)
        authorize(session, "profile:password", user)
        self._check_password(user, current)        # перевірка поточного пароля + блокування
        new_hash = self._make_hash(new) if new else None
        try:
            # лише обгортка DEK під новий KEK (нова сіль); дані задач не перешифровуються
            user["crypto"], keys = self.km.rewrap(user["id"], user["crypto"], session.keys, new)
        except CryptoError as e:
            raise AuthError(f"Не вдалося оновити ключі шифрування: {e}")
        user["password"] = new_hash
        user["failed"], user["locked_until"] = 0, 0
        self._save()
        session.attach_keys(keys)
        session.idle_limit = IDLE_SECONDS if user["password"] else None

    # -- ротація ключів
    def rotate_dek(self, session):
        """Крок 1 ротації DEK: нова версія додається поруч зі старою. Повертає нові ключі."""
        user = next((u for u in self.users if session is not None and u["id"] == session.user_id), None)
        authorize(session, "profile:password", user)
        user["crypto"], keys = self.km.add_version(user["id"], user["crypto"], session.keys)
        self._save()
        session.attach_keys(keys)
        return keys

    def finish_dek_rotation(self, session):
        """Крок 3: після перешифрування даних стара версія DEK видаляється."""
        user = next((u for u in self.users if session is not None and u["id"] == session.user_id), None)
        authorize(session, "profile:password", user)
        user["crypto"], keys = self.km.prune(user["id"], user["crypto"], session.keys)
        self._save()
        session.attach_keys(keys)

    def dek_due(self, session):
        user = next((u for u in self.users if u["id"] == session.user_id), None)
        return bool(user and user.get("crypto") and self.km.dek_due(user["crypto"]))

    def rotate_device_key(self):
        """Ротація ключа пристрою (запуск без графічного інтерфейсу): профілі без пароля отримують
        нові обгортки DEK; users.json зберігається до видалення старого ключа."""
        used = self.km.rotate_device(self.users)
        self._save()
        self.km.device.retire(used)


# ---------------------------------------------------------------- екрани входу
class AuthScreen(ttk.Frame):
    """Вибір імені користувача (+ пароль, якщо задано) або створення нового користувача."""

    def __init__(self, master, auth, on_success, notice=""):
        super().__init__(master, padding=20)
        self.auth, self.on_success, self.notice = auth, on_success, notice
        self.name_var = tk.StringVar()
        self.pw_var = tk.StringVar()
        self.pw2_var = tk.StringVar()
        self.pack(expand=True)
        self._show_login() if auth.usernames() else self._show_register()

    def _reset(self, title):
        for w in self.winfo_children():
            w.destroy()
        self.pw_var.set("")
        self.pw2_var.set("")
        ttk.Label(self, text=title, font=("TkDefaultFont", 14, "bold")).grid(
            row=0, column=0, columnspan=2, pady=(0, 10))
        if self.notice:
            ttk.Label(self, text=self.notice, foreground="#c62828").grid(row=1, column=0, columnspan=2, pady=(0, 8))

    # -- вхід
    def _show_login(self):
        self._reset("Вхід")
        names = self.auth.usernames()
        self.name_var.set(names[0])
        ttk.Label(self, text="Користувач:").grid(row=2, column=0, sticky="w", pady=4)
        combo = ttk.Combobox(self, textvariable=self.name_var, values=names, state="readonly", width=28)
        combo.grid(row=2, column=1, pady=4)
        combo.bind("<<ComboboxSelected>>", lambda e: self._sync_password_field())

        ttk.Label(self, text="Пароль:").grid(row=3, column=0, sticky="w", pady=4)
        self.pw_entry = ttk.Entry(self, textvariable=self.pw_var, show="•", width=30)
        self.pw_entry.grid(row=3, column=1, pady=4)
        self.pw_entry.bind("<Return>", lambda e: self._login())

        btns = ttk.Frame(self)
        btns.grid(row=4, column=0, columnspan=2, pady=(12, 0))
        ttk.Button(btns, text="Увійти", command=self._login).pack(side="left", padx=5)
        ttk.Button(btns, text="Новий користувач", command=self._show_register).pack(side="left", padx=5)
        self._sync_password_field()

    def _sync_password_field(self):
        self.pw_var.set("")
        if self.auth.has_password(self.name_var.get()):
            self.pw_entry.state(["!disabled"])
            self.pw_entry.focus_set()
        else:
            self.pw_entry.state(["disabled"])

    def _login(self):
        try:
            user = self.auth.login(self.name_var.get(), self.pw_var.get())
        except AuthError as e:
            self.pw_var.set("")
            messagebox.showerror("Вхід", str(e))
            return
        self.on_success(user, False)

    # -- реєстрація
    def _show_register(self):
        self.notice = ""
        self._reset("Новий користувач")
        self.name_var.set("")
        ttk.Label(self, text="Ім'я:").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.name_var, width=30).grid(row=2, column=1, pady=4)
        ttk.Label(self, text="Пароль:").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.pw_var, show="•", width=30).grid(row=3, column=1, pady=4)
        ttk.Label(self, text="Повтор пароля:").grid(row=4, column=0, sticky="w", pady=4)
        ttk.Entry(self, textvariable=self.pw2_var, show="•", width=30).grid(row=4, column=1, pady=4)
        ttk.Label(self, text=f"Пароль необов'язковий (мін. {PASSWORD_MIN} символів). "
                             "Без пароля вхід лише за іменем.",
                  foreground="#666666", wraplength=340).grid(row=5, column=0, columnspan=2, pady=4)

        btns = ttk.Frame(self)
        btns.grid(row=6, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btns, text="Створити", command=self._register).pack(side="left", padx=5)
        if self.auth.usernames():
            ttk.Button(btns, text="Назад", command=self._show_login).pack(side="left", padx=5)

    def _register(self):
        if self.pw_var.get() != self.pw2_var.get():
            messagebox.showerror("Реєстрація", "Паролі не збігаються.")
            return
        first = not self.auth.usernames()
        try:
            user = self.auth.register(self.name_var.get(), self.pw_var.get())
        except AuthError as e:
            messagebox.showerror("Реєстрація", str(e))
            return
        self.on_success(user, first)


class PasswordDialog(tk.Toplevel):
    """Задати / змінити / прибрати пароль поточного користувача."""

    def __init__(self, parent, auth, session):
        super().__init__(parent)
        self.auth, self.session = auth, session
        self.has_password = auth.has_password(session.username)
        self.title("Пароль")
        self.resizable(False, False)
        self.transient(parent)
        self.cur_var, self.new_var, self.rep_var = tk.StringVar(), tk.StringVar(), tk.StringVar()

        frm = ttk.Frame(self, padding=15)
        frm.pack()
        row = 0
        fields = [("Новий пароль:", self.new_var), ("Повтор:", self.rep_var)]
        if self.has_password:
            fields.insert(0, ("Поточний пароль:", self.cur_var))
        for label, var in fields:
            ttk.Label(frm, text=label).grid(row=row, column=0, sticky="w", pady=4)
            ttk.Entry(frm, textvariable=var, show="•", width=28).grid(row=row, column=1, pady=4, padx=(8, 0))
            row += 1
        hint = ("Порожній новий пароль прибирає пароль." if self.has_password
                else f"Мінімум {PASSWORD_MIN} символів.")
        ttk.Label(frm, text=hint, foreground="#666666").grid(row=row, column=0, columnspan=2, pady=4)
        btns = ttk.Frame(frm)
        btns.grid(row=row + 1, column=0, columnspan=2, pady=(8, 0))
        ttk.Button(btns, text="Зберегти", command=self._save).pack(side="left", padx=5)
        ttk.Button(btns, text="Скасувати", command=self.destroy).pack(side="left", padx=5)
        self.grab_set()
        self.wait_window()

    def _save(self):
        if self.new_var.get() != self.rep_var.get():
            messagebox.showerror("Пароль", "Паролі не збігаються.", parent=self)
            return
        try:
            self.auth.change_password(self.session, self.cur_var.get(), self.new_var.get())
        except (AuthError, AccessDenied) as e:
            messagebox.showerror("Пароль", str(e), parent=self)
            return
        messagebox.showinfo("Пароль", "Збережено.", parent=self)
        self.destroy()


# ---------------------------------------------------------------- додаток
class TodoApp:
    def __init__(self, root, auth, vault):
        self.root = root
        self.auth = auth
        self.root.title("Планувальник справ")

        self.vault = vault
        self.service = None         # створюється після входу, містить лише розшифровані задачі власника
        self.session = None         # сеанс: лише в пам'яті, на диск не записується
        self.editing_id = None
        self._after_id = None

        self.title_var = tk.StringVar()
        self.date_var = tk.StringVar()
        self.time_var = tk.StringVar()
        self.priority_var = tk.StringVar(value="Середній")
        self.reminder_var = tk.StringVar(value="За 15 хв")
        self.sort_var = tk.StringVar(value="deadline")
        self.show_done_var = tk.BooleanVar(value=True)

        for seq in ("<Key>", "<Button>", "<Motion>"):
            self.root.bind_all(seq, self._touch, add="+")
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.show_login()

    # ------------------------------------------------------------ сеанс
    def _touch(self, _event=None):
        if self.session is not None:
            self.session.touch()     # прострочений сеанс не відновлюється

    def _end_session(self):
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        if self.session is not None:
            self.session.end()
        self.session = None
        self.service = None         # розшифровані задачі видаляються з пам'яті
        self.editing_id = None

    def _denied(self, err):
        """Реакція на відмову: недійсний сеанс — екран входу, інакше повідомлення."""
        if self.session is None or not self.session.active:
            self.show_login(str(err))
        else:
            messagebox.showerror("Доступ", str(err))

    def _call(self, op, *args):
        """Виклик захищеної операції сервісу; повертає (успіх, результат)."""
        try:
            return True, op(self.session, *args)
        except AccessDenied as e:
            self._denied(e)
            return False, None

    def show_login(self, notice=""):
        self._end_session()
        for w in self.root.winfo_children():
            w.destroy()
        self.root.geometry("420x340")
        self.root.minsize(380, 300)
        AuthScreen(self.root, self.auth, self._on_login, notice)

    def _on_login(self, session, first_user):
        self.session = session
        try:
            tasks = self._open_vault(session)
        except (VaultError, AuthError) as e:
            messagebox.showerror("Помилка", str(e))
            self.show_login()
            return
        self.service = TaskService(tasks, save=lambda t: self.vault.save_user(session.user_id, session.keys, t))
        # задачі з версії без користувачів дістаються першому створеному користувачу
        self.service.claim_legacy(session, self.auth.first_user_id())
        self._rotate_dek_if_due(session, tasks)
        for w in self.root.winfo_children():
            w.destroy()
        self.root.geometry("900x560")
        self.root.minsize(780, 480)
        self._touch()
        self._build_ui()
        self._reset_form()
        self.refresh()
        self.check_reminders()

    def _open_vault(self, session):
        """Розшифрування задач одразу після входу."""
        adopt = session.user_id == self.auth.first_user_id()
        return self.vault.load_user(session.user_id, session.keys, adopt_orphans=adopt)

    def _rotate_dek_if_due(self, session, tasks):
        """Плановий строк життя DEK минув: нова версія -> перешифрування -> видалення старої."""
        try:
            if self.auth.dek_due(session):
                rotate_dek(self.auth, self.vault, session, tasks)
        except (CryptoError, AuthError, AccessDenied) as e:
            messagebox.showwarning("Ключі", f"Ротацію ключа даних відкладено: {e}")

    def change_password(self):
        PasswordDialog(self.root, self.auth, self.session)
        self._touch()

    def quit(self):
        self._end_session()
        self.root.destroy()

    # ------------------------------------------------------------ інтерфейс
    def _build_ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=10, pady=(8, 0))
        ttk.Label(top, text=f"Користувач: {self.session.username}").pack(side="left")
        ttk.Button(top, text="Вийти", command=self.show_login).pack(side="right")
        ttk.Button(top, text="Пароль…", command=self.change_password).pack(side="right", padx=5)

        form = ttk.LabelFrame(self.root, text="Завдання")
        form.pack(fill="x", padx=10, pady=(10, 5))

        ttk.Label(form, text="Назва:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(form, textvariable=self.title_var).grid(row=0, column=1, columnspan=5, sticky="ew", padx=5, pady=5)

        ttk.Label(form, text="Дата (РРРР-ММ-ДД):").grid(row=1, column=0, sticky="w", padx=5)
        ttk.Entry(form, textvariable=self.date_var, width=14).grid(row=1, column=1, sticky="w", padx=5)

        ttk.Label(form, text="Час (ГГ:ХХ):").grid(row=1, column=2, sticky="e", padx=5)
        ttk.Entry(form, textvariable=self.time_var, width=8).grid(row=1, column=3, sticky="w", padx=5)

        ttk.Label(form, text="Пріоритет:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Combobox(form, textvariable=self.priority_var, values=list(PRIORITIES),
                     state="readonly", width=12).grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(form, text="Нагадування:").grid(row=2, column=2, sticky="e", padx=5)
        ttk.Combobox(form, textvariable=self.reminder_var, values=list(REMINDERS),
                     state="readonly", width=16).grid(row=2, column=3, sticky="w", padx=5)

        self.submit_btn = ttk.Button(form, text="Додати", command=self.submit)
        self.submit_btn.grid(row=2, column=4, padx=5)
        self.cancel_btn = ttk.Button(form, text="Скасувати", command=self._reset_form)
        self.cancel_btn.grid(row=2, column=5, padx=5)
        form.columnconfigure(1, weight=1)

        # панель сортування / фільтра
        bar = ttk.Frame(self.root)
        bar.pack(fill="x", padx=10, pady=5)
        ttk.Label(bar, text="Сортування:").pack(side="left")
        ttk.Radiobutton(bar, text="за дедлайном", value="deadline",
                        variable=self.sort_var, command=self.refresh).pack(side="left", padx=5)
        ttk.Radiobutton(bar, text="за пріоритетом", value="priority",
                        variable=self.sort_var, command=self.refresh).pack(side="left", padx=5)
        ttk.Checkbutton(bar, text="Показувати виконані", variable=self.show_done_var,
                        command=self.refresh).pack(side="right")

        # таблиця
        columns = ("done", "title", "deadline", "priority", "reminder")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", selectmode="browse")
        for col, text, width, anchor in [
            ("done", "✓", 40, "center"),
            ("title", "Завдання", 350, "w"),
            ("deadline", "Дедлайн", 130, "center"),
            ("priority", "Пріоритет", 90, "center"),
            ("reminder", "Нагадування", 120, "center"),
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=anchor, stretch=(col == "title"))
        self.tree.tag_configure("done", foreground="#999999")
        self.tree.tag_configure("overdue", foreground="#c62828")
        self.tree.tag_configure("high", font=("TkDefaultFont", 10, "bold"))

        scroll = ttk.Scrollbar(self.root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=5)
        scroll.pack(side="left", fill="y", pady=5)
        self.tree.bind("<Double-1>", lambda e: self.toggle_done())

        # кнопки дій
        actions = ttk.Frame(self.root)
        actions.pack(side="right", fill="y", padx=10, pady=5)
        ttk.Button(actions, text="Виконано / Ні", command=self.toggle_done).pack(fill="x", pady=2)
        ttk.Button(actions, text="Редагувати", command=self.start_edit).pack(fill="x", pady=2)
        ttk.Button(actions, text="Видалити", command=self.delete).pack(fill="x", pady=2)

        self.status = ttk.Label(self.root, text="", anchor="w")
        self.status.pack(side="bottom", fill="x", padx=10)

    # ------------------------------------------------------------ форма
    def _reset_form(self):
        self.editing_id = None
        default = datetime.now().replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
        self.title_var.set("")
        self.date_var.set(default.strftime("%Y-%m-%d"))
        self.time_var.set(default.strftime("%H:%M"))
        self.priority_var.set("Середній")
        self.reminder_var.set("За 15 хв")
        self.submit_btn.config(text="Додати")
        self.cancel_btn.state(["disabled"])

    def submit(self):
        title = self.title_var.get().strip()
        if not title:
            messagebox.showerror("Помилка", "Введіть назву завдання.")
            return
        try:
            deadline = datetime.strptime(f"{self.date_var.get().strip()} {self.time_var.get().strip()}", DT_FMT)
        except ValueError:
            messagebox.showerror("Помилка", "Невірний формат дати або часу.\nПриклад: 2026-10-15 і 18:30")
            return

        data = {
            "title": title,
            "deadline": deadline.strftime(DT_FMT),
            "priority": self.priority_var.get(),
            "remind_minutes": REMINDERS[self.reminder_var.get()],
        }

        try:
            if self.editing_id is None:
                ok, _ = self._call(self.service.create, data)
            else:
                ok, _ = self._call(self.service.update, self.editing_id, data)
        except ValueError as e:
            messagebox.showerror("Помилка", str(e))
            return
        if not ok:
            return
        self._reset_form()
        self.refresh()

    # ------------------------------------------------------------ дії
    def _selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Підказка", "Спочатку виберіть завдання у списку.")
            return None
        return int(sel[0])

    def toggle_done(self):
        task_id = self._selected_id()
        if task_id is not None and self._call(self.service.toggle_done, task_id)[0]:
            self.refresh()

    def start_edit(self):
        task_id = self._selected_id()
        if task_id is None:
            return
        ok, task = self._call(self.service.get, task_id)
        if not ok:
            return
        dt = datetime.strptime(task["deadline"], DT_FMT)
        self.editing_id = task["id"]
        self.title_var.set(task["title"])
        self.date_var.set(dt.strftime("%Y-%m-%d"))
        self.time_var.set(dt.strftime("%H:%M"))
        self.priority_var.set(task["priority"])
        self.reminder_var.set(REMINDER_BY_VALUE.get(task["remind_minutes"], "Без нагадування"))
        self.submit_btn.config(text="Зберегти")
        self.cancel_btn.state(["!disabled"])

    def delete(self):
        task_id = self._selected_id()
        if task_id is None:
            return
        ok, task = self._call(self.service.get, task_id)
        if ok and messagebox.askyesno("Видалення", f"Видалити «{task['title']}»?"):
            if not self._call(self.service.delete, task_id)[0]:   # права перевіряються ще раз перед видаленням
                return
            if self.editing_id == task_id:
                self._reset_form()
            self.refresh()

    # ------------------------------------------------------------ відображення
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        now = datetime.now()
        try:
            mine = self.service.list(self.session)
        except AccessDenied as e:
            self._denied(e)
            return

        tasks = [t for t in mine if self.show_done_var.get() or not t["done"]]
        if self.sort_var.get() == "priority":
            key = lambda t: (t["done"], PRIORITIES[t["priority"]], t["deadline"])
        else:
            key = lambda t: (t["done"], t["deadline"])  # невиконані зверху, за найближчим дедлайном
        tasks.sort(key=key)

        for t in tasks:
            deadline = datetime.strptime(t["deadline"], DT_FMT)
            tags = []
            if t["done"]:
                tags.append("done")
            elif deadline < now:
                tags.append("overdue")
            if t["priority"] == "Високий" and not t["done"]:
                tags.append("high")
            self.tree.insert("", "end", iid=str(t["id"]), tags=tags, values=(
                "✔" if t["done"] else "",
                t["title"],
                deadline.strftime("%d.%m.%Y %H:%M"),
                t["priority"],
                REMINDER_BY_VALUE.get(t["remind_minutes"], "—"),
            ))

        active = sum(1 for t in mine if not t["done"])
        overdue = sum(1 for t in mine
                      if not t["done"] and datetime.strptime(t["deadline"], DT_FMT) < now)
        self.status.config(text=f"Усього: {len(mine)} | Активних: {active} | Прострочених: {overdue}")

    # ------------------------------------------------------------ нагадування
    def check_reminders(self):
        if self.session is None:
            return
        if not self.session.active:
            self.show_login("Сеанс завершено через неактивність.")
            return
        now = datetime.now()
        try:
            for t in self.service.list(self.session):
                if t["done"] or t.get("reminded") or t["remind_minutes"] is None:
                    continue
                deadline = datetime.strptime(t["deadline"], DT_FMT)
                if now >= deadline - timedelta(minutes=t["remind_minutes"]):
                    self.service.mark_reminded(self.session, t["id"])
                    self.root.bell()
                    left = deadline - now
                    if left.total_seconds() > 0:
                        mins = int(left.total_seconds() // 60)
                        when = f"Залишилось ≈ {mins // 60} год {mins % 60} хв"
                    else:
                        when = "Дедлайн уже минув!"
                    messagebox.showinfo("Нагадування",
                                        f"{t['title']}\nДедлайн: {deadline.strftime('%d.%m.%Y %H:%M')}\n{when}")
        except AccessDenied as e:
            self._denied(e)
            return
        self.refresh()
        if self.session is None:
            return
        self._after_id = self.root.after(15_000, self.check_reminders)  # перевірка кожні 15 секунд


def rotate_dek(auth, vault, session, tasks):
    """Ротація DEK профілю. Порядок захищає від втрати даних при збої між кроками:
    1) нова версія ключа поруч зі старою (users.json); 2) перешифрування (tasks.json); 3) видалення старої."""
    keys = auth.rotate_dek(session)
    vault.save_user(session.user_id, keys, tasks)
    auth.finish_dek_rotation(session)


def main():
    if "--rotate-device-key" in sys.argv:        # ротація ключа пристрою без GUI
        try:
            AuthService(USERS_FILE, DEVICE_KEY_FILE).rotate_device_key()
        except (AuthFileError, CryptoError) as e:
            print(f"Помилка: {e}")
            return 1
        print("Ключ пристрою замінено.")
        return 0
    root = tk.Tk()
    try:
        auth = AuthService(USERS_FILE, DEVICE_KEY_FILE)
        vault = TaskVault(DATA_FILE)
    except (AuthFileError, VaultError) as e:
        root.withdraw()
        messagebox.showerror("Помилка", str(e))
        root.destroy()
        return 1
    TodoApp(root, auth, vault)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())