import json
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
from pathlib import Path

DATA_FILE = Path(__file__).with_name("tasks.json")
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


# ---------------------------------------------------------------- сховище
def load_tasks():
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            messagebox.showwarning("Помилка", "Не вдалося прочитати tasks.json, починаємо з порожнього списку.")
    return []


def save_tasks(tasks):
    DATA_FILE.write_text(json.dumps(tasks, ensure_ascii=False, indent=2), encoding="utf-8")


# ---------------------------------------------------------------- додаток
class TodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Планувальник справ")
        self.root.geometry("900x560")
        self.root.minsize(780, 480)

        self.tasks = load_tasks()
        self.editing_id = None

        self.title_var = tk.StringVar()
        self.date_var = tk.StringVar()
        self.time_var = tk.StringVar()
        self.priority_var = tk.StringVar(value="Середній")
        self.reminder_var = tk.StringVar(value="За 15 хв")
        self.sort_var = tk.StringVar(value="deadline")
        self.show_done_var = tk.BooleanVar(value=True)

        self._build_ui()
        self._reset_form()
        self.refresh()
        self.check_reminders()

    # ------------------------------------------------------------ інтерфейс
    def _build_ui(self):
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
            "reminded": False,
        }

        if self.editing_id is None:
            data["id"] = max((t["id"] for t in self.tasks), default=0) + 1
            data["done"] = False
            self.tasks.append(data)
        else:
            task = self._find(self.editing_id)
            task.update(data)

        save_tasks(self.tasks)
        self._reset_form()
        self.refresh()

    # ------------------------------------------------------------ дії
    def _find(self, task_id):
        return next(t for t in self.tasks if t["id"] == task_id)

    def _selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Підказка", "Спочатку виберіть завдання у списку.")
            return None
        return self._find(int(sel[0]))

    def toggle_done(self):
        task = self._selected()
        if task:
            task["done"] = not task["done"]
            save_tasks(self.tasks)
            self.refresh()

    def start_edit(self):
        task = self._selected()
        if not task:
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
        task = self._selected()
        if task and messagebox.askyesno("Видалення", f"Видалити «{task['title']}»?"):
            self.tasks.remove(task)
            save_tasks(self.tasks)
            if self.editing_id == task["id"]:
                self._reset_form()
            self.refresh()

    # ------------------------------------------------------------ відображення
    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        now = datetime.now()

        tasks = [t for t in self.tasks if self.show_done_var.get() or not t["done"]]
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

        active = sum(1 for t in self.tasks if not t["done"])
        overdue = sum(1 for t in self.tasks
                      if not t["done"] and datetime.strptime(t["deadline"], DT_FMT) < now)
        self.status.config(text=f"Усього: {len(self.tasks)} | Активних: {active} | Прострочених: {overdue}")

    # ------------------------------------------------------------ нагадування
    def check_reminders(self):
        now = datetime.now()
        fired = False
        for t in self.tasks:
            if t["done"] or t.get("reminded") or t["remind_minutes"] is None:
                continue
            deadline = datetime.strptime(t["deadline"], DT_FMT)
            if now >= deadline - timedelta(minutes=t["remind_minutes"]):
                t["reminded"] = True
                fired = True
                self.root.bell()
                left = deadline - now
                if left.total_seconds() > 0:
                    mins = int(left.total_seconds() // 60)
                    when = f"Залишилось ≈ {mins // 60} год {mins % 60} хв"
                else:
                    when = "Дедлайн уже минув!"
                messagebox.showinfo("Нагадування",
                                    f"{t['title']}\nДедлайн: {deadline.strftime('%d.%m.%Y %H:%M')}\n{when}")
        if fired:
            save_tasks(self.tasks)
        self.refresh()
        self.root.after(15_000, self.check_reminders)  # перевірка кожні 15 секунд


if __name__ == "__main__":
    root = tk.Tk()
    TodoApp(root)
    root.mainloop()