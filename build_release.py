"""Пакування «лише байткод» для розповсюдження (не входить до складу самої програми).

  python build_release.py [--out ДИРЕКТОРІЯ]

Компілює захищені модулі в .pyc (без оптимізації, щоб asserts і docstring-перевірки не губились),
прибирає .py з дистрибутива й додає тонкий запускач run.py (єдиний файл, що лишається відкритим
текстом). Підписані файли (MANIFEST.json, MANIFEST.sig, release_public.key, license_public.key)
копіюються як є: вони мають залишатися саме тими байтами, які підписав sign_release.py.

Це піднімає поріг СТАТИЧНОГО читання (потрібен декомпілятор на кшталт decompyle3, і не кожна
конструкція відновлюється точно), але НЕ є стійким захистом: байткод CPython залишається
достатньо прозорим для досвідченого аналітика, а ДИНАМІЧНИЙ аналіз (dis, трасування під час
виконання) бачить код так само, як і джерело. Докладніше й чесні межі — zakhyst_vid_reversu.md.
"""
import argparse
import py_compile
import shutil
import sys
from pathlib import Path

from integrity import MANIFEST, PROTECTED, PUBLIC_KEY, SIGNATURE
from licensing import LICENSE_PUBLIC

APP_DIR = Path(__file__).resolve().parent
COMPILED = [n for n in PROTECTED if n.endswith(".py")]           # requirements.txt копіюється як є
PLAIN_COPY = [n for n in PROTECTED if not n.endswith(".py")] + [MANIFEST, SIGNATURE, PUBLIC_KEY, LICENSE_PUBLIC]

RUN_PY = '''"""Запускач байткодового дистрибутива: єдиний файл, що лишається відкритим текстом."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import main  # noqa: E402  (main.pyc поруч; .py немає)

if __name__ == "__main__":
    sys.exit(main.main())
'''


def build(app_dir, out_dir):
    app_dir, out_dir = Path(app_dir), Path(out_dir)
    dist = out_dir / "planuvalnyk_dist"
    shutil.rmtree(dist, ignore_errors=True)
    dist.mkdir(parents=True)

    compiled, missing = [], []
    for name in COMPILED:
        src = app_dir / name
        if not src.exists():
            missing.append(name)
            continue
        target = dist / (Path(name).stem + ".pyc")
        py_compile.compile(str(src), cfile=str(target), doraise=True, optimize=0)
        compiled.append(target.name)
    if missing:
        raise SystemExit(f"Відсутні файли джерела: {missing}")

    copied = []
    for name in PLAIN_COPY:
        src = app_dir / name
        if src.exists():
            shutil.copy2(src, dist / name)
            copied.append(name)

    (dist / "run.py").write_text(RUN_PY, encoding="utf-8")
    return dist, compiled, copied


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(APP_DIR))
    a = ap.parse_args()
    dist, compiled, copied = build(APP_DIR, a.out)
    print(f"Дистрибутив: {dist}\n.pyc: {', '.join(compiled)}\nСкопійовано як є: {', '.join(copied)}\n"
          f"Запуск: python {dist / 'run.py'} --version")
    return 0


if __name__ == "__main__":
    sys.exit(main())
