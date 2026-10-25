"""Версія й ідентифікатор продукту (входить до підписаного маніфесту)."""
APP_VERSION = "1.5.0"
PRODUCT = "planuvalnyk"


def version_tuple(text):
    return tuple(int(x) for x in str(text).split("."))


def major(text=APP_VERSION):
    return version_tuple(text)[0]
