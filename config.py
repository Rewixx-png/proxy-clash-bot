"""Конфигурация бота из переменных окружения (.env)."""
import logging
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

BOT_TOKEN: str = os.getenv("BOT_TOKEN", "").strip()
LOG_LEVEL: int = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
# Максимум прокси в выдаче: FLClash/Clash-клиенты не тянут десятки тысяч
# нод (getProxies умирает по таймауту). Поднимите в .env, если нужно больше.
MAX_PROXIES: int = int(os.getenv("MAX_PROXIES", "2000"))

if not BOT_TOKEN:
    raise RuntimeError(
        "BOT_TOKEN не задан. Создайте файл .env с BOT_TOKEN=<токен> "
        "(см. .env.example) и перезапустите бота."
    )
