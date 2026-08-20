"""Базовые типы парсеров прокси-ссылок."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ParsedProxy:
    """Результат разбора одной ссылки: имя прокси + словарь для YAML."""
    name: str
    data: dict[str, Any]


class BaseParser(ABC):
    """Контракт парсера прокси-ссылок.

    Чтобы добавить новый протокол (VMess, Trojan, Shadowsocks):
      1. Создайте parsers/<proto>.py с подклассом BaseParser.
      2. Задайте protocol (схема ссылки) и реализуйте parse().
      3. Зарегистрируйте класс в parsers/__init__.py.
    """

    protocol: str = ""

    @classmethod
    @abstractmethod
    def parse(cls, raw: str) -> ParsedProxy:
        """Разбирает сырую ссылку.

        Возвращает ParsedProxy; при ошибке бросает ValueError
        с человекочитаемой причиной (попадёт в статистику «Пропущено»).
        """
