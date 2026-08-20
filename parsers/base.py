from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass
class ParsedProxy:
    name: str
    data: dict[str, Any]

class BaseParser(ABC):
    protocol: str = ''

    @classmethod
    @abstractmethod
    def parse(cls, raw: str) -> ParsedProxy:
        pass
