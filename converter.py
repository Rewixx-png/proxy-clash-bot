"""Пакетный разбор входящего текста и генерация YAML (секция proxies).

YAML собирается собственным эмиттером, а не PyYAML: safe_dump на
~28k прокси тратит ~50 секунд, ручной эмиттер — доли секунды.
Схема данных известна (строки/числа/булевы/списки/словари), поэтому
квотирование сводится к одной эвристике для строк.
"""
import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from parsers import PROTOCOL_PARSERS

logger = logging.getLogger(__name__)

# Все схемы, которые встречаются в подписках (поддерживаемые и ещё нет).
# Неподдерживаемые протоколы честно уходят в статистику «Пропущено».
_LINK_RE = re.compile(
    r"\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard|wg|socks5|socks5h|socks|http|https|anytls)://[^\s]+",
    re.IGNORECASE,
)

# Пунктуация, которая может приклеиться к ссылке (конец строки, кавычки).
_TRAILING_JUNK = ".,;:!?\"'<>()[]{}\\`"


@dataclass
class ConvertResult:
    """Результат пакетного разбора входных данных."""
    proxies: list[dict[str, Any]] = field(default_factory=list)
    total_lines: int = 0
    ok: int = 0
    skipped: int = 0


async def parse_batch(
    text: str,
    on_progress: Callable[[int, int, int], None] | None = None,
    chunk_size: int = 200,
) -> ConvertResult:
    """Извлекает прокси-ссылки из текста и разбирает их.

    Вход дробится на порции по chunk_size строк; после каждой порции
    вызывается on_progress(pct, processed, total) с реальным процентом
    обработанных строк — прогресс-бар привязан к фактической работе,
    а не к таймеру. Между порциями отдаётся управление циклу событий.

    «Получено строк» — число непустых строк. Битые ссылки и
    неподдерживаемые протоколы попадают в счётчик skipped с записью
    причины в лог. Точные дубликаты ссылок отбрасываются; у прокси с
    одинаковым именем имя делается уникальным (Clash это требует).
    """
    lines = [ln.strip() for ln in text.splitlines()]
    total = sum(1 for ln in lines if ln)
    result = ConvertResult(total_lines=total)
    seen: set[str] = set()  # точные дубликаты ссылок
    used_names: set[str] = set()  # имена, занятые в итоговом списке
    processed = 0

    for start in range(0, len(lines), chunk_size):
        for line_no, line in enumerate(lines[start : start + chunk_size], start=start + 1):
            if not line:
                continue
            processed += 1
            for match in _LINK_RE.finditer(line):
                raw = match.group(0).rstrip(_TRAILING_JUNK)
                scheme = raw.split(":", 1)[0].lower()
                try:
                    parser_cls = PROTOCOL_PARSERS.get(scheme)
                    if parser_cls is None:
                        raise ValueError(f"протокол '{scheme}' пока не поддерживается")
                    if raw in seen:
                        raise ValueError("дубликат ссылки")
                    seen.add(raw)
                    proxy = parser_cls.parse(raw).data
                    # Уникальные имена: одинаковые (разные серверы/параметры)
                    # получают суффикс « #2», « #3», ...
                    name = proxy["name"]
                    if name in used_names:
                        base, i = name, 2
                        while f"{base} #{i}" in used_names:
                            i += 1
                        proxy["name"] = f"{base} #{i}"
                    used_names.add(proxy["name"])
                    result.proxies.append(proxy)
                except Exception as exc:
                    result.skipped += 1
                    logger.warning("Строка %d: пропущена ссылка (%s): %s", line_no, scheme, exc)
        if on_progress and processed:
            on_progress(round(processed / total * 100), processed, total)
        await asyncio.sleep(0)  # отдать цикл событий между порциями

    result.ok = len(result.proxies)
    return result


# --- Собственный YAML-эмиттер (быстрее PyYAML в десятки раз) ---

# Строки из этих символов можно писать без кавычек (безопасный plain-скаляр).
# Без '@' — он не может начинать plain-скаляр в YAML (ошибка libyaml,
# её же выдаёт FLClash).
_SAFE_PLAIN = re.compile(r"^[A-Za-z0-9_./~-]+$")
# Числоподобные строки («10575») кавычим, чтобы остались строками.
_NUMERIC = re.compile(r"^-?\d+(\.\d+)?$")
# Паттерны, которые yaml.v2/v3 (mihomo) резолвит как числа/даты даже без
# точки: «9715e9» -> float 9.715e+12, «0x1F» -> int, «2026-08-11» -> дата.
# Если такое попадёт в поле short-id/public-key/имя, mihomo получит число
# и уронит весь конфиг («invalid REALITY short ID» и т.п.).
_YAML_NUMERIC_LIKE = re.compile(
    r"^[-+]?(\d[\d_]*\.?\d*|\.\d+)([eE][-+]?\d+)?$"  # int/float/экспонента
    r"|^0[xX][0-9a-fA-F_]+$|^0[oO][0-7_]+$|^0[bB][01_]+$"  # 0x / 0o / 0b
    r"|^0[0-7]+$"  # ведущий ноль — восьмеричное (yaml.v2)
)
_DATE_LIKE = re.compile(r"^\d{4}-\d{1,2}-\d{1,2}([Tt ].*)?$")
_YAML_RESERVED = {
    "true", "false", "null", "yes", "no", "on", "off", "~",
    "inf", "infinity", "nan",  # yaml.v2 резолвит их через ParseFloat
}


def _needs_quotes(s: str) -> bool:
    """True, если строка в plain-виде будет прочитана YAML-парсером не как строка."""
    return (
        not s
        or not _SAFE_PLAIN.fullmatch(s)
        or s.lower() in _YAML_RESERVED
        or _NUMERIC.fullmatch(s)
        or _YAML_NUMERIC_LIKE.match(s)
        or _DATE_LIKE.match(s)
    )


def _scalar(value: Any) -> str:
    """Превращает значение в YAML-скаляр с минимальным квотированием."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    s = str(value)
    if not _needs_quotes(s):
        return s
    parts = []
    for ch in s:
        if ch == "\\":
            parts.append("\\\\")
        elif ch == '"':
            parts.append('\\"')
        elif ch == "\n":
            parts.append("\\n")
        elif ch == "\t":
            parts.append("\\t")
        elif ch.isprintable():
            parts.append(ch)
        else:
            parts.append(f"\\u{ord(ch):04x}")
    return '"' + "".join(parts) + '"'


def _emit(out: list[str], data: Any, indent: int) -> None:
    """Печатает dict/list/скаляр с отступами по 2 пробела (стиль Clash)."""
    pad = "  " * indent
    if isinstance(data, dict):
        for key, value in data.items():
            prefix = f"{pad}{key}"
            if isinstance(value, (dict, list)):
                out.append(prefix + ":")
                _emit(out, value, indent + 1)
            else:
                out.append(prefix + ": " + _scalar(value))
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                _emit_list_item(out, value, indent)
            elif isinstance(value, list):
                out.append(f"{pad}-")
                _emit(out, value, indent + 1)
            else:
                out.append(f"{pad}- {_scalar(value)}")
    else:
        out.append(f"{pad}- {_scalar(data)}")


def _emit_list_item(out: list[str], data: dict, indent: int) -> None:
    """Словарь-элемент списка: первый ключ идёт за '- ', остальные — глубже."""
    inner = "  " * (indent + 1)
    for i, (key, value) in enumerate(data.items()):
        prefix = f"{'  ' * indent}- {key}" if i == 0 else f"{inner}{key}"
        if isinstance(value, (dict, list)):
            out.append(prefix + ":")
            _emit(out, value, indent + 2)
        else:
            out.append(prefix + ": " + _scalar(value))


def build_yaml(proxies: list[dict[str, Any]]) -> str:
    """Собирает YAML-документ с секцией proxies для Clash Meta."""
    out = ["proxies:"]
    _emit(out, proxies, 1)
    return "\n".join(out) + "\n"
