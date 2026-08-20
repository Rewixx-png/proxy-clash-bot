import asyncio
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from parsers import PROTOCOL_PARSERS
logger = logging.getLogger(__name__)
_LINK_RE = re.compile('\\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic|wireguard|wg|socks5|socks5h|socks|http|https|anytls)://[^\\s]+', re.IGNORECASE)
_TRAILING_JUNK = '.,;:!?"\'<>()[]{}\\`'

@dataclass
class ConvertResult:
    proxies: list[dict[str, Any]] = field(default_factory=list)
    total_lines: int = 0
    ok: int = 0
    skipped: int = 0

async def parse_batch(text: str, on_progress: Callable[[int, int, int], None] | None=None, chunk_size: int=200) -> ConvertResult:
    lines = [ln.strip() for ln in text.splitlines()]
    total = sum((1 for ln in lines if ln))
    result = ConvertResult(total_lines=total)
    seen: set[str] = set()
    used_names: set[str] = set()
    processed = 0
    for start in range(0, len(lines), chunk_size):
        for (line_no, line) in enumerate(lines[start:start + chunk_size], start=start + 1):
            if not line:
                continue
            processed += 1
            for match in _LINK_RE.finditer(line):
                raw = match.group(0).rstrip(_TRAILING_JUNK)
                scheme = raw.split(':', 1)[0].lower()
                try:
                    parser_cls = PROTOCOL_PARSERS.get(scheme)
                    if parser_cls is None:
                        raise ValueError(f"протокол '{scheme}' пока не поддерживается")
                    if raw in seen:
                        raise ValueError('дубликат ссылки')
                    seen.add(raw)
                    proxy = parser_cls.parse(raw).data
                    name = proxy['name']
                    if name in used_names:
                        (base, i) = (name, 2)
                        while f'{base} #{i}' in used_names:
                            i += 1
                        proxy['name'] = f'{base} #{i}'
                    used_names.add(proxy['name'])
                    result.proxies.append(proxy)
                except Exception as exc:
                    result.skipped += 1
                    logger.warning('Строка %d: пропущена ссылка (%s): %s', line_no, scheme, exc)
        if on_progress and processed:
            on_progress(round(processed / total * 100), processed, total)
        await asyncio.sleep(0)
    result.ok = len(result.proxies)
    return result
_SAFE_PLAIN = re.compile('^[A-Za-z0-9_./~-]+$')
_NUMERIC = re.compile('^-?\\d+(\\.\\d+)?$')
_YAML_NUMERIC_LIKE = re.compile('^[-+]?(\\d[\\d_]*\\.?\\d*|\\.\\d+)([eE][-+]?\\d+)?$|^0[xX][0-9a-fA-F_]+$|^0[oO][0-7_]+$|^0[bB][01_]+$|^0[0-7]+$')
_DATE_LIKE = re.compile('^\\d{4}-\\d{1,2}-\\d{1,2}([Tt ].*)?$')
_YAML_RESERVED = {'true', 'false', 'null', 'yes', 'no', 'on', 'off', '~', 'inf', 'infinity', 'nan'}

def _needs_quotes(s: str) -> bool:
    return not s or not _SAFE_PLAIN.fullmatch(s) or s.lower() in _YAML_RESERVED or _NUMERIC.fullmatch(s) or _YAML_NUMERIC_LIKE.match(s) or _DATE_LIKE.match(s)

def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, int):
        return str(value)
    s = str(value)
    if not _needs_quotes(s):
        return s
    parts = []
    for ch in s:
        if ch == '\\':
            parts.append('\\\\')
        elif ch == '"':
            parts.append('\\"')
        elif ch == '\n':
            parts.append('\\n')
        elif ch == '\t':
            parts.append('\\t')
        elif ch.isprintable():
            parts.append(ch)
        else:
            parts.append(f'\\u{ord(ch):04x}')
    return '"' + ''.join(parts) + '"'

def _emit(out: list[str], data: Any, indent: int) -> None:
    pad = '  ' * indent
    if isinstance(data, dict):
        for (key, value) in data.items():
            prefix = f'{pad}{key}'
            if isinstance(value, (dict, list)):
                out.append(prefix + ':')
                _emit(out, value, indent + 1)
            else:
                out.append(prefix + ': ' + _scalar(value))
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, dict):
                _emit_list_item(out, value, indent)
            elif isinstance(value, list):
                out.append(f'{pad}-')
                _emit(out, value, indent + 1)
            else:
                out.append(f'{pad}- {_scalar(value)}')
    else:
        out.append(f'{pad}- {_scalar(data)}')

def _emit_list_item(out: list[str], data: dict, indent: int) -> None:
    inner = '  ' * (indent + 1)
    for (i, (key, value)) in enumerate(data.items()):
        prefix = f"{'  ' * indent}- {key}" if i == 0 else f'{inner}{key}'
        if isinstance(value, (dict, list)):
            out.append(prefix + ':')
            _emit(out, value, indent + 2)
        else:
            out.append(prefix + ': ' + _scalar(value))

def build_yaml(proxies: list[dict[str, Any]]) -> str:
    out = ['proxies:']
    _emit(out, proxies, 1)
    return '\n'.join(out) + '\n'
