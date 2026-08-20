from urllib.parse import unquote
import base64
import binascii
import re

def split_host_port(hostport: str) -> tuple[str, str]:
    if hostport.startswith('['):
        end = hostport.find(']')
        if end == -1:
            raise ValueError('битый IPv6-адрес')
        port_part = hostport[end + 1:]
        if not port_part.startswith(':'):
            raise ValueError('отсутствует порт после IPv6')
        return (hostport[1:end], port_part[1:])
    if ':' not in hostport:
        raise ValueError('отсутствует порт')
    (host, _, port) = hostport.rpartition(':')
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f"невалидный порт '{port}'")
    return (host, port)

def b64decode_safe(s: str) -> bytes:
    clean = s.strip().replace('-', '+').replace('_', '/')
    clean = re.sub('\\s+', '', clean)
    rem = len(clean) % 4
    if rem == 1:
        raise ValueError('невалидная длина base64')
    if rem > 0:
        clean += '=' * (4 - rem)
    try:
        return base64.b64decode(clean)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f'ошибка декодирования base64: {exc}') from None

def b64decode_str(s: str, encoding: str='utf-8') -> str:
    data = b64decode_safe(s)
    return data.decode(encoding, errors='replace')

def clean_name(fragment: str, fallback: str) -> str:
    if fragment:
        name = unquote(fragment).strip()
        name = ''.join((ch for ch in name if ch.isprintable()))
        if name:
            return name
    return fallback

def validate_reality(pbk: str, sid: str) -> None:
    s = pbk.strip()
    if not re.fullmatch('[A-Za-z0-9_-]+', s):
        raise ValueError('невалидный REALITY public-key (битый base64)')
    if '=' in s:
        raise ValueError('невалидный REALITY public-key (паддинг не допускается)')
    if len(s) % 4 == 1:
        raise ValueError('невалидный REALITY public-key (битая длина base64)')
    try:
        raw = base64.b64decode(s.replace('-', '+').replace('_', '/') + '=' * (-len(s) % 4))
    except (binascii.Error, ValueError):
        raise ValueError('невалидный REALITY public-key (битый base64)') from None
    if len(raw) != 32:
        raise ValueError(f'невалидный REALITY public-key (ожидается 32 байта, получено {len(raw)})')
    if sid and (len(sid) > 16 or len(sid) % 2 != 0 or (not re.fullmatch('[0-9a-fA-F]+', sid))):
        raise ValueError('невалидный REALITY short-id (hex чётной длины, до 16 символов)')

def validate_flow(flow: str) -> None:
    if len(flow) >= 16 and flow[:16] != 'xtls-rprx-vision':
        raise ValueError(f"неподдерживаемый flow '{flow}'")
