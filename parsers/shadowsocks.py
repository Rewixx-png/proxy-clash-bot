from urllib.parse import parse_qs, unquote
from .base import BaseParser, ParsedProxy
from .utils import b64decode_str, clean_name, split_host_port

def _parse_plugin(plugin_str: str) -> tuple[str, dict]:
    unquoted = unquote(plugin_str)
    parts = unquoted.split(';')
    plugin_name = parts[0].strip().lower()
    opts: dict = {}
    for part in parts[1:]:
        if not part.strip():
            continue
        if '=' in part:
            (k, _, v) = part.partition('=')
            (k, v) = (k.strip().lower(), v.strip())
            if k in ('mode', 'obfs'):
                opts['mode'] = v
            elif k in ('host', 'obfs-host'):
                opts['host'] = v
            elif k in ('path', 'ws-path'):
                opts['path'] = v
            elif k in ('password', 'shadow-tls-password'):
                opts['password'] = v
            elif k in ('version', 'shadow-tls-version'):
                opts['version'] = int(v) if v.isdigit() else v
            elif k == 'sni':
                opts['host'] = v
        else:
            flag = part.strip().lower()
            if flag == 'tls':
                opts['tls'] = True
            elif flag == 'mux':
                opts['mux'] = True
    if plugin_name in ('v2ray-plugin', 'v2ray'):
        plugin_name = 'v2ray-plugin'
    elif plugin_name in ('obfs-local', 'simple-obfs', 'obfs'):
        plugin_name = 'obfs'
    return (plugin_name, opts)

class ShadowsocksParser(BaseParser):
    protocol = 'ss'

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        if not raw.lower().startswith('ss://'):
            raise ValueError(f"ожидалась схема '{cls.protocol}'")
        payload = raw[5:].strip()
        (main_part, _, fragment) = payload.partition('#')
        if '@' in main_part:
            (userinfo, _, hostport_query) = main_part.rpartition('@')
            (hostport, _, query) = hostport_query.partition('?')
            (host, port_s) = split_host_port(hostport)
            if ':' in userinfo:
                (method, _, password) = userinfo.partition(':')
            else:
                decoded = b64decode_str(userinfo)
                if ':' not in decoded:
                    raise ValueError('не удалось извлечь method:password из userinfo')
                (method, _, password) = decoded.partition(':')
        else:
            hostport_query = b64decode_str(main_part)
            if '@' not in hostport_query:
                raise ValueError('не удалось разобрать legacy ss ссылку (нет @)')
            (userinfo, _, hostport_tail) = hostport_query.rpartition('@')
            if ':' not in userinfo:
                raise ValueError('нет method:password в legacy ссылке')
            (method, _, password) = userinfo.partition(':')
            (hostport, _, query) = hostport_tail.partition('?')
            (host, port_s) = split_host_port(hostport)
        name = clean_name(fragment, f'{host}:{port_s}')
        proxy: dict = {'name': name, 'type': 'ss', 'server': host, 'port': int(port_s), 'cipher': method, 'password': password, 'udp': True}
        if query:
            params = {k: v[0] for (k, v) in parse_qs(query, keep_blank_values=True).items()}
            plugin_val = params.get('plugin')
            if plugin_val:
                (p_name, p_opts) = _parse_plugin(plugin_val)
                proxy['plugin'] = p_name
                if p_opts:
                    proxy['plugin-opts'] = p_opts
        return ParsedProxy(name=name, data=proxy)
