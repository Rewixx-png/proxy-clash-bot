from urllib.parse import parse_qs, urlparse
from .base import BaseParser, ParsedProxy
from .utils import clean_name, split_host_port

class Socks5Parser(BaseParser):
    protocol = 'socks5'

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        if scheme not in ('socks5', 'socks', 'socks5h'):
            raise ValueError(f"ожидалась схема 'socks5' / 'socks', получено '{scheme}'")
        (userinfo, _, hostport) = parsed.netloc.rpartition('@')
        if not hostport:
            hostport = userinfo
            userinfo = ''
        (host, port_s) = split_host_port(hostport)
        params = {k: v[0] for (k, v) in parse_qs(parsed.query, keep_blank_values=True).items()}
        name = clean_name(parsed.fragment, f'{host}:{port_s}')
        proxy: dict = {'name': name, 'type': 'socks5', 'server': host, 'port': int(port_s), 'udp': True}
        if userinfo:
            (username, _, password) = userinfo.partition(':')
            if username:
                proxy['username'] = username
            if password:
                proxy['password'] = password
        if params.get('tls') in ('1', 'true'):
            proxy['tls'] = True
            sni = params.get('sni') or params.get('host')
            if sni:
                proxy['sni'] = sni
            if params.get('insecure') in ('1', 'true'):
                proxy['skip-cert-verify'] = True
        return ParsedProxy(name=name, data=proxy)

class SocksParser(Socks5Parser):
    protocol = 'socks'

class Socks5hParser(Socks5Parser):
    protocol = 'socks5h'
