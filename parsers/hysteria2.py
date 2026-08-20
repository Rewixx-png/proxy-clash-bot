from urllib.parse import parse_qs, urlparse
from .base import BaseParser, ParsedProxy
from .utils import clean_name, split_host_port

class Hysteria2Parser(BaseParser):
    protocol = 'hysteria2'

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        if scheme not in ('hysteria2', 'hy2'):
            raise ValueError(f"ожидалась схема 'hysteria2' или 'hy2', получено '{scheme}'")
        (userinfo, _, hostport) = parsed.netloc.rpartition('@')
        if not hostport:
            raise ValueError('нет адреса сервера (host:port)')
        (host, port_s) = split_host_port(hostport)
        params = {k: v[0] for (k, v) in parse_qs(parsed.query, keep_blank_values=True).items()}
        password = userinfo or params.get('auth') or ''
        name = clean_name(parsed.fragment, f'{host}:{port_s}')
        proxy: dict = {'name': name, 'type': 'hysteria2', 'server': host, 'port': int(port_s), 'password': password, 'udp': True}
        sni = params.get('sni') or params.get('peer')
        if sni:
            proxy['sni'] = sni
        if params.get('alpn'):
            proxy['alpn'] = [a.strip() for a in params['alpn'].split(',') if a.strip()]
        if params.get('insecure') in ('1', 'true') or params.get('allowInsecure') in ('1', 'true'):
            proxy['skip-cert-verify'] = True
        ports = params.get('mport') or params.get('ports')
        if ports:
            proxy['ports'] = ports
        obfs = params.get('obfs')
        if obfs:
            proxy['obfs'] = obfs
            obfs_pwd = params.get('obfs-password') or params.get('obfs_param') or params.get('obfs-param')
            if obfs_pwd:
                proxy['obfs-password'] = obfs_pwd
        if params.get('up'):
            proxy['up'] = params['up']
        if params.get('down'):
            proxy['down'] = params['down']
        if params.get('ca-str'):
            proxy['ca-str'] = params['ca-str']
        return ParsedProxy(name=name, data=proxy)

class Hy2Parser(Hysteria2Parser):
    protocol = 'hy2'
