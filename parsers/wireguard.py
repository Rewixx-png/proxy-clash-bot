from urllib.parse import parse_qs, urlparse
from .base import BaseParser, ParsedProxy
from .utils import clean_name, split_host_port

class WireguardParser(BaseParser):
    protocol = 'wireguard'

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        if scheme not in ('wireguard', 'wg'):
            raise ValueError(f"ожидалась схема 'wireguard' или 'wg', получено '{scheme}'")
        (userinfo, _, hostport) = parsed.netloc.rpartition('@')
        if not hostport:
            raise ValueError('нет адреса сервера (host:port)')
        (host, port_s) = split_host_port(hostport)
        params = {k: v[0] for (k, v) in parse_qs(parsed.query, keep_blank_values=True).items()}
        private_key = userinfo or params.get('private_key') or params.get('privatekey') or ''
        public_key = params.get('public_key') or params.get('publickey') or params.get('pubkey') or ''
        ip = params.get('ip') or params.get('address') or ''
        if not public_key:
            raise ValueError('нет public_key для WireGuard')
        name = clean_name(parsed.fragment, f'{host}:{port_s}')
        proxy: dict = {'name': name, 'type': 'wireguard', 'server': host, 'port': int(port_s), 'ip': ip or '10.0.0.2', 'public-key': public_key, 'udp': True}
        if private_key:
            proxy['private-key'] = private_key
        if params.get('ipv6'):
            proxy['ipv6'] = params['ipv6']
        psk = params.get('preshared_key') or params.get('presharedkey') or params.get('psk')
        if psk:
            proxy['preshared-key'] = psk
        reserved = params.get('reserved')
        if reserved:
            try:
                if ',' in reserved:
                    proxy['reserved'] = [int(x.strip()) for x in reserved.split(',') if x.strip()]
                elif '[' in reserved:
                    import json
                    proxy['reserved'] = json.loads(reserved)
            except Exception:
                pass
        if params.get('mtu'):
            try:
                proxy['mtu'] = int(params['mtu'])
            except ValueError:
                pass
        return ParsedProxy(name=name, data=proxy)

class WgParser(WireguardParser):
    protocol = 'wg'
