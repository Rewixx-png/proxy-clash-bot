from urllib.parse import parse_qs, urlparse
from .base import BaseParser, ParsedProxy
from .utils import clean_name, split_host_port

class TuicParser(BaseParser):
    protocol = 'tuic'

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        if parsed.scheme.lower() != cls.protocol:
            raise ValueError(f"ожидалась схема '{cls.protocol}'")
        (userinfo, _, hostport) = parsed.netloc.rpartition('@')
        if not userinfo or not hostport:
            raise ValueError('нет части uuid:password@host:port')
        if ':' in userinfo:
            (uuid, _, password) = userinfo.partition(':')
        else:
            (uuid, password) = (userinfo, '')
        (host, port_s) = split_host_port(hostport)
        params = {k: v[0] for (k, v) in parse_qs(parsed.query, keep_blank_values=True).items()}
        name = clean_name(parsed.fragment, f'{host}:{port_s}')
        proxy: dict = {'name': name, 'type': 'tuic', 'server': host, 'port': int(port_s), 'uuid': uuid, 'password': password, 'udp': True}
        sni = params.get('sni') or params.get('host')
        if sni:
            proxy['sni'] = sni
        alpn = params.get('alpn')
        if alpn:
            proxy['alpn'] = [a.strip() for a in alpn.split(',') if a.strip()]
        congestion = params.get('congestion_control') or params.get('congestion-controller')
        if congestion:
            proxy['congestion-controller'] = congestion
        udp_mode = params.get('udp_relay_mode') or params.get('udp-relay-mode')
        if udp_mode:
            proxy['udp-relay-mode'] = udp_mode
        if params.get('allow_insecure') in ('1', 'true') or params.get('insecure') in ('1', 'true'):
            proxy['skip-cert-verify'] = True
        if params.get('reduce_rtt') in ('1', 'true') or params.get('reduce-rtt') in ('1', 'true'):
            proxy['reduce-rtt'] = True
        if params.get('disable_sni') in ('1', 'true') or params.get('disable-sni') in ('1', 'true'):
            proxy['disable-sni'] = True
        return ParsedProxy(name=name, data=proxy)
