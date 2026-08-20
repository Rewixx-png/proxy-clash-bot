from urllib.parse import parse_qs, urlparse
from .base import BaseParser, ParsedProxy
from .utils import clean_name, split_host_port, validate_flow, validate_reality
_NETWORK_ALIASES = {'tcp': 'tcp', 'raw': 'tcp', 'ws': 'ws', 'grpc': 'grpc', 'http': 'http', 'httpupgrade': 'http', 'h2': 'h2', 'xhttp': 'xhttp'}
_TLS_SECURITIES = {'tls', 'xtls', 'reality'}

class VlessParser(BaseParser):
    protocol = 'vless'

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        if parsed.scheme != cls.protocol:
            raise ValueError(f"ожидалась схема '{cls.protocol}'")
        (userinfo, _, hostport) = parsed.netloc.rpartition('@')
        if not userinfo or not hostport:
            raise ValueError('нет части uuid@host:port')
        (uuid, (host, port_s)) = (userinfo, split_host_port(hostport))
        params = {k: v[0] for (k, v) in parse_qs(parsed.query, keep_blank_values=True).items()}
        network = params.get('type', 'tcp').lower()
        network = _NETWORK_ALIASES.get(network)
        if network is None:
            raise ValueError(f"транспорт '{params.get('type')}' не поддерживается Clash Meta")
        validate_flow(params.get('flow', ''))
        security = params.get('security', 'none')
        tls_enabled = security in _TLS_SECURITIES
        name = clean_name(parsed.fragment, f'{host}:{port_s}')
        proxy: dict = {'name': name, 'type': 'vless', 'server': host, 'port': int(port_s), 'uuid': uuid, 'udp': True}
        if tls_enabled:
            proxy['tls'] = True
            sni = params.get('sni') or params.get('host')
            if sni:
                proxy['servername'] = sni
            if params.get('fp'):
                proxy['client-fingerprint'] = params['fp']
            if params.get('flow'):
                proxy['flow'] = params['flow']
            if security == 'reality':
                pbk = params.get('pbk')
                if not pbk:
                    raise ValueError('Reality-ссылка без pbk (public-key)')
                validate_reality(pbk, params.get('sid', ''))
                reality_opts = {'public-key': pbk}
                if params.get('sid'):
                    reality_opts['short-id'] = params['sid']
                proxy['reality-opts'] = reality_opts
            alpn = params.get('alpn')
            if alpn:
                proxy['alpn'] = [a.strip() for a in alpn.split(',') if a.strip()]
        else:
            proxy['tls'] = False
        if network == 'ws':
            proxy['network'] = 'ws'
            ws_opts: dict = {}
            if params.get('path'):
                ws_opts['path'] = params['path']
            ws_opts['headers'] = {'Host': params.get('host') or params.get('sni') or host}
            proxy['ws-opts'] = ws_opts
        elif network == 'grpc':
            proxy['network'] = 'grpc'
            service = params.get('serviceName')
            if service:
                proxy['grpc-opts'] = {'grpc-service-name': service}
        elif network in ('http', 'h2'):
            proxy['network'] = network
            opts: dict = {'path': [params.get('path') or '/'] if network == 'http' else params.get('path') or '/'}
            host_hdr = params.get('host') or params.get('sni') or host
            if network == 'http':
                opts['headers'] = {'Host': [host_hdr]}
            else:
                opts['host'] = [host_hdr]
            proxy[f'{network}-opts'] = opts
        elif network == 'xhttp':
            proxy['network'] = 'xhttp'
            xhttp_opts: dict = {}
            if params.get('path'):
                xhttp_opts['path'] = params['path']
            host_hdr = params.get('host') or params.get('sni') or host
            if host_hdr:
                xhttp_opts['host'] = host_hdr
            if xhttp_opts:
                proxy['xhttp-opts'] = xhttp_opts
        else:
            proxy['network'] = 'tcp'
        return ParsedProxy(name=name, data=proxy)
