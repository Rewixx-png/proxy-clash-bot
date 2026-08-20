import json
from urllib.parse import parse_qs, urlparse
from .base import BaseParser, ParsedProxy
from .utils import b64decode_str, clean_name, split_host_port

_NETWORK_ALIASES = {
    "tcp": "tcp",
    "raw": "tcp",
    "ws": "ws",
    "websocket": "ws",
    "grpc": "grpc",
    "http": "http",
    "h2": "h2",
    "xhttp": "xhttp",
}


class VmessParser(BaseParser):
    protocol = "vmess"

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        if not raw.lower().startswith("vmess://"):
            raise ValueError(f"ожидалась схема '{cls.protocol}'")
        payload = raw[8:].strip()
        if "@" in payload:
            return cls._parse_uri(raw)
        (b64_part, _, fragment) = payload.partition("#")
        decoded_text = b64decode_str(b64_part)
        try:
            cfg = json.loads(decoded_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"невалидный JSON в vmess-ссылке: {exc}") from None
        if not isinstance(cfg, dict):
            raise ValueError("содержимое vmess JSON не является объектом")
        server = str(cfg.get("add") or "").strip()
        port = cfg.get("port")
        uuid = str(cfg.get("id") or "").strip()
        if not server or not port or (not uuid):
            raise ValueError("отсутствуют обязательные поля (add, port, id)")
        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError
        except (ValueError, TypeError):
            raise ValueError(f"невалидный порт vmess '{port}'")
        name = str(cfg.get("ps") or "").strip()
        name = clean_name(fragment, name or f"{server}:{port_num}")
        net_raw = str(cfg.get("net") or "tcp").lower()
        network = _NETWORK_ALIASES.get(net_raw, "tcp")
        cipher = str(cfg.get("scy") or "auto").strip()
        alter_id = int(cfg.get("aid") or 0)
        proxy: dict = {
            "name": name,
            "type": "vmess",
            "server": server,
            "port": port_num,
            "uuid": uuid,
            "alterId": alter_id,
            "cipher": cipher,
            "udp": True,
        }
        tls_val = str(cfg.get("tls") or "").lower()
        if tls_val in ("tls", "reality", "1", "true"):
            proxy["tls"] = True
            sni = str(cfg.get("sni") or cfg.get("host") or "").strip()
            if sni:
                proxy["servername"] = sni
            fp = str(cfg.get("fp") or "").strip()
            if fp:
                proxy["client-fingerprint"] = fp
            alpn = cfg.get("alpn")
            if alpn:
                if isinstance(alpn, str):
                    proxy["alpn"] = [a.strip() for a in alpn.split(",") if a.strip()]
                elif isinstance(alpn, list):
                    proxy["alpn"] = [str(a).strip() for a in alpn if str(a).strip()]
        else:
            proxy["tls"] = False
        path = str(cfg.get("path") or "").strip()
        host = str(cfg.get("host") or "").strip()
        if network == "ws":
            proxy["network"] = "ws"
            ws_opts: dict = {}
            if path:
                ws_opts["path"] = path
            ws_opts["headers"] = {"Host": host or proxy.get("servername") or server}
            proxy["ws-opts"] = ws_opts
        elif network == "grpc":
            proxy["network"] = "grpc"
            service = path or host
            if service:
                proxy["grpc-opts"] = {"grpc-service-name": service}
        elif network in ("http", "h2"):
            proxy["network"] = network
            opts: dict = {"path": [path or "/"] if network == "http" else path or "/"}
            host_hdr = host or proxy.get("servername") or server
            if network == "http":
                opts["headers"] = {"Host": [host_hdr]}
            else:
                opts["host"] = [host_hdr]
            proxy[f"{network}-opts"] = opts
        elif network == "xhttp":
            proxy["network"] = "xhttp"
            xhttp_opts: dict = {}
            if path:
                xhttp_opts["path"] = path
            host_hdr = host or proxy.get("servername") or server
            if host_hdr:
                xhttp_opts["host"] = host_hdr
            if xhttp_opts:
                proxy["xhttp-opts"] = xhttp_opts
        else:
            proxy["network"] = "tcp"
            type_hdr = str(cfg.get("type") or "").lower()
            if type_hdr == "http":
                proxy["http-opts"] = {
                    "path": [path or "/"],
                    "headers": {"Host": [host or server]},
                }
        return ParsedProxy(name=name, data=proxy)

    @classmethod
    def _parse_uri(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        (userinfo, _, hostport) = parsed.netloc.rpartition("@")
        if not userinfo or not hostport:
            raise ValueError("нет части uuid@host:port")
        (uuid, (host, port_s)) = (userinfo, split_host_port(hostport))
        params = {
            k: v[0] for (k, v) in parse_qs(parsed.query, keep_blank_values=True).items()
        }
        net_raw = params.get("type", "tcp").lower()
        network = _NETWORK_ALIASES.get(net_raw, "tcp")
        name = clean_name(parsed.fragment, f"{host}:{port_s}")
        proxy: dict = {
            "name": name,
            "type": "vmess",
            "server": host,
            "port": int(port_s),
            "uuid": uuid,
            "alterId": int(params.get("alterId", 0)),
            "cipher": params.get("cipher", "auto"),
            "udp": True,
        }
        security = params.get("security", "none").lower()
        if security in ("tls", "reality"):
            proxy["tls"] = True
            sni = params.get("sni") or params.get("host")
            if sni:
                proxy["servername"] = sni
            if params.get("fp"):
                proxy["client-fingerprint"] = params["fp"]
            if params.get("alpn"):
                proxy["alpn"] = [
                    a.strip() for a in params["alpn"].split(",") if a.strip()
                ]
        else:
            proxy["tls"] = False
        if network == "ws":
            proxy["network"] = "ws"
            ws_opts: dict = {}
            if params.get("path"):
                ws_opts["path"] = params["path"]
            ws_opts["headers"] = {
                "Host": params.get("host") or params.get("sni") or host
            }
            proxy["ws-opts"] = ws_opts
        elif network == "grpc":
            proxy["network"] = "grpc"
            service = params.get("serviceName") or params.get("path")
            if service:
                proxy["grpc-opts"] = {"grpc-service-name": service}
        elif network in ("http", "h2"):
            proxy["network"] = network
            opts: dict = {
                "path": [params.get("path") or "/"]
                if network == "http"
                else params.get("path") or "/"
            }
            host_hdr = params.get("host") or params.get("sni") or host
            if network == "http":
                opts["headers"] = {"Host": [host_hdr]}
            else:
                opts["host"] = [host_hdr]
            proxy[f"{network}-opts"] = opts
        else:
            proxy["network"] = "tcp"
        return ParsedProxy(name=name, data=proxy)
