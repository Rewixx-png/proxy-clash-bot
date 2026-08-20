"""Парсер ShadowsocksR (ssr://) ссылок в прокси-словарь Clash Meta (Mihomo).

Формат ссылки:
  ssr://BASE64(host:port:protocol:method:obfs:base64pass/?obfsparam=...&protoparam=...&remarks=...&group=...)
"""
from urllib.parse import parse_qs

from .base import BaseParser, ParsedProxy
from .utils import b64decode_str, clean_name


class SsrParser(BaseParser):
    """Разбирает ssr:// ссылки в структуру для секции proxies."""

    protocol = "ssr"

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        if not raw.lower().startswith("ssr://"):
            raise ValueError(f"ожидалась схема '{cls.protocol}'")

        payload = raw[6:].strip()
        decoded = b64decode_str(payload)

        # host:port:protocol:method:obfs:base64pass/?query
        main_part, _, query_part = decoded.partition("/?")
        parts = main_part.split(":")
        if len(parts) < 6:
            raise ValueError("невалидный формат SSR ссылки (ожидалось 6 компонентов)")

        host = parts[0]
        port_s = parts[1]
        protocol = parts[2]
        method = parts[3]
        obfs = parts[4]
        b64pass = parts[5]

        password = b64decode_str(b64pass)

        params = {}
        if query_part:
            params = {k: v[0] for k, v in parse_qs(query_part, keep_blank_values=True).items()}

        remarks = params.get("remarks", "")
        name = ""
        if remarks:
            try:
                name = b64decode_str(remarks)
            except Exception:
                name = remarks

        name = clean_name(name, f"{host}:{port_s}")

        proxy: dict = {
            "name": name,
            "type": "ssr",
            "server": host,
            "port": int(port_s),
            "cipher": method,
            "password": password,
            "protocol": protocol,
            "obfs": obfs,
            "udp": True,
        }

        if params.get("protoparam"):
            try:
                proxy["protocol-param"] = b64decode_str(params["protoparam"])
            except Exception:
                proxy["protocol-param"] = params["protoparam"]

        if params.get("obfsparam"):
            try:
                proxy["obfs-param"] = b64decode_str(params["obfsparam"])
            except Exception:
                proxy["obfs-param"] = params["obfsparam"]

        return ParsedProxy(name=name, data=proxy)
