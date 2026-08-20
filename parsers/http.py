"""Парсер HTTP / HTTPS (http://, https://) ссылок в прокси-словарь Clash Meta (Mihomo).

Формат ссылки:
  http://username:password@host:port#Имя
  https://username:password@host:port#Имя
"""
from urllib.parse import parse_qs, urlparse

from .base import BaseParser, ParsedProxy
from .utils import clean_name, split_host_port


class HttpParser(BaseParser):
    """Разбирает http:// и https:// ссылки в структуру для секции proxies."""

    protocol = "http"

    @classmethod
    def parse(cls, raw: str) -> ParsedProxy:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"ожидалась схема 'http' или 'https', получено '{scheme}'")

        userinfo, _, hostport = parsed.netloc.rpartition("@")
        if not hostport:
            hostport = userinfo
            userinfo = ""

        # Если порт не указан в http/https ссылке, проверяем дефолтный или требуем порт
        if ":" in hostport or hostport.startswith("["):
            host, port_s = split_host_port(hostport)
        else:
            # Обычный http URL без порта скорее всего веб-ссылка, а не прокси
            # Но если это явная ссылка, дефолтный порт 80 для http, 443 для https
            host = hostport
            port_s = "443" if scheme == "https" else "80"

        params = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        name = clean_name(parsed.fragment, f"{host}:{port_s}")

        proxy: dict = {
            "name": name,
            "type": "http",
            "server": host,
            "port": int(port_s),
        }

        if userinfo:
            username, _, password = userinfo.partition(":")
            if username:
                proxy["username"] = username
            if password:
                proxy["password"] = password

        if scheme == "https" or params.get("tls") in ("1", "true"):
            proxy["tls"] = True
            sni = params.get("sni") or params.get("host")
            if sni:
                proxy["sni"] = sni
            if params.get("insecure") in ("1", "true") or params.get("allowInsecure") in ("1", "true"):
                proxy["skip-cert-verify"] = True

        return ParsedProxy(name=name, data=proxy)


class HttpsParser(HttpParser):
    protocol = "https"
