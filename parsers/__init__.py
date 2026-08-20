"""Реестр парсеров прокси-ссылок."""
from .base import BaseParser, ParsedProxy
from .http import HttpParser, HttpsParser
from .hysteria2 import Hy2Parser, Hysteria2Parser
from .shadowsocks import ShadowsocksParser
from .socks import Socks5hParser, Socks5Parser, SocksParser
from .ssr import SsrParser
from .trojan import TrojanParser
from .tuic import TuicParser
from .vless import VlessParser
from .vmess import VmessParser
from .wireguard import WgParser, WireguardParser

# Схема ссылки -> класс парсера.
PROTOCOL_PARSERS: dict[str, type[BaseParser]] = {
    VlessParser.protocol: VlessParser,
    VmessParser.protocol: VmessParser,
    TrojanParser.protocol: TrojanParser,
    ShadowsocksParser.protocol: ShadowsocksParser,
    Hysteria2Parser.protocol: Hysteria2Parser,
    Hy2Parser.protocol: Hy2Parser,
    TuicParser.protocol: TuicParser,
    HttpParser.protocol: HttpParser,
    HttpsParser.protocol: HttpsParser,
    Socks5Parser.protocol: Socks5Parser,
    SocksParser.protocol: SocksParser,
    Socks5hParser.protocol: Socks5hParser,
    WireguardParser.protocol: WireguardParser,
    WgParser.protocol: WgParser,
    SsrParser.protocol: SsrParser,
}

__all__ = [
    "BaseParser",
    "ParsedProxy",
    "PROTOCOL_PARSERS",
    "VlessParser",
    "VmessParser",
    "TrojanParser",
    "ShadowsocksParser",
    "Hysteria2Parser",
    "Hy2Parser",
    "TuicParser",
    "HttpParser",
    "HttpsParser",
    "Socks5Parser",
    "SocksParser",
    "Socks5hParser",
    "WireguardParser",
    "WgParser",
    "SsrParser",
]
