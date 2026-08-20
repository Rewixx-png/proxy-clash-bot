# Proxy Clash Meta Converter Bot

Telegram-бот для автоматической конвертации прокси-ссылок любых форматов в готовый YAML-конфиг (`clash_meta_proxies.yaml`) для **Clash Meta (Mihomo)** / **FLClash** / **Clash Verge Rev**.

## 🚀 Поддерживаемые протоколы

- **VLESS** (`vless://`) — Reality, TLS, TCP, WebSocket, gRPC, H2, HTTPUpgrade, XHTTP, flow (`xtls-rprx-vision`)
- **VMess** (`vmess://`) — v2rayN Base64 JSON и URI (WS, gRPC, TCP, HTTP, TLS)
- **Trojan** (`trojan://`) — TLS, Reality, WebSocket, gRPC, H2
- **Shadowsocks (SS)** (`ss://`) — SIP002, Legacy, Plain, плагины (`v2ray-plugin`, `obfs-local`, `shadow-tls`)
- **ShadowsocksR (SSR)** (`ssr://`) — протоколы, обфускация
- **Hysteria 2** (`hy2://`, `hysteria2://`) — SNI, port hopping, Salamander obfs, bandwidth limits
- **TUIC** (`tuic://`) — UUID, BBR congestion control, ALPN h3, UDP relay
- **SOCKS5 / SOCKS** (`socks5://`, `socks://`, `socks5h://`) — логин/пароль, TLS
- **HTTP / HTTPS** (`http://`, `https://`) — классические и защищенные HTTP-прокси
- **WireGuard** (`wireguard://`, `wg://`) — IP, public/private keys, preshared key, MTU, reserved

## ⚙️ Особенности

- **Высокая производительность:** собственный быстрый YAML-эмиттер без оверхеда PyYAML.
- **Пакетная обработка:** поддержка десятков тысяч ссылок текстом или `.txt` файлом с реальным прогресс-баром.
- **Дедупликация:** фильтрация точных дубликатов ссылок, уникализация названий (`#2`, `#3`) и интерактивный вопрос на удаление дубликатов по серверным IP.
- **Валидация:** строгая проверка REALITY-ключей и параметров перед экспортом, чтобы Clash Meta не отклонял конфиг.

## 🛠️ Установка и запуск

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/Rewixx-png/proxy-clash-bot.git
   cd proxy-clash-bot
   ```

2. Создайте виртуальное окружение и установите зависимости:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Настройте конфигурацию:
   ```bash
   cp .env.example .env
   # Укажите ваш токен в .env
   ```

4. Запустите бота:
   ```bash
   python main.py
   # Или через PM2:
   pm2 start ecosystem.config.js
   ```

## 🧪 Тестирование

Запуск тестов парсинга всех протоколов:
```bash
python selftest.py
```
