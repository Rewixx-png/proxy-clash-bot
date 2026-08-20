import asyncio
import base64
import json
from converter import build_yaml, parse_batch
_vmess_sample = json.dumps({'v': '2', 'ps': 'VMess-WS-TLS', 'add': 'vmess.example.com', 'port': 443, 'id': 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d', 'aid': 0, 'scy': 'auto', 'net': 'ws', 'type': 'none', 'host': 'vmess.example.com', 'path': '/vpath', 'tls': 'tls', 'sni': 'vmess.example.com'})
_vmess_b64 = base64.b64encode(_vmess_sample.encode()).decode()
_ss_userinfo = base64.b64encode(b'aes-256-gcm:pass123').decode()
_ssr_inner = f"1.2.3.4:8388:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:{base64.b64encode(b'secret').decode()}/?remarks={base64.b64encode(b'SSR-Test').decode()}"
_ssr_b64 = base64.b64encode(_ssr_inner.encode()).decode()
LINKS = ['vless://c5293e6a-4e14-4f8f-9b4f-1e2d3c4b5a6d@193.233.201.25:443?type=tcp&security=reality&sni=yahoo.com&fp=chrome&pbk=8N2Wv3rQkLmXzYpQaBcDeFgHiJkLmNoPqRsTuVwXyZa&sid=6ba85179&flow=xtls-rprx-vision&spx=%2F#%F0%9F%87%A9%F0%9F%87%AA%20DE-01', 'vless://e0d7e0c0-5f4a-4b3c-9d2e-1a2b3c4d5e6f@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&fp=firefox&path=%2Ffast%2Fws&host=cdn.example.com#WS-Test', 'vless://a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d@grpc.example.com:8443?type=grpc&security=tls&sni=grpc.example.com&serviceName=mygrpc#GRPC-Test', 'vless://b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e@10.0.0.5:8080?type=tcp&security=none#Plain-Test', 'vless://851ed0d8-a37b-452d-8ef2-5b6c2d28a060@37.18.14.121:2027?encryption=none&flow=xtls-rprx-vision&pbk=ISa-DZOI4LRRb9DHMFYm5oFqBXDjYzz0hVWUfWvzLmo&security=reality&sid=dc8109baf0f607ea&sni=storage.yandex.net&type=raw&fp=chrome#%F0%9F%87%A9%F0%9F%87%AA%20Germany%20%7C%20%5B%2ACIDR%5D%20CDN', 'vless://a1a2a3a4-b5b6-4c7c-8d8d-9e9f0f1f2f3f@up.example.com:443?type=httpupgrade&security=tls&sni=up.example.com&path=%2Fup&host=up.example.com#HTTPUpgrade-Test', 'vless://b1b2b3b4-c5c6-4d7d-8e8e-9f0a1b2c3d4e@xh.example.com:443?type=xhttp&security=tls&sni=xh.example.com&path=%2Fxh&host=xh.example.com#XHTTP-Test', 'vless://c1c2c3c4-d5d6-4e7e-8f8f-0a1b2c3d4e5f@h2.example.com:443?type=h2&security=tls&sni=h2.example.com&path=%2Fh2&host=h2.example.com#H2-Test', f'vmess://{_vmess_b64}', 'vmess://11223344-5566-7788-9900-aabbccddeeff@vuri.example.com:443?type=ws&security=tls&path=%2Fws#VMess-URI', 'trojan://mypassword@trojan.example.com:443?type=ws&sni=trojan.example.com&path=%2Ftrws#Trojan-WS', 'trojan://trojanpass@tr-reality.example:443?type=tcp&security=reality&sni=yahoo.com&pbk=8N2Wv3rQkLmXzYpQaBcDeFgHiJkLmNoPqRsTuVwXyZa&sid=6ba85179#Trojan-Reality', f'ss://{_ss_userinfo}@ss.example.com:8388?plugin=v2ray-plugin%3Btls%3Bhost%3Dss.example.com#SS-SIP002', 'ss://chacha20-ietf-poly1305:secret123@ss-plain.example.com:8443#SS-Plain', f'ssr://{_ssr_b64}', 'hy2://hy2pass@hy2.example.com:443?sni=hy2.example.com&obfs=salamander&obfs-password=obfspass&mport=20000-40000#Hy2-Test', 'hysteria2://h2pass@hysteria.example.com:8443?sni=hysteria.example.com&insecure=1#Hysteria2-Test', 'tuic://a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d:tuicpass@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr&alpn=h3#TUIC-Test', 'socks5://user:pass@socks5.example.com:1080#Socks5-Test', 'http://httpuser:httppass@http.example.com:8080#HTTP-Test', 'https://httpsuser:httpspass@https.example.com:8443#HTTPS-Test', 'wireguard://aGVsbG93b3JsZA==@wg.example.com:51820?public_key=d29ybGRoZWxsbw==&ip=10.0.0.2#WireGuard-Test']
BAD = ['vless://no-at-sign-here', 'vmess://bad-base64-payload#BadVmess', 'anytls://abc123@example.com:443#Anytls', LINKS[3]]
PAYLOAD = '\n'.join(LINKS) + '\n\n' + '\n'.join(BAD)
SAME_NAME = [f'vless://851ed0d8-a37b-452d-8ef2-5b6c2d28a060@37.18.14.121:2027?encryption=none&flow=xtls-rprx-vision&pbk=ISa-DZOI4LRRb9DHMFYm5oFqBXDjYzz0hVWUfWvzLmo&security=reality&sid=dc8109baf0f607ea&sni=storage.yandex.net&type=raw&fp={fp}#%F0%9F%87%A9%F0%9F%87%AA%20Germany%20%7C%20%5B%2ACIDR%5D%20CDN' for fp in ('android', 'chrome', 'firefox', 'qq', 'safari')]

async def main() -> None:
    progress: list[tuple[int, int, int]] = []
    res = await parse_batch(PAYLOAD, on_progress=lambda pct, done, total: progress.append((pct, done, total)), chunk_size=2)
    print(f'Парсинг завершён: ok={res.ok}, skipped={res.skipped}, total={res.total_lines}')
    assert res.total_lines == len(LINKS) + len(BAD), f'total={res.total_lines}'
    assert res.ok == len(LINKS), f'ожидалось {len(LINKS)} валидных ссылок, получено {res.ok}'
    assert res.skipped == 4, f'ожидалось 4 пропущенных, получено {res.skipped}'
    p = {x['name']: x for x in res.proxies}
    reality = p['🇩🇪 DE-01']
    assert reality['type'] == 'vless' and reality['udp'] is True
    assert reality['server'] == '193.233.201.25' and reality['port'] == 443
    assert reality['tls'] is True and reality['flow'] == 'xtls-rprx-vision'
    assert reality['servername'] == 'yahoo.com' and reality['client-fingerprint'] == 'chrome'
    assert reality['reality-opts'] == {'public-key': '8N2Wv3rQkLmXzYpQaBcDeFgHiJkLmNoPqRsTuVwXyZa', 'short-id': '6ba85179'}
    assert reality['network'] == 'tcp'
    vmess_ws = p['VMess-WS-TLS']
    assert vmess_ws['type'] == 'vmess' and vmess_ws['server'] == 'vmess.example.com'
    assert vmess_ws['port'] == 443 and vmess_ws['tls'] is True
    assert vmess_ws['network'] == 'ws' and vmess_ws['ws-opts']['path'] == '/vpath'
    trojan_ws = p['Trojan-WS']
    assert trojan_ws['type'] == 'trojan' and trojan_ws['password'] == 'mypassword'
    assert trojan_ws['network'] == 'ws' and trojan_ws['sni'] == 'trojan.example.com'
    ss_node = p['SS-SIP002']
    assert ss_node['type'] == 'ss' and ss_node['cipher'] == 'aes-256-gcm'
    assert ss_node['password'] == 'pass123' and ss_node['plugin'] == 'v2ray-plugin'
    ssr_node = p['SSR-Test']
    assert ssr_node['type'] == 'ssr' and ssr_node['server'] == '1.2.3.4'
    assert ssr_node['port'] == 8388 and ssr_node['protocol'] == 'auth_aes128_md5'
    hy2_node = p['Hy2-Test']
    assert hy2_node['type'] == 'hysteria2' and hy2_node['password'] == 'hy2pass'
    assert hy2_node['obfs'] == 'salamander' and hy2_node['obfs-password'] == 'obfspass'
    tuic_node = p['TUIC-Test']
    assert tuic_node['type'] == 'tuic' and tuic_node['uuid'] == 'a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d'
    assert tuic_node['password'] == 'tuicpass' and tuic_node['congestion-controller'] == 'bbr'
    socks_node = p['Socks5-Test']
    assert socks_node['type'] == 'socks5' and socks_node['username'] == 'user' and (socks_node['password'] == 'pass')
    http_node = p['HTTP-Test']
    assert http_node['type'] == 'http' and http_node['port'] == 8080
    https_node = p['HTTPS-Test']
    assert https_node['type'] == 'http' and https_node['tls'] is True and (https_node['port'] == 8443)
    wg_node = p['WireGuard-Test']
    assert wg_node['type'] == 'wireguard' and wg_node['ip'] == '10.0.0.2'
    assert wg_node['public-key'] == 'd29ybGRoZWxsbw=='
    yaml_text = build_yaml(res.proxies)
    assert yaml_text.startswith('proxies:\n')
    assert 'name: "🇩🇪 DE-01"' in yaml_text
    assert 'name: VMess-WS-TLS' in yaml_text
    assert 'name: Hy2-Test' in yaml_text
    assert 'name: WireGuard-Test' in yaml_text
    dupes_res = await parse_batch('\n'.join(SAME_NAME))
    assert dupes_res.ok == 5
    names = [x['name'] for x in dupes_res.proxies]
    assert names[0] == '🇩🇪 Germany | [*CIDR] CDN'
    assert names[1] == '🇩🇪 Germany | [*CIDR] CDN #2'
    assert names[2] == '🇩🇪 Germany | [*CIDR] CDN #3'
    assert names[3] == '🇩🇪 Germany | [*CIDR] CDN #4'
    assert names[4] == '🇩🇪 Germany | [*CIDR] CDN #5'
    print('OK: all protocol tests and selftest passed!')
if __name__ == '__main__':
    asyncio.run(main())
