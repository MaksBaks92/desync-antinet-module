# module desync — SOCKS DPI-desync для AntiNet

Локальный SOCKS5-модуль по модели [ByeByeDPI](https://github.com/romanvht/ByeByeDPI):
AntiNet гонит трафик в helper → protect-dial → на **первом payload** desync
(OOB / split / disorder / fake / multisplit), затем bidi-relay. Своего VPN/TUN нет.

Схема: `desync://`.

## Как у ByeByeDPI

| ByeByeDPI | Этот модуль |
|---|---|
| VpnService → hev-socks5-tunnel → ciadpi SOCKS | AntiNet VPN → модуль SOCKS (уже есть) |
| Дефолт: OOB, split pos=1, hosts=Нет | пресет `byedpi`, method=`oob`, hostsMode=`all` |
| whitelist / blacklist хостов | `hostsMode` + `userDomains` + builtin lists |
| Свои списки доменов в UI | настройка «Свои домены» + `profileDir/user-hosts.txt` |

## Свои домены

1. В карточке модуля: поле **Свои домены** (по одному на строку).
2. Файл **`user-hosts.txt`** в каталоге профиля helper (создаётся при старте).
3. **Встроенные списки** (через запятую): `youtube`, `googlevideo`, `discord`,
   `telegram`, `social`, `cloudflare`, `general` — из ассетов ByeByeDPI.

Режим **Хосты**:
- `all` — desync на весь TLS/HTTP (как ByeByeDPI «Нет»)
- `whitelist` — только домены из своих+builtin
- `blacklist` — всё, кроме списка

## Ссылки

| Ссылка | Смысл |
|---|---|
| `desync://byedpi` | дефолт ByeByeDPI |
| `desync://general` | Flowseal-like multisplit |
| `desync://alt#Домашний` | alt, имя «Домашний» |
| `desync://passthrough` | без desync |

## Ограничения

На SOCKS-пути нет WinDivert/NFQUEUE: seqovl, fooling=ts, SYN-правки недоступны.
UDP ASSOCIATE — passthrough (без QUIC fake). OOB на Windows откатывается к split.

## Сборка

Только CI (GitHub Actions). Локально для отладки:

```bash
python build.py --module desync --os android --abis arm64-v8a
```
