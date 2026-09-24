# module desync — SOCKS DPI-desync для AntiNet

Локальный SOCKS5-модуль: AntiNet гонит трафик в helper, тот делает protect-dial и на
**первом клиентском payload** применяет стратегию desync (split / multisplit / fake / tlsrec),
затем обычный bidi-relay. Своего VPN/TUN нет — захват уже у хоста.

Схема ссылок: `desync://`.

## Ссылки

| Ссылка | Смысл |
|---|---|
| `desync://general` | пресет general |
| `desync://alt#Домашний` | alt, имя в карточке «Домашний» |
| `desync://auto?auto=1` | auto + флаг failover |
| `desync://passthrough` | без desync |
| `desync:general` / JSON | `normalize` → канон `desync://…` |

Пресет также задаётся в карточке модуля (`settings.preset`) и перекрывает путь ссылки.

## Пресеты

| Имя | Intent (Flowseal) | SOCKS-реализация |
|---|---|---|
| `general` | multisplit + seqovl | multisplit (+SNI); **seqovl skipped** |
| `alt` | fake,fakedsplit + fooling=ts | fake(TTL) + multisplit; **ts/fakedsplit inject skipped** |
| `alt2` | multisplit pos=2 + seqovl | multisplit parts/pos≈2; **seqovl skipped** |
| `youtube` | google/youtube lists | fake + multisplit + tlsrec |
| `discord` | discord hostlist | fake + multisplit (UDP-fake — MVP passthrough) |
| `safe` | мягкий режим | один split |
| `auto` | цепочка | general→alt→alt2→safe (см. лог; полный failover — реконнект) |
| `passthrough` | — | чистый проброс |

Hostlists (embed): `lists/list-general.txt`, `list-google.txt`, `list-exclude.txt`
(стартовые списки в духе Flowseal).

## Ограничения (важно)

На SOCKS-пути **нет** WinDivert/NFQUEUE/raw inject. Поэтому **не поддерживаются**:

- `--dpi-desync-split-seqovl` / seq overlap inject
- `fooling=ts` / badseq / IP fragmentation
- полноценный `fakedsplit` как у winws
- правка SYN / wscale
- Discord/QUIC UDP-fake (UDP ASSOCIATE = passthrough в MVP)

Модуль логирует `unsupported` и применяет ближайший эквивалент (write-split / TTL-fake).

## Сборка

Из корня репозитория:

```bash
python build.py --module desync --os windows
python build.py --module desync --os android --abis arm64-v8a
```

Артефакты: `examples/moduledesync/dist/desktop/<os>_<arch>/` и `dist/android/<abi>/`.

Контракт — корневой `MODULE_API.md`.
