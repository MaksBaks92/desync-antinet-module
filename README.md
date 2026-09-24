# Модуль «Desync» для AntiNet (`desync://`)

Самодостаточный архив протокол-модуля AntiNet: локальный SOCKS5 с DPI-desync стратегиями
(ByeDPI-like на SOCKS-пути) и готовыми пресетами в духе
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).

Собирается под **Android + Windows/Linux/macOS** без репозитория AntiNet.

## Что внутри

| Путь | Что это |
|---|---|
| `README.md` | этот файл |
| `MODULE_API.md` | контракт AntiNet-модулей |
| `MODULE_SYSTEM.md` | тулчейн и публикация |
| `build.py` | сборщик helper'ов |
| `examples/moduledesync/` | сам модуль: `module.json` + Go helper |
| `shared/` | каноны (socks5, protect, offtun, dns, lifecycle, hostproto, entry) — инжектит `build.py` |

## Установка в AntiNet

**Сборка только в GitHub Actions.** Берите zip с
[Releases](https://github.com/MaksBaks92/desync-antinet-module/releases) или Artifacts в Actions.

1. Распакуйте zip в `modules/desync/` (Desktop: рядом с exe; Android: filesDir).
2. Добавьте конфиг `desync://general` (или другой пресет).
3. Карточка модуля ведёт на репозиторий; автообновление — через `antinet-module.json` на `main`.

После обновления с 1.0.0 → 1.0.1 переустановите бандл (или дождитесь авто-обновления, если `updateUrl` уже подхватился после ручной подстановки манифеста).

## Как работает

```
приложения → AntiNet (TUN) → SOCKS5 модуля → strategy (split/fake/…) → protect dial → интернет
```

IP не скрывается, своего шифрования нет — только запутывание DPI на первых сегментах TCP.

## Пресеты

`general`, `alt`, `alt2`, `youtube`, `discord`, `safe`, `auto`, `passthrough` —
см. `examples/moduledesync/README.md`.

## Ограничения vs zapret2 / winws

Нет packet-path (WinDivert / NFQUEUE): **seqovl**, **fooling=ts**, IP-frag, правка SYN и
полноценный fake-inject как у winws **недоступны**. Они логируются как `unsupported`.
UDP ASSOCIATE в MVP — passthrough без QUIC/Discord UDP-fake.

## Сборка (CI)

Workflow: `.github/workflows/release.yml`

- push в `main` / `workflow_dispatch` → артефакты Actions
- тег `v*` → GitHub Release с zip + `antinet-module.json`

Локальный `build.py` — только для разработки; дистрибутив пользователям — с GitHub.

## Лицензия

MIT (`LICENSE`). Каноны `shared/` — MIT, инжектируются в бинарь при сборке.
