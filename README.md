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

1. Соберите модуль: `python build.py --module desync --os windows` (или `android`).
2. Скопируйте содержимое `examples/moduledesync/dist/desktop/<os>_<arch>/` (или `dist/android/<abi>/`)
   в каталог модулей AntiNet: Desktop — `<exe>/modules/desync/`, Android — `filesDir/modules/desync/`.
3. Добавьте конфиг со ссылкой, например `desync://general` или `desync://alt#YouTube`.
4. В карточке модуля можно выбрать пресет (`general` / `alt` / …) и флаг auto.

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

## Сборка

```
python build.py --doctor --module desync --os all
python build.py --module desync --os windows
python build.py --module desync --os android --abis arm64-v8a
python build.py --module desync --os all
```

## Лицензия

MIT (`LICENSE`). Каноны `shared/` — MIT, инжектируются в бинарь при сборке.
