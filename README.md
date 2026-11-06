# Smart DNS

Изолированный пилот по [issue #1](https://github.com/Kwentin3/smart-dns/issues/1):
AdGuard Home → точные TCP HostSNI rules Traefik → HAProxy → фиксированный origin.
Production VPS и Hermes не изменяются. Реальное развёртывание требует отдельного разрешения.

Пилот содержит **два точных имени**, `chatgpt.com` и `claude.ai`. Это проверка
безопасного маршрута, а не готовность всего ChatGPT/Claude: вход, CDN, загрузки,
мобильные приложения и дополнительные домены пока не приняты. Gemini отложен.

## Что проверено

Настоящий AGH отклоняет анонимный/неизвестный ClientID через DNS REFUSED
(HTTP при этом **200**). Точные A rewrite, AAAA/HTTPS/SVCB NODATA, passthrough с
проверкой origin-сертификатов, отказ чужому SNI и соседний HTTP router проверены
на отдельном Linux-стенде. [Отчёт и ограничения](docs/reports/2026-11-06/acceptance.md).
После ревью дополнительно проверены смешанный регистр SNI и 15 сырых URL DoH:
[правки и повторная проверка](docs/reports/2026-11-06/review-followup.md).

Один [reviewed список](rules/pilot.json) порождает DNS rules, Traefik labels и
HAProxy ACL/backends. Внешние [реестры](rules/sources.json) — предложения;
автоматического импорта/обновления/деплоя нет. Лицензия двух основных кандидатов
не установлена, их содержимое сюда не копируется. Реальные настройки и секреты
хранятся только вне Git.

## Воспроизведение

Нужны Python 3.11+ (stdlib), Docker Engine и Compose v2 на **разрешённом Linux
полигоне**. Этот проект не устанавливает Docker и не меняет системный DNS.

```sh
python3 -m unittest discover -s tests -v
# Только в отдельной disposable копии на полигоне; не production:
timeout --signal=TERM --kill-after=30 480 bash tools/run_lab.sh
```

Стенд фиксирует reviewed исходные имена, получает для проверки публичные A
origin, создаёт случайный временный ID и рендерит Compose. Разрешены внешние DNS
и TLS к двум выбранным origin; учётных записей, GitHub-токенов и production data
в стенде нет. Разрешение A в этом скрипте относится к тесту, а не к автоматическому
обновлению production. Там каждый набор origin проверяется вручную.

Compose использует собственную сеть и localhost-порты 18443/18444, четыре
digest-pinned образа, максимум 128 MiB/0.5 CPU/100 PID на контейнер, логи 2×5 MiB.
В DNS-контейнере используется UID/GID оператора; writable каталог конфигурации
нужен для штатной atomic-записи AGH. Весь файл конфигурации не монтируется отдельно.
Нативный бинарник образа требует NET_BIND_SERVICE; остальные capabilities удалены.
Никакие сети/тома существующих приложений не подключаются. Docker socket у
тестового Traefik чувствителен даже при `:ro`: это fixture для доверенного полигона.

`run_lab.sh` прекращает работу при существующем task-project/следах незакрытого
прогона; не удаляйте их вслепую. EXIT trap собирает логи, удаляет свой Compose
project/network/volumes и сравнивает ID существовавших контейнеров. Исходники и
`.local/` остаются для readback/сбора; после сбора удалить только disposable
копию эксперимента. Образы остаются в Docker cache, без работающих сервисов.

Для ручного рендера без запуска:

```sh
python3 tools/render.py --settings .local/settings.json --origins .local/origins.json
docker compose -f generated/compose.lab.json config -q
```

[settings.example.json](config/settings.example.json) содержит вымышленные
сетевые сведения и нерабочий секрет. Замените ID на криптографически случайный
32–64-символьный lowercase hex; добавьте все собственные домены и публичные IP в
запреты. `origins.json` — объект `точный-домен: проверенный-публичный-IPv4` для
каждого имени из pilot.json, без лишних записей. Render отвергает private,
reserved, metadata, multicast, IPv6, собственный ingress и provider-service IP.
Не отправляйте `.local/settings.json` и generated/ в PR: там ClientID.

DoH router принимает только `/dns-query` и `/dns-query/<32–64 lowercase hex>`;
анонимный/неизвестный ID по-прежнему отклоняет сам AGH. `dns.ratelimit: 20`
ограничивает UDP DNS, **не DoH**. Перед production нужен отдельный план лимитов
DoH; IP прокси в `allowed_clients` для этого не добавлять. AGH management/API
без пароля нельзя помещать в общую сеть приложений: нужна узкая сеть
Traefik↔AGH либо отдельно одобренная защита management.

Нативная Windows-проверка отдельно: скачать
[официальный AGH v0.107.80](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.80),
сверить ZIP с release `checksums.txt`, распаковать в `.local/agh/`, затем:

```powershell
python tools/test_native_agh.py --binary .local/agh/AdGuardHome/AdGuardHome.exe
```

Скрипт использует localhost fixture и порты 13000/15353, не устанавливает службу,
не меняет DNS клиента и завершает свои процессы. Перед запуском убедиться, что
порты свободны. Бинарный checksum и команды приведены в отчёте.

## Перед production

Нужна отдельно одобренная private Compose-интеграция: только новые DNS/relay
контейнеры и labels существующего Traefik, без второго public 443, catch-all или
file provider. У production Traefik уже включён access log: DoH URL содержит
секрет, поэтому до активации обязательна проверка исключения/редакции этих путей
с согласованным владельцем логирования. Перезапуск общего Traefik не разрешён
этим пилотом. Имена ingress/certresolver/network и SSH-доступ в репозиторий не
публикуются.

[Архитектура](docs/architecture.md) · [безопасность](docs/security.md) ·
[откат и cache/drain](docs/rollback.md) · [DNS/клиенты](docs/dns-research.md) ·
[выбор Relay](docs/relay-research.md) · [реестры](docs/registry-research.md).
