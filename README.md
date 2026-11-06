# Smart DNS

Текущая продуктовая задача — [issue #3](https://github.com/Kwentin3/smart-dns/issues/3):
[оценка разрывов и последовательность](docs/product-goal.md). Изолированный пилот
ниже — техническая база; управляемый product и устройства ещё не приняты.

Изолированный пилот [issue #1](https://github.com/Kwentin3/smart-dns/issues/1):
AdGuard Home → точные HostSNI rules Traefik → HAProxy → фиксированный public IPv4.
Production, Hermes и общий Traefik не изменяются. Список содержит только
`chatgpt.com` и `claude.ai`, без поддоменов. Вход, сообщения, CDN, файлы, повторные
сессии и устройства целиком пока не приняты; Gemini отложен.
[Текущий GOAL и решения](docs/refactor.md).

## Устройство

Один [reviewed список](rules/pilot.json) через `tools/render.py` порождает DNS
rules, Traefik labels и HAProxy ACL/backends. [Внешние реестры](rules/sources.json)
дают предложения, без автоматического импорта. Render не обращается в сеть и не
запускает сервисы. Origins — reviewed numeric public IPv4:443; private/reserved,
metadata, multicast, IPv6, собственный ingress и provider-service IP отвергаются.
Runtime DNS/fallback нет.

Для candidate доступен optional `settings.origin_dns: ["9.9.9.9"]`: штатный
HAProxy разрешает одобренный SNI и проверяет выбранный IPv4 перед соединением.
В этом режиме `--origins` не передают. Механизм проверен отдельно; полный
интегрированный runtime пока не принят. По умолчанию остаётся fixed-origin режим.

AGH использует native ClientID-only `allowed_clients` и обязательную admin-учётную
запись с bcrypt hash. Узкая DNS-сеть соединяет только AGH и lab Traefik. Plain DNS
5353 остаётся внутренним и не публикуется. Public DoH route не ведёт к management;
native login дополнительно защищает прямой доступ. AGH работает под UID/GID
оператора с writable config directory и только необходимой NET_BIND_SERVICE.

Native Traefik middleware сначала задаёт канонический Host, затем применяет
общий для DoH-router бюджет 20 req/s, burst 40 и 8 in-flight requests. Это lab
параметры, не доказанный production capacity threshold. AGH `dns.ratelimit:20`
ограничивает только UDP. DoH-router не пишет access logs; lab field allowlist
защищает также denied URL, сохраняя журнал соседнего сайта. Production logging
этим не принят.

HAProxy сохраняется ради global `maxconn 256` и idle timeouts 60s. Native Traefik
TCP inFlightConn ограничивает по IP; dialTimeout не заменяет idle timeout.
Включение file provider общего edge отдельно не разрешено.

## Воспроизведение

В [сервисном каталоге](rules/pilot.json) меняют `services[].enabled`, причину,
одобренные exact domains и `excluded_domains`. Это desired state. Renderer
создаёт новый candidate; он не применяет его к работающему AGH и не подтверждает
active state. `settings.client_ids` — только bootstrap: повторная запись полной
конфигурации может вернуть уже отозванного клиента.

Предложения обновлений community-источника:

```sh
python3 tools/source_proposals.py
# .local/source-proposals/latest.json: raw diff + immutable SHA + MIT attribution
```

Scheduled/manual workflow только сохраняет этот артефакт; расписание требует
default branch. Новые правила включаются после review. Ошибка fetch сохраняет
предыдущий proposal и accepted каталог. Ни deploy, ни автоматический импорт не выполняются.

Для уже работающего пилота `tools/service_policy.py --lab-only` (стенд) или
`--production` (отдельно разрешённое внедрение) выполняет service-only
apply/readback/rollback через native API и Compose. Требуются старый
accepted bundle, новый render candidate и его исходные settings/catalog. Он не
записывает полную конфигурацию AGH и не возвращает отозванных клиентов из bootstrap.
На время операции relay, включая DoT, останавливается. Production representation
создаётся `tools/render.py --production`: два контейнера, отдельная DNS-сеть,
native labels текущего edge. Этот флаг сам по себе не даёт разрешения на deploy и
не меняет общий Traefik. [Приёмка стенда](docs/reports/2026-11-06/product-native-acceptance.md).

Для render/service operation достаточно системного Python 3.9+ (stdlib);
стендовые проверки выполнялись также на Python 3.11+. Нужен Docker Engine/Compose v2 на разрешённом Linux
полигоне. Docker и системный DNS скриптом не устанавливаются/не изменяются.

```sh
python3 -m unittest discover -s tests -v
# Только disposable копия на разрешённом полигоне:
timeout --signal=TERM --kill-after=30 480 bash tools/run_lab.sh
```

Четыре digest-pinned образа: [images.lock.json](config/images.lock.json).
Собственные сети, localhost 18443/18444; на контейнер 128 MiB/0.5 CPU/100 PID,
логи 2×5 MiB. Разрешены внешние DNS/TLS к двум origin; production data и аккаунты
продуктов не нужны. Случайный ClientID и публичный admin fixture — только для lab.
Docker socket `:ro` остаётся привилегированным доступом к daemon API.

Runner отвергает занятые порты и существующий task project; EXIT trap удаляет
свои контейнеры/сети и сравнивает существовавшие container IDs. `.local/` и образы
остаются для readback; disposable копию удаляют после сбора. Не удаляйте следы
незакрытого прогона вслепую. Результаты изменённого кода и cleanup фиксируются в
[refactor acceptance](docs/reports/2026-11-06/refactor-acceptance.md).
[Первый acceptance](docs/reports/2026-11-06/acceptance.md) и
[PR2 follow-up](docs/reports/2026-11-06/review-followup.md) относятся к прежним
кандидатам и не доказывают результат текущего.

Рендер без запуска требует нового output directory:

```sh
python3 tools/render.py --settings .local/settings.json --origins .local/origins.json --out .local/candidate-001
docker compose -f .local/candidate-001/compose.lab.json config -q
```

Повторная запись в существующий `--out` завершается ошибкой. Полный комплект
публикуется rename из соседнего staging directory; это не атомарное обновление
работающих сервисов. Hash приватных settings/файлов хранится отдельно: snapshot
SHA покрывает rules/origins, а не все settings.

[settings.example.json](config/settings.example.json) содержит placeholders.
Задайте случайные lowercase-hex ClientIDs длиной 32–64, `admin_username`,
`admin_password_hash`, свои зоны и public IP. Получите bcrypt штатным
`htpasswd -Bni <admin_username>` с безопасным вводом и сохраните hash после `:` в
приватные settings. Не передавайте пароль аргументом и не выводите секреты в
общий transcript. Runtime Python bcrypt dependency не нужен. Публичный fixture
`lab-only-change-me` никогда не используется в production.

Windows: скачайте [официальный AGH v0.107.80](https://github.com/AdguardTeam/AdGuardHome/releases/tag/v0.107.80),
сверьте archive checksum с release `checksums.txt`, распакуйте в `.local/agh/`.
Через приватный редактор создайте `.local/native-admin-password` с lab-only
fixture паролем, ограничьте доступ к файлу. При свободных портах 13000/15353:

```powershell
python tools/test_native_agh.py --binary .local/agh/AdGuardHome/AdGuardHome.exe --admin-password-file .local/native-admin-password
```

Harness использует localhost upstream fixture и завершает свои процессы; служба
и DNS клиента не меняются. Не коммитьте settings, generated configs, пароли,
ClientID URL, ключи и private evidence.

## Перед production

Отдельно согласуются private Compose/labels, сертификат, узкая сеть, admin
credentials, origin snapshot, logging, limits и rollback window. Второй public
443, catch-all, file provider и restart общего edge не входят в пилот. DNS ClientID
не защищает public relay от прямого доступа к разрешённым SNI; shared-origin
domain fronting остаётся ограничением. Product/device приёмка — отдельный этап.

[Архитектура](docs/architecture.md) · [безопасность](docs/security.md) ·
[откат](docs/rollback.md) · [DNS/клиенты](docs/dns-research.md) ·
[Relay research](docs/relay-research.md) · [реестры](docs/registry-research.md).
