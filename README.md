# Smart DNS

Текущая продуктовая задача — [issue #12](https://github.com/Kwentin3/smart-dns/issues/12),
расширяющий [issue #3](https://github.com/Kwentin3/smart-dns/issues/3):
[текущее состояние и обязательный остаток](docs/product-goal.md). Private pilot
развёрнут с отдельным разрешением владельца; [техническая приёмка production](docs/reports/2026-11-06/production-pilot.md)
завершена. Готовый community-каталог и ежедневный сбор обновлений доставлены в
`main`; [первый запуск](https://github.com/Kwentin3/smart-dns/actions/runs/42276996672)
завершился без изменений источника. По [допуску #14](https://github.com/Kwentin3/smart-dns/issues/14)
на VPS применён полный приватный Fancy GEO с сохранением прежнего GeoBlock/AI
baseline: 2508 native rules, wire scope 114 exact + 1140 suffix roots, лимит 4096.
Native status `matches`; 64 внешних DNS/TLS checks и 12 соседних маршрутов PASS.
[Production evidence](docs/reports/2026-11-07/production-fancy-rollout.md).
Владелец подтвердил, что Gemini заработал. Полная приёмка прочих функций
приложений/смены сети ещё не завершена.

Изолированный пилот [issue #1](https://github.com/Kwentin3/smart-dns/issues/1):
AdGuard Home → точные HostSNI rules Traefik → HAProxy → фиксированный public IPv4.
В этом историческом baseline production, Hermes и общий Traefik не изменялись.
Локальные предпочтения и границы одобрения задаёт [сервисный каталог](rules/pilot.json),
а сведения community-источника — [принятый snapshot](rules/registry.json).
Вход, сообщения, CDN, файлы, повторные
сессии и устройства целиком пока не приняты. Gemini уже включён в GEO-профиле;
владелец подтвердил работу пользовательской сессии. Полный прогон функций и
перехода Wi-Fi → мобильная сеть пока отложен.
[Историческая приёмка рефакторинга](docs/refactor.md).

`rules/pilot.json` и Meta snapshot в Git остаются воспроизводимым публичным
AI-пилотом/discovery. Полные действующие GEO preferences/snapshot находятся в
приватных `.local/policy/rules/` на VPS: MIT у Fancy не устанавливает разрешения
на перепубликацию всех агрегированных сторонних списков. Status/apply для этой установки получают явные private `--rules`
и `--registry`; локальный `catalog list` без них показывает публичный пример,
а не удалённый runtime. Клиентами по-прежнему управляет native AdGuard Home.

Полный профиль готовит `python3 tools/bootstrap_geoblock.py`: два готовых списка
из одного pinned Git source, строгие suffix literals, прежний принятый AI-набор
сохранён. По умолчанию output — приватная `.local/geoblock-policy`, без запуска
сервисов и изменения DNS. Исторические `geoblock-proposals` templates собирают только приватные
предложения, ежедневно 06:31 UTC с задержкой до пяти минут; не выполняют deploy и
не включают новые roots. Публичный Meta collector остаётся отдельным discovery.

## Устройство

Для действующей установки есть один операторский вход:

На VPS установлен shortcut `smart-dns`: например, `smart-dns status`.

```sh
python3 tools/product.py status
python3 tools/product.py list
python3 tools/product.py show geoblock
python3 tools/product.py off chatgpt --reason 'Paused by owner'
python3 tools/product.py on chatgpt --reason 'Enabled by owner'
python3 tools/product.py add example --suffix example.org --reason 'Reviewed service'
python3 tools/product.py exclude api.example.org --reason 'Keep this name direct'
python3 tools/product.py include api.example.org --reason 'Restore routing'
python3 tools/product.py refresh
python3 tools/product.py rollback --to GENERATION
```

`list` и `show ID` читают discovery и desired policy из
deployment manifest без сети и admin password. Показывают ON/OFF/discovered,
source/commit, ограничения и исключения. Они явно не подтверждают runtime,
сетевой путь или функции приложения; для native actual используется `status`.
Установленный shortcut использует проверенный source PR #13.

Для действующего source profile `russia-fancy-geo` используется готовый смешанный
exact/suffix JSON; прежний baseline сохранён как frozen local policy. Существующий
product refresh обновляет Fancy, клиенты/admin остаются у AGH. [Исследование и
границы источника](docs/reports/2026-11-07/universal-geo-candidate.md).

Пути к приватным inputs, releases и management задаются один раз в
`/opt/smart-dns/.local/deployment.json`; [пример](config/deployment.example.json)
не содержит секретов. `status` читает actual из native AGH и relay. Изменяющие
команды готовят candidate и restore, вызывают существующий service-only operator
и публикуют preferences после успешного readback. Клиенты и администратор остаются
у AGH. Изменение состава fixed origins требует согласованной карты адресов;
текущий production GEO использует native dynamic origins.

OFF отдельного сервиса имеет приоритет над включённой группой. Домены, нужные
другому включённому отдельному сервису, сохраняются и видны в `shared_routing`.
OFF группы снимает её массовое разрешение, сохраняя отдельные включённые сервисы.
`exclude`/`include` меняют явное исключение одного имени; `include` не отменяет OFF.

Новые [product-refresh templates](config/product-refresh.service.in) запускают
тот же `refresh` ежедневно: обновление известного источника проходит native
apply/readback/restore, новые roots остаются pending; удаления и смена лицензии —
на review. Ошибка источника сохраняет принятый snapshot и runtime. Полное
предложение хранится приватно. Старые proposal-only templates остаются отдельным
режимом; два таймера одновременно для одной политики не нужны.

`tools/certificate_deploy.py` публикует уже выпущенную Certbot пару в существующий
TLS-каталог после проверки цепочки, имён, ключа и срока. AGH подхватывает файлы без
рестарта; hook проверяет выдаваемый fingerprint и восстанавливает прежнюю пару
при сбое. Выпуском и продлением владеет существующий Certbot: native acme-dns
обслуживает делегированный challenge namespace, готовый client служит auth hook.
В текущей установке delegation, staging, production issuance и повторный renewal
без ручных auth overrides проверены. [Автопродление и evidence](docs/reports/2026-11-07/acme-renewal-candidate.md).

Один [каталог предпочтений](rules/pilot.json) вместе с [registry snapshot](rules/registry.json)
через `catalog_rules` и `tools/render.py` порождает DNS rules, Traefik labels и
HAProxy ACL/backends. Готовый индекс MetaCubeX содержит сервисы, категории и группы;
в полном индексе не каждая запись означает отдельный геосервис. Определения
загружаются только для выбранных сервисов. Exact и suffix сохраняют разный смысл;
новые имена вне локального `approved_scope` и неподдерживаемые predicates остаются
видимыми кандидатами. Ручные hosts, enabled/reason и исключения не заменяются
внешним списком. [Источники и лицензии](rules/sources.json) сохраняют provenance.
Render не обращается в сеть и не
запускает сервисы. Origins — reviewed numeric public IPv4:443; private/reserved,
metadata, multicast, IPv6, собственный ingress и provider-service IP отвергаются.
В fixed-origin режиме runtime DNS/fallback нет.

Для candidate доступен optional `settings.origin_dns: ["9.9.9.9"]`: штатный
HAProxy разрешает одобренный SNI и проверяет выбранный IPv4 перед соединением.
В этом режиме `--origins` не передают. Он принят в общем runtime и текущем private
pilot. По умолчанию lab renderer сохраняет fixed-origin режим.

AGH использует native ClientID-only `allowed_clients` и обязательную admin-учётную
запись с bcrypt hash. DNS-сеть соединяет AGH с edge и, при DoT, с relay. Plain DNS
5353 в lab без DoT остаётся внутренним и не публикуется; при DoT plain DNS отключён.
Public DoH route не ведёт к management;
native login дополнительно защищает прямой доступ. AGH работает под UID/GID
оператора с writable config directory и только необходимой NET_BIND_SERVICE.

Native Traefik middleware сначала задаёт канонический Host, затем применяет
общий для DoH-router бюджет 20 req/s, burst 40 и 8 in-flight requests. Это lab
параметры, не доказанный production capacity threshold. AGH `dns.ratelimit:20`
ограничивает только UDP. DoH-router не пишет access logs; lab field allowlist
защищает также denied URL, сохраняя журнал соседнего сайта. Production logging
этим не принят; проверка фактического production описана отдельно в его отчёте.

HAProxy сохраняется ради global `maxconn 256` и idle timeouts 60s. Native Traefik
TCP inFlightConn ограничивает по IP; dialTimeout не заменяет idle timeout.
Включение file provider общего edge отдельно не разрешено.

## Воспроизведение

В [сервисном каталоге](rules/pilot.json) меняют `services[].enabled`, причину,
ручные `domains`/`domain_suffixes`, локальный `upstream.approved_scope` и
`excluded_domains`. Новое имя вне approved scope требует отдельного review;
обновлённое membership внутри уже одобренной suffix-границы может проецироваться
без расширения этой границы. Неподдерживаемые regex/keyword не превращаются в
разрешение всего сервиса. Для выбора и просмотра есть небольшой CLI:

```sh
python3 tools/catalog.py list --search spotify
python3 tools/catalog.py show spotify
# После просмотра definition: изменить только desired preferences/snapshot.
python3 tools/catalog.py enable spotify --approve-source-scope --reason 'Reviewed service scope for a separate pilot'
python3 tools/catalog.py disable spotify --reason 'Pilot paused'
```

`list` читает принятый индекс. `show`/`enable` могут получить отсутствующее
определение из публичного источника; executable code источника не запускается.
Перед включением partial definition требуется осознанное `--accept-literal-only`;
это не включает его неподдерживаемые predicates. Изменения review/commit в Git
не равны применённому runtime. Renderer
создаёт новый candidate; он не применяет его к работающему AGH и не подтверждает
active state. `settings.client_ids` — только bootstrap: повторная запись полной
конфигурации может вернуть уже отозванного клиента.

Предложения обновлений community-источника:

```sh
python3 tools/source_proposals.py
# .local/source-proposals/latest.json: index/rule diffs + pinned candidate + GPL attribution
```

Ежедневный/manual workflow собирает полный индекс и выбранные определения,
проверяет candidate и создаёт/обновляет один PR `automation/service-registry`.
В PR меняется только принятый registry snapshot с provenance и текстом лицензии;
local preferences и runtime не меняются. Автоматического merge или deploy пока нет.
Bot PR не запускает независимый PR CI: candidate contracts выполняются в самом
trusted workflow и так обозначены в отчёте. Workflow активен в default branch
(`main`), Actions разрешено создавать PR при default read permissions. Первый
default-branch запуск проверил collector/artifact/extraction с `changed=false`;
фактическая публикация первого PR ожидает изменения источника. Ошибка
fetch/validation оставляет принятый набор и прежний proposal.

Для уже работающего пилота `tools/service_policy.py --lab-only` (стенд) или
`--production` (отдельно разрешённое внедрение) выполняет service-only
apply/readback/rollback через native API и Compose. Требуются старый
accepted bundle, новый render candidate и его исходные settings/catalog. Он не
записывает полную конфигурацию AGH и не возвращает отозванных клиентов из bootstrap.
На время операции relay, включая DoT, останавливается. Production representation
создаётся `tools/render.py --production`: два контейнера, отдельная DNS-сеть,
native labels текущего edge. Этот флаг сам по себе не даёт разрешения на deploy и
не меняет общий Traefik. [Приёмка стенда](docs/reports/2026-11-06/product-native-acceptance.md).

У того же оператора есть `--status-only`: с теми же target/settings/rules/registry,
project и management credentials, но без `--accepted`, `--candidate` и `--out`.
Он читает actual generation из mounted relay, сверяет native DNS rules, image,
labels и байты policy с desired; показывает drift, pending scopes и partial
coverage. Этот режим ничего не применяет и не пишет receipt. `catalog list` ON/OFF
означает desired selection; актуальность runtime подтверждает именно readback.
[Новый registry/native срез](docs/reports/2026-11-06/registry-acceptance.md).

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

Этот fixed-origin runner и старые smoke probes предназначены для exact-host
набора: они читают ту же registry projection, а при активных suffix rules явно
отказываются от запуска. Native suffix acceptance проверяется отдельно; exact
smoke не выдаётся за приёмку suffix-сервиса или всего community-каталога.

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

Первый private rollout отдельно разрешён и выполнен, включая согласованное
пересоздание общего edge; это не общее разрешение на любые будущие изменения
Traefik. Новое внедрение требует конкретных private Compose/labels, сертификата,
сетей, admin credentials, origin policy, logging, limits и rollback window.
Второй public 443, catch-all и новый file provider не требуются. DNS ClientID
не защищает public relay от прямого доступа к разрешённым SNI; shared-origin
domain fronting остаётся ограничением. Product/device приёмка — отдельный этап.

[Архитектура](docs/architecture.md) · [безопасность](docs/security.md) ·
[откат](docs/rollback.md) · [DNS/клиенты](docs/dns-research.md) ·
[Relay research](docs/relay-research.md) · [реестры](docs/registry-research.md).
