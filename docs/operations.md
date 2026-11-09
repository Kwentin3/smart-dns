# Сопровождение действующего Smart DNS

Точка входа для production. Проверено read-only **2026-11-07** в рамках
[GOAL #16](https://github.com/Kwentin3/smart-dns/issues/16); это описание, а не
разрешение обновлять сервер. Историю внедрения сохраняют
[production pilot](reports/2026-11-06/production-pilot.md),
[GEO rollout #14](reports/2026-11-07/production-fancy-rollout.md) и
[автопродление](reports/2026-11-07/acme-renewal-candidate.md).
Их числа, ограничения и команды относятся к дате отчёта.
[Текущий продуктовый остаток](product-goal.md) ведётся отдельно от технической приёмки.

Публикация принятой политики в приватный Git включена и проверена **2026-11-09**;
актуальные source bindings и её контракт приведены ниже. Исторические числа
остальных проверок относятся к дате соответствующего отчёта.

## Что работает и кому принадлежит

Два контейнера Compose project `smart-dns`: `dns` (AdGuard Home) и `relay`
(HAProxy). Общий Traefik принадлежит платформе VPS; Hermes/Authelia и соседние
приложения обслуживаются тем же ingress и не входят в Smart DNS.

- **DoH:** HTTPS/443 → общий Traefik с точным resolver Host/path → AGH HTTP.
  TLS DoH и его ACME storage принадлежат Traefik.
- **DoT:** TCP/853 → HAProxy → AGH TLS/853. Сертификат base+wildcard AGH
  обслуживают Certbot, acme-dns и deploy hook; это отдельная цепочка от DoH.
- **Выбранный сайт:** AGH возвращает relay IPv4; TLS/443 с исходным SNI →
  разрешённый HostSNI общего edge → HAProxy → origin IPv4. Website TLS проходит
  насквозь. Сейчас HAProxy штатно разрешает origin через заданные DNS, проверяя
  публичный IPv4 по deny policy; старые fixed-origin lab-описания здесь неприменимы.
- Обычные имена дают direct DNS. Для выбранных подавлены AAAA/HTTPS/SVCB;
  suffix охватывает корень и поддомены. Plain recursive DNS наружу не опубликован.
  Публичный UDP/TCP 53 занят **authoritative acme-dns**, только challenge namespace.

DNS-доступ проверяет native AGH ClientID, управление — отдельный native admin.
Management опубликован только на loopback `127.0.0.1:13000`; оператор использует
доверенный SSH и при необходимости loopback forwarding с native login.
ClientID не авторизует website relay: одобренные SNI публично доступны.
ECH, QUIC, встроенный DoH приложений и клиентские кеши могут обходить этот путь;
DNS/TLS-проверка не доказывает полную функцию приложения.

| Владелец / проверенная версия | Источник истины и где искать |
| --- | --- |
| Оператор `smart-dns`, source `78d1514` | `/usr/local/bin/smart-dns` → `/opt/smart-dns/releases/policy-git-78d1514/source/tools/product.py`; тот же source использует существующая refresh service. Manifest `/opt/smart-dns/.local/deployment.json` задаёт пути inputs, releases, receipts, TLS, management и `policy_git` |
| Локальные ON/OFF, ручные suffix, исключения, approved scope | Manifest `catalog`: сейчас `/opt/smart-dns/.local/policy/rules/pilot.json`. Ручная запись LemonFox сохранена после refresh |
| Community discovery / GEO definitions | Manifest `registry` и `sources` в том же private `policy/rules/`; обновляемый Fancy `russia-fancy-geo`, прежний itdog — frozen local policy с provenance. Frozen часть сама не обновляется |
| Приватная история политики, Git **2.30.2** | `policy_git.directory`: `/opt/smart-dns/.local/policy/rules`; отслеживаются только `pilot.json`, `registry.json`, `sources.json`. Remote/branch и author identity — native `.git/config`; выделенный SSH profile/key принадлежат service account и находятся вне Git |
| AGH **0.107.80** | Writable `/opt/smart-dns/runtime/agh-conf/AdGuardHome.yaml`: актуальные клиенты/отзывы, admin, effective rules; bootstrap `settings.client_ids` не заменяет этот owner. Work directory — tmpfs, durable history там нет; query log/statistics отключены |
| HAProxy **3.2.26-alpine** | Actual generation из `smart-dns status`: её `compose.production.json`, `haproxy.cfg`, `denied-v4.txt`, `snapshot.json` и `inputs/`. Relay работает из архива product-releases, AGH — из `/opt/smart-dns/runtime/compose.production.json`; это разные действующие Compose paths |
| Общий Traefik **3.6.25** | Native platform Compose `/opt/platform/traefik/compose.platform-edge.yml` с ingress overlay и `/opt/smart-dns/runtime/edge.override.json`. Полный текущий набор `-f` брать из container labels, включая env и внешние сети; не запускать по одному base-файлу |
| AGH TLS / Certbot **1.12.0** | `/opt/smart-dns/tls`; соответствующая lineage в `/etc/letsencrypt/{live,archive,renewal,accounts}`. Пароль admin — manifest `admin_password_file`, сейчас `/opt/smart-dns/runtime/admin-password`; не выводить его в терминал/отчёт |
| acme-dns **2.0.2**, client **0.3** | Unit `smart-dns-acme.service`; config `/etc/smart-dns/acme-dns.cfg`; SQLite `/var/lib/smart-dns-acme/acme-dns.db`; отдельные credentials `/etc/acmedns/clientstorage.json`; binaries `/usr/local/lib/smart-dns-acme/`. Registration штатно закрыта, API только loopback |
| Certificate deploy adapter | `/etc/letsencrypt/renewal-hooks/deploy/50-smart-dns-native` всё ещё вызывает `/opt/smart-dns/releases/product-8764162/source/tools/certificate_deploy.py`. Этот прежний source нужен; смена product shortcut сама hook не обновляет |

Production inputs, generated config и backups приватны. `rules/*.json`,
`config/settings.example.json` и `config/deployment.example.json` в Git — шаблоны
и публичный AI/discovery пример, а не копия действующего GEO/клиентского состояния.
Read-only `smart-dns list/show` показывает desired/discovery; `status` сверяет
native policy/relay, но не заменяет проверку образа AGH, сертификатов или приложения.
На дату аудита: `matches`, `fa1115bc…`, **2510 rules, 114 exact + 1141 suffix**.
Следующий refresh может сменить поколение; actual следует читать заново.

AGH/relay pinned references находятся в [image lock](../config/images.lock.json)
и effective Compose; сверять также running image ID/RepoDigest. `edge` в lock —
образ лабораторного fixture, не инструкция обновления общего Traefik, где сейчас
задан version tag. ACME binaries сверяются по
[binary lock](../config/acme-dns-binaries.lock.json). Host: Debian 11 amd64,
Python 3.9.2, Docker 29.8.0 / Compose 5.5.1, systemd 247, OpenSSL 1.1.1w.
Tools используют Python 3.9+ stdlib, Docker/Compose; certificate hook — ещё
OpenSSL и system CA. Это проверенная база, не обещание поддержки любых следующих версий.

## Версионирование принятой политики в Git: opt-in

**Включено 2026-11-09** на проверенном source `78d1514`. Первый снимок и повторный
`git-sync` сохранили одно поколение политики и один Git commit. Обычный refresh
через прежнюю systemd service принял обновление registry и создал второй commit;
оба снимка побайтно сверены с private GitHub API. Существующий `smart-dns` остаётся
владельцем операций, а отдельный
приватный Git-репозиторий версионирует его фактические `catalog`, `registry`,
`sources`. Репозиторий должен содержать только эти три файла; Git не заменяет
native readback и не становится отдельным редактором правил.

В deployment manifest можно добавить:

```json
{
  "policy_git": {
    "directory": "policy/rules",
    "remote": "origin",
    "branch": "main"
  }
}
```

`directory` разрешается относительно manifest. Это существующая рабочая Git-копия
с тремя canonical inputs внутри; например, `policy/rules/{pilot,registry,sources}.json`.
В действующей установке Git root — именно `policy/rules`, поэтому файлы в истории
имеют плоские имена. Соседние source proposals в родительском каталоге не публикуются.
`settings`, origins, пароль admin, TLS, releases и receipts должны находиться
вне неё. Имена remote/branch задаются явно. Git root не может быть общим репозиторием
исходников или содержать посторонние tracked/staged/untracked файлы.

Оператор заранее создаёт пустой приватный remote и рабочую копию, задаёт native
Git author identity и `origin`, проверяет выбранную ветку. Код не создаёт remote,
не определяет приватность сервиса по Git URL и не получает токены из policy.
Доступность Git на host и неинтерактивный доступ по SSH или через credential helper проверяются
для того же account/environment, который запускает `smart-dns-product-refresh.service`.
Python остаётся stdlib-only; Git — дополнительная host dependency только при opt-in.
Новый `tools/policy_git.py` должен войти в проверенный source release оператора:
изменение checkout само по себе не переключает установленный shortcut или unit.

Контракт выполнения:

1. До native apply проверяются Git root, bindings трёх файлов, ветка и отсутствие
   посторонних файлов, staged-изменений и запрещённых путей в истории.
   Ошибка этой проверки не применяет политику.
2. Существующий оператор применяет/проверяет политику и публикует canonical inputs.
   Только после native `matches` Git adapter получает точные принятые bytes.
3. Adapter проверяет неизменность файлов, создаёт commit при изменении bytes,
   отправляет конкретный commit в выбранный ref без force и читает remote ref назад.
   Полученный ref и blob bytes должны соответствовать принятой политике.
4. Тот же путь используется для успешных `refresh`/`rollback`/ручных операций.
   Source failure или review-required предложение не публикуются. Успешный refresh
   без изменений может завершить ранее неудавшуюся публикацию.

Детерминированы состав трёх файлов, их точные bytes, `content_sha256`, порядок
операций и исходы. Повторная публикация тех же bytes не создаёт новый commit.
Git commit ID также зависит от родителя и metadata времени; одинаковый commit ID
для независимых историй этот контракт не обещает.

При включённой опции результат содержит `runtime_status` и `policy_git`.
`matches` и `policy_git.status=synced` означают, что native состояние и remote
сверены. Если push/проверка remote не удались после native apply, возвращаются
`status=git-sync-pending`, `runtime_status=matches`, безопасная причина и exit 1.
Принятую политику из-за ошибки Git не откатывают. При конкурентной замене canonical
inputs возвращается `runtime_status=not-rechecked`; внешние правки сохраняются.
Следующий `status` сверяет состояние заново и не создаёт commit.

```sh
smart-dns status
smart-dns git-sync
```

`git-sync` повторяет только публикацию принятой политики под существующим product
lock: без source fetch и native reapply. При native drift публикация запрещена.
Локальный commit после отказа push сохраняется для повторной попытки; divergence
remote требует ручной сверки, автоматических merge/rebase/force-push нет.
Без `policy_git` сохраняются прежние команды, результаты и требования среды.

При новой установке сначала подготовить приватный remote и credentials,
сохранить прежние bindings, установить проверенный source release, затем включить
опцию и выполнить первый `git-sync`/readback. Это не меняет существующий timer.

На существующем Debian 11 Git установлен штатными пакетами без обновления уже
установленных пакетов. Для недоступных package bytes исправлен только URI
security source на официальный `https://archive.debian.org/debian-security`:
его signed InRelease совпал с прежним индексом; проверка подписей сохранена.

Для отключения Git-публикации восстановить прежние source bindings и убрать
`policy_git`, сохранив текущие принятые canonical inputs. Отключение функции
не должно возвращать старый registry или выполнять Git reset. Прежний source,
резервные конфигурации и история policy remote сохранены.

## GEO-обновление и обновление программ

`smart-dns-product-refresh.timer` ежедневно запускает тот же `smart-dns refresh`
(06:31 UTC + до 300 секунд jitter). Он обновляет принятый источник в разрешённых
границах; новые roots pending, удаления/лицензия/неподдерживаемые predicates — review.
Это не автообновление программ. `certbot.timer` отдельно обслуживает существующие
lineages; второго scheduler нет. У общей `certbot.service` сохранён failed result
из-за чужой Nginx lineage: адресный renewal Smart DNS принят, общий scheduler
нельзя оценивать только по зелёному/красному состоянию service. Чужую lineage
сопровождает её владелец; [подробности](reports/2026-11-07/acme-renewal-candidate.md#принятое-автопродление).

При уже выданном допуске сопровождающий меняет policy через существующий CLI.
Обновление runtime требует отдельного согласованного кандидата и окна. Общие
Traefik/Docker/OS, сети, firewall, DNS-зона, Certbot с чужими lineages и Hermes
требуют участия владельца платформы. Этот документ сам такого допуска не выдаёт.

Для любого отдельного обновления:

1. Зафиксировать actual и точный прежний artifact: commit/digest/binary hash,
   effective Compose со всеми overlays, native config/state, units/hooks и пути.
   Прочитать upstream release/security notes **между текущей и целевой версией**,
   migration/deprecation notes и требования к OS/API/state. Записать, зачем версия
   нужна нам: исправление применимого дефекта, уязвимости или окончание поддержки.
   Latest tag сам по себе не основание; версию не выбирать автоматически.
2. Сохранить доступный предыдущий image/binary/source и согласованную копию
   его config/state **до первого запуска кандидата**. При необходимости native
   `docker image save`/приватный архив сохраняет образ независимо от registry.
   Проверить читаемость копии и путь возврата; не делать prune предыдущей версии.
3. Проверить кандидат вне рабочей VPS, на disposable Linux runner, с synthetic
   credentials и теми же schemas/options. Новые production keys/accounts/ClientID
   на полигон не переносить. Для state migration отдельно проверить old→new и
   восстановление old+old-state на обезличенной копии; чистый startup этого не доказывает.
4. Согласовать diff, затронутые сервисы, допустимый перерыв и конкретный возврат.
   Учесть GEO timer и текущие операции: для короткого окна допустимо согласованно
   остановить только product refresh timer, дождаться service idle и вернуть
   прежнее enabled/active состояние после работы. Shared Certbot без согласования
   не останавливать. Обновить один компонент его native owner; не делать общий
   `compose down/up` и не включать всю связку в одно обновление.
5. Сверить artifact и проверки ниже. При новом отказе доступа, утечке ClientID,
   drift policy/ACL или побочном изменении соседей остановиться и выполнить
   заранее проверенный возврат. Сохранить receipt результата и очистить только
   свои disposable ресурсы. При неизвестной совместимости возврата кандидат не готов.

| Компонент | Подготовка и отдельное применение после согласования | Возврат |
| --- | --- | --- |
| AGH | [Docker guide](https://github.com/AdguardTeam/AdGuardHome/wiki/Docker), changelog и [config migration](https://github.com/AdguardTeam/AdGuardHome/blob/v0.107.80/internal/configmigrate/migrator.go). Проверить API, ClientID, admin, DoH/DoT/SNI и watched TLS; отдельно native config migration. Остановить только `dns` для согласованной копии writable config/state; заменить только его image в private effective Compose, сохранить mounts, UID/GID и лимиты. Новый YAML из bootstrap renderer поверх native ACL не писать | Прежний образ **и соответствующий ему config/state**. Более новая config schema может отвергаться старым AGH; один downgrade image недостаточен. Не затирать отзывы клиентов, сделанные после копии; при конкурентном изменении остановиться для сверки |
| HAProxy | [Management guide](https://docs.haproxy.org/3.2/management.html): `haproxy -c` именно кандидатным образом с обоими config mounts; затем disposable wire с dynamic origin/deny policy, suffix/SNI и DoT. Пересоздать только `relay` из его actual Compose с прежними labels/сетями. Это прерывает текущие relay/DoT соединения | Прежний digest + matching config/labels/mounts. HAProxy reload не публикует Docker labels |
| Общий Traefik | [Migration guide](https://doc.traefik.io/traefik/v3.6/migrate/v3/) и все промежуточные release notes, включая patch. Проверить Docker provider/API, TCP passthrough, HTTP path/log middleware, ForwardAuth/Authelia и certificate storage на отдельном fixture. Platform owner обновляет только edge с полным native Compose/overlays; shared impact требует проверки соседей | Прежний edge artifact + matching static config/overlays/env/ACME state; остальная платформа остаётся под её владельцем. Не добавлять catch-all HostSNI, public management или новый provider ради обновления |
| acme-dns server | [Server v2.0.2](https://github.com/acme-dns/acme-dns/blob/v2.0.2/README.md): synthetic DB/registration, UDP/TCP authoritative TXT, non-recursion, закрытая registration, loopback API. Проверить DB migration и Linux/systemd compatibility. После согласованной cold copy DB заменить только проверенный binary, restart только `smart-dns-acme` | Прежний binary/config и согласованная прежняя SQLite state + client registration. Downgrade DB заранее не доказан; credentials должны совпадать с регистрацией |
| acme-dns-client / Certbot | [Client v0.3](https://github.com/acme-dns/acme-dns-client/blob/v0.3/README.md), соответствующие Certbot release notes. Client заменяется отдельно без новой регистрации/смены CNAME. Certbot обновляет native package owner, с учётом **всех** lineages, account/storage/flags/hooks и system Python зависимостей; без второго timer | Прежний client binary либо Certbot package/environment с совместимой renewal/account state. Не возвращать целиком `/etc/letsencrypt` поверх чужих свежих сертификатов |
| Собственные adapters / hook | Новый immutable Git source; offline contracts и релевантный native fixture. Проверить текущие input/snapshot schemas и эквивалентность принятой policy. Переключить только требуемые shortcut/unit/hook; сохранив прежний source и абсолютные пути. Для hook отдельно проверить OpenSSL validation, публикацию и served fingerprint | Прежний source + bindings и совместимые inputs. Если менялась schema/settings, возврат должен включать их; простой возврат symlink/shortcut этого не доказывает |

Image lock и source bindings должны соответствовать принятому component update:
подготовить отдельный source release с изменением только нужного lock entry и
согласованный private Compose. Архивы readonly generation не править на месте.
На кандидате проверить согласованность нового source/lock, effective Compose и
immutable accepted baseline, а также подготовку **следующей policy операции**
тем же source без infrastructure mismatch. `matches` этого не доказывает:
проверка не удостоверяет все image references. Если нужен новый accepted baseline,
его native подготовку/переключение и возврат включить в согласованный component
plan, сохранив прежний архив. Иначе будущий policy refresh/apply может отказать
из-за различия старого и нового Compose вне service labels.
`product apply/rollback` отвергает non-service infrastructure changes, включая
image update: использовать его как component installer нельзя. Автоматического
component upgrade/migration runner в проекте нет; для выбранной версии конкретные
native команды, полный diff и возврат фиксируются до допуска к production.

Существующий [offline CI](../.github/workflows/check.yml) запускает
`python3 -m unittest discover -s tests -v`.
[Native GEO CI](../.github/workflows/native-geo.yml) воспроизводит pinned policy,
проверяет синтаксис, образы, actual/wire, policy OFF/refresh/failure restore и cleanup.
Его filtered trigger не запускает lab для docs-only PR. Для следующего image
кандидата использовать этот же fixture с целевым digest и неизменной policy,
а при изменении tools сверить идентичность final commit/inputs.
Эти проверки **не принимают** миграцию state AGH, обновление shared edge,
Certbot или ACME binaries: соответствующие version-transition проверки добавляются
к конкретному кандидату, а не объявляются уже выполненными.

## Минимальная приёмка до и после изменения

Сначала сохранить приватный baseline; после сравнивать тем же способом:

- `smart-dns status`: actual directory/generation, `matches`, пустые findings;
  native AGH rules/admission/admin, фактические image IDs, mounts/config/labels,
  unit/binary/source bindings и сроки/served fingerprints сертификатов.
- С внешнего клиента: DoH и DoT с двумя действующими идентичностями; выбранное A
  через relay, AAAA/HTTPS/SVCB suppression, обычное имя direct; неизвестный,
  отсутствующий и отозванный ID — DNS `REFUSED` (HTTP 200 сам по себе недостаточен).
  Origin TLS через actual relay проверять CA/исходным SNI.
- Native admin: login/доступ только разрешённым путём; public management закрыт.
  ClientID не должен появляться в Docker API/raw logs edge/AGH/relay и отчётах;
  обращаться с log/evidence как с секретами. Проверять в ограниченном окне и
  по принятой privacy-процедуре, не печатая полные URL/ACL.
- Незатронутые container ID/StartedAt/config/networks прежние. Проверить ранее
  принятые соседние HTTPS/auth-маршруты без redirects и сравнить HTTP/TLS с baseline,
  отдельно отмечая прежние ошибки. При shared edge update нужны также сценарии
  владельцев приложений; health одного Smart DNS не принимает Hermes/Authelia.
- Для ACME: authoritative TXT по UDP/TCP и delegation, closed registration и
  прежний account; адресный staging renewal. В Certbot 1.12
  [dry-run пропускает deploy hook](https://github.com/certbot/certbot/blob/v1.12.0/certbot/certbot/_internal/hooks.py#L184-L199),
  поэтому hook/реальная TLS-публикация принимаются отдельно, без routine force-renewal.
  Для сетевого компонента владелец подтверждает обычное устройство: reconnect,
  browser/download, egress и нужную функцию приложения. Технический PASS этой
  пользовательской проверки не заменяет.

Без согласованной мутации достаточно read-only baseline. Не запускать production
lab, load test, issuance или отказ ради формального завершения документации.

## Три разных восстановления

| Случай | Действие и доказанность |
| --- | --- |
| Неудачная policy операция | Native service-only operator готовит restore и при сбое восстанавливает rules/relay с readback; production failure/disable/all-off/restore принят в [pilot report](reports/2026-11-06/production-pilot.md). Для одиночной записи достаточно `smart-dns off ID --reason '...'`; запись/причина сохраняются, `remove` нет |
| Возврат ранее принятой policy | `smart-dns rollback --to ARCHIVE_NAME`: имя **каталога** в manifest `releases` (operation UUID либо его `-restore`), из private operation receipt. Это не `actual_generation` SHA snapshot. Выбрать архив по его inputs/snapshot/receipt, проверить различия; текущий compiler заново готовит candidate. Команда возвращает только catalog/registry, сохраняет текущие settings/sources, клиентов и код |
| Source/limit миграция #14 | Сохранены исходные bytes четырёх inputs, предыдущие source bindings и native restore. Подготовка/валидация доказаны, выполнение production rollback — **NOT_TESTED**. Указатель и guard: private `.local/issue14/operator-receipt.private.json` у оператора, server workdir `/opt/smart-dns/.local/issue14-9980f67`. После LemonFox/refresh guard уже не совпадает: старую команду нельзя исполнять вслепую; сначала переоценить текущие изменения и подготовить согласованный возврат |
| Версия компонента | Предыдущий artifact **вместе** с совместимыми config/state/bindings по таблице обновлений. Реальное old→new→old восстановление будущих версий — **NOT_TESTED**, потребуется на кандидате |
| Потеря VPS / перенос | Нужен полный согласованный private комплект ниже, внешние доступы и platform baseline. Восстановление всей установки на другом сервере — **NOT_TESTED**; наличие server-local rollback не доказывает его |

TLS deploy hook валидирует пару и проверяет served fingerprint; при пойманной
ошибке восстанавливает прежнюю пару. Два файла не crash-atomic, прежние bytes
хранятся в памяти вызова — это не долговременный backup. Восстановление ACME DB,
client registration и Certbot lineage из backup отдельно **NOT_TESTED**.

## Что хранить вне VPS и как восстанавливать установку

Использовать существующее защищённое хранилище/backup владельца и native export
или согласованную cold copy; новая backup-платформа не нужна. На дату аудита
доказаны private rollback-каталоги и ACME cold copy **на самой VPS**. Полная
независимая копия, её актуальность, доступность и restore **НЕ ПРОВЕРЕНЫ**.
Локальные receipts намеренно не содержат ключи: они не являются recovery-комплектом.
RPO/RTO не измерены. Следующий отдельный шаг — владелец указывает действующее
защищённое хранилище, проверяет комплект/читаемость и согласует isolated restore.

| Часть согласованной копии | Что обязательно сохранить |
| --- | --- |
| Smart DNS | Deployment manifest и все canonical inputs; actual native AGH config/ACL/admin и действительно persistent state; admin password file; текущий и прежний source releases с locks, shortcut, units/timer, actual generated bundles/receipts, runtime Compose и edge override |
| Сертификаты | AGH TLS pair; своя Certbot renewal config, live symlinks **с целями archive**, связанный CA account/private key, auth/deploy hooks и используемые source/binaries. Чужие lineages и Traefik ACME storage — у platform owner; согласовать их совместное восстановление, не считать AGH TLS их заменой |
| Challenge service | Согласованные SQLite DB (со связанными файлами при наличии), clientstorage, server config и units, pinned binaries/locks. Снять cold copy при остановке только challenge service в согласованном окне либо проверенным native SQLite backup; не копировать live DB произвольно. Certbot не должен одновременно выполнять challenge |
| Метаданные и внешние доступы | Права/UID/GID, symlinks, хеши/версия/время копии; SSH keys/trust и доступ к независимому хранилищу, VPS/provider/DNS-panel account; приватные A/wildcard A/NS/CNAME/delegation records, адреса, platform Compose/env/network/ACME baseline. Наличие этих доступов у следующего оператора **НЕ ПРОВЕРЕНО** |

После отдельного согласования восстановления:

1. Проверить копию, доступы и точный scope; сохранить доступные повреждённые
   данные. Platform owner готовит доверенный host/Docker/edge, прежние external
   networks и согласованные порты. При смене IP/имени заново сверить private settings,
   deny own-address policy, DNS/delegation, cert SAN и endpoint устройств — это
   отдельная миграция, а не побайтовый replay старого Compose.
2. Восстановить private inputs, immutable source/locks и **native** AGH config,
   сохранив отзывы клиентов. Восстановить runtime/actual Compose с правильными
   mounts и согласованным edge overlay; не генерировать full AGH YAML из старых
   bootstrap ClientID. Сверить hashes и права до запуска; не расширять права
   каталогов ради устранения ошибки доступа.
3. Восстановить свою Certbot lineage/account/hooks/TLS и согласованную ACME
   DB+client registration. Для DynamicUser/StateDirectory использовать владельца,
   созданного systemd на новом host, а не вслепую старый числовой UID. Сверить
   delegation и закрытую registration. При утрате DB/credentials точное восстановление
   не доказано: новая регистрация и смена DNS delegation требуют отдельного решения
   владельца. Shared certificate state восстанавливает platform owner; повторный
   issuance требует отдельной необходимости/допуска.
4. Пока публичный доступ закрыт согласованным способом, проверить native syntax,
   network/ACL/secret/TLS и coherent policy/config. Поднять только Smart DNS services
   через native owners, затем открыть согласованный ingress. Включить прежние
   product/renewal timers после сверки их bindings и исключения двух работающих
   scheduler/ACME owners при переносе. Проверить всё из раздела приёмки и обычное
   устройство; измерить фактическую потерю данных/время восстановления.
5. Старый artifact/копию оставить до принятия результата. При неуспехе не открывать
   public management/recursive DNS и не расширять relay; назвать, что именно
   восстановлено и что осталось недоступно. Сейчас эти шаги — план, **не receipt
   успешно выполненного full restore**.

Полное отключение согласовывать отдельно: штатный OFF снимает маршрутизацию policy,
а удаление DNS endpoint без возврата resolver-настроек устройств оставит их без DNS.
Сначала вернуть устройства на согласованный resolver и учесть DNS/Alt-Svc кеши;
затем снять только Smart DNS routers/override, контейнеры и собственный challenge
namespace, если он больше не обслуживает lineage. Общий edge, `certbot.timer`,
чужие сертификаты и сети не удалять; проверить соседние маршруты. Исторические
all-off/restore доказывают policy independence, полное удаление установки — **NOT_TESTED**.
