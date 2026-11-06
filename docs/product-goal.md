# Product GOAL #3: управляемый частный Smart DNS

Источник требований: [issue #3](https://github.com/Kwentin3/smart-dns/issues/3).
Это текущая запись продуктовой задачи; [рефакторинг](refactor.md) остаётся
завершённым инфраструктурным этапом. Product GOAL **не завершён**.

## Уточнённый первый сценарий

Владелец указал Zyxel Keenetic Ultra с DoH и Huawei P50 со штатным DoT,
системный DNS для всех приложений, а не browser-only DoH. Wi-Fi → мобильная
сеть входит в приёмку. Отправная точка сервиса — ChatGPT; полнота каталога
не требуется для первого пилота. По уточнению владельца инструкции по меню и сбор
версий не нужны: выдаются DoH URL роутера и DoT hostname телефона, без привязки
допуска к модели/MAC/IP. Приложения со своим resolver/IP способны обходить системный
DNS; такую универсальную перехватную гарантию без дополнительного механизма
не обещаем.

## Соответствие текущего результата продукту

Исходная оценка: код `f696536`, [приёмка refactor](reports/2026-11-06/refactor-acceptance.md).
Таблица описывает исходные разрывы; выполненный срез указан в конце документа.

| Требование #3 | Что уже есть | Продуктовый пробел |
| --- | --- | --- |
| Частный доступ/отзыв | Native AGH admission/admin/GET/POST/revoke и direct-peer denial — PASS в стенде | Реальные DoH Keenetic, DoT P50, certificate/bootstrap и смена сети — NOT_TESTED |
| Геосервис и обычные сайты | Verified TLS к двум origin, exact rewrites, unrelated HTTP fixture | Вход/сообщение/файл/CDN/повторная сессия и реальная региональная политика — NOT_TESTED |
| Одно управление сервисами | Один плоский `rules/pilot.json` порождает три конфигурации | Нет сущности service, enabled/reason/exclusions и отображения desired/actual |
| Актуальные сведения | Pinned metadata публичных источников | Нет получения предложений/обновлений; два старых источника без установленной лицензии |
| Безопасное применение | Новый staging output, native checks, failed startup/restore — PASS в lab | Native client/admin state нельзя перезаписывать stale provisioning settings; production apply/rollback — NOT_TESTED |
| Независимость/стоимость | Пределы новых контейнеров, native HTTP limits, lab cleanup | Общий production edge, host-wide capacity/logging и восстановление устройств — NOT_TESTED |

Ни 18 unit tests, ни successful TLS не доказывают продуктовые строки справа.

## Минимальный путь управления

Отдельная панель, БД доменов и новый DNS/proxy не нужны. Для первого частного
пилота предлагается обычный GitHub-репозиторий и существующая админка AGH:

- **Один сервисный каталог** заменит плоский authority, а не станет его копией:
  service ID/name, enabled, причина, approved domains/scope, исключения с причиной,
  pinned provenance. Native DNS/SNI/relay конфигурации будут только производными.
  Git хранит diff/дату/автора; enable/disable/exclude делаются в одном месте.
- **Клиенты и администратор остаются у AGH.** `settings.client_ids/users` —
  bootstrap, не второй актуальный реестр. Native API
  [filtering/set_rules](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/filtering/http.go#L346)
  меняет custom rules без назначения allowed_clients/users. Endpoint заменяет
  весь блок и не имеет cross-component transaction: блок должен иметь одного
  writer, а изменение сервиса обязано сохранить ранее отозванные IDs от возврата.
- **Состояние применяется/проверяется через существующих владельцев.** Desired
  catalog и успешная generation не равны active. Подтверждение active должно
  читаться из effective AGH rules, Docker labels и relay policy с точной версией;
  при расхождении показывается drift, не ложное «применено». Нужен небольшой
  bounded operation/readback, не постоянно работающий controller.

Известный риск текущего пути: render целиком пишет AGH users/allowed_clients из
private settings. Повторное использование старого файла после настоящего отзыва
может вернуть ID. Это источник-кодом установленный риск; инцидент не наблюдался.
Следующий срез должен проверить service toggle/update/rollback после revoke.

## Готовые сведения и обновления

Первичный кандидат — service-oriented **v2fly/domain-list-community**, MIT,
исследовательский pin `16fd8005d390470e8523745c9fa631c9e767cc61`:
[license](https://github.com/v2fly/domain-list-community/blob/16fd8005d390470e8523745c9fa631c9e767cc61/LICENSE),
[openai](https://github.com/v2fly/domain-list-community/blob/16fd8005d390470e8523745c9fa631c9e767cc61/data/openai),
[anthropic](https://github.com/v2fly/domain-list-community/blob/16fd8005d390470e8523745c9fa631c9e767cc61/data/anthropic).
Это готовая классификация, не доказанная полнота браузерного сценария.

Bare/domain правила означают suffix; full — exact; include/regexp/keyword и
attributes меняют охват. Типы надо сохранять в предложениях. Не превращать
suffix в exact молча и не включать общий CDN, telemetry, Sora либо другие
сервисы только из-за их присутствия в категории OpenAI.

Минимальное получение: native scheduled/manual GitHub Actions → immutable SHA
→ ограниченный service-file fetch → diff предложений с additions/removals/type
changes → review. Source failure не меняет accepted snapshot/runtime. На первом
пилоте новые domains/scopes включаются явно. Для одобренного охвата адресная
актуальность рассматривается отдельно; собственный каталог всех интернет-сервисов
или автономный downloader/deployer на VPS не требуется. Workflow реализован в
`.github/workflows/source-proposals.yml`, но расписание заработает только после
попадания в default branch. Локальный live fetch проверен; GitHub run ещё не принят.

## Актуальность origin без ручного списка CDN IP

Текущая fixed-IP схема безопасна в проверенном охвате, но плохо масштабируется
на реальные login/API/CDN hosts. IP apex нельзя без доказательств использовать
для всех его поддоменов. Кандидат — **native HAProxy do-resolve для фактического
SNI**, сохраняя global maxconn и idle timeouts. В pinned 3.2.26 это доступно в
tcp-request content; выбранный typed IP можно проверить и использовать тем же
set-dst без второй резолюции. [Native manual](https://docs.haproxy.org/3.2/configuration.html).

Строгое IPv4 требует `dns-accept-family ipv4`: аргумент ipv4 у do-resolve — только
предпочтение. Необходимы независимый origin resolver, fail-closed на ошибках,
проверка выбранного IP на private/loopback/link-local/metadata/reserved и свои
endpoints. DNS rewriting не является защитой relay. Exact/suffix/exclusions должны
совпадать у всех трёх consumers. Candidate — **NOT_TESTED runtime**; безопасный
динамический путь не считается доказанным до контролируемых DNS/actual-connect
проб. До этого fixed origin остаётся последним принятым baseline.

Готовый [ameshkov/snirelay](https://github.com/ameshkov/snirelay/tree/ef8961b7c78180efc6f4760e46fb9a476aeb1ce9)
имеет встроенный DNS/SNI routing, но его рассмотренный config не даёт доказанного
замещения native client admission, management и service catalog. Замена им AGH
не сокращает доказанную задачу без новых проверок; fork не предлагается.

## Системный DoH/DoT и граница идентификации

Для Keenetic кандидат — personal DoH URL `/dns-query/<router-ID>`; downstream
LAN clients при этом используют router как одного разрешённого клиента. Это
не отдельная server-side идентичность каждого устройства LAN.
[Официальная инструкция](https://adguard-dns.io/kb/private-dns/connect-devices/routers/keenetic/)
поддерживает URL с ID; соответствие установленной прошивке ещё надо проверить.

Для Huawei candidate — `<phone-ID>.dns.example.net` через native Private DNS
DoT/853, native AGH server_name и cert с base + wildcard именем.
[AGH ClientID formats](https://adguard-dns.io/kb/adguard-home/clients/),
[Android native hostname configuration](https://developers.google.com/speed/public-dns/docs/using).
Владельцу был задан отдельный вопрос о принятии границы: hostname ID виден в bootstrap
DNS/обычном TLS SNI и может быть воспроизведён узнавшим его клиентом. Это отзывной
bearer identifier, не строгая криптографическая аутентификация устройства и не
эквивалент секретному HTTPS URL path. Ответ владельца в этой сессии 2026-11-06:
«Приемлемо для пилота». Эта ограниченная граница принята для первого пилота;
строгую криптографическую аутентификацию устройства продукту не приписываем.

DoT обходит HTTP middlewares: ограничения DoH на него переносить нельзя.
Существующий HAProxy может ограничивать отдельный native TCP frontend DoT,
передающий TLS одному AGH backend; это не произвольный private destination.
Дополнительный порт, сертификат/DNS и лимиты требуют конкретного согласования
внедрения. На VPS они не создавались.

## Последовательность и обязательный остаток

1. **Repo-only сервисный срез:** один catalog, enable/disable/exclude, provenance,
   source proposals и сохранение accepted state при source/validation failure.
   Проверить, в том числе отключение последнего сервиса и невозможность
   автоматической активации нового upstream правила.
2. **Isolated native slice:** проверка DoT candidate/threat model, guarded
   dynamic origin, сохранение AGH clients при service update, desired/actual
   readback, плохой update/restore. Использовать существующий lab lifecycle,
   не повторять неизменённые прежние проверки ради счётчиков.
3. **Конкретный private deployment package:** выбранные native configs, exact
   new-service/network/port/certificate changes, logging всех relevant sinks,
   budgets, admin SSH path и rollback/cache window. Доказать candidate в lab
   перед запросом отдельного разрешения. Shared Traefik/Hermes не менять заранее.
4. **Практический pilot:** P50 system DoT home→mobile, Keenetic DoH, посторонний/
   отозванный client, сервис login→message→file→повторная сессия, ordinary site
   напрямую, catalog toggle, source-update proposal, rollback без нарушения
   контрольных сценариев Hermes/сайтов. Отмечать ограничения и неподдержанный охват.

Нулевой downtime при изменении сервисов не доказан. Первый private pilot может
использовать bounded stop-first/rollback только с явно согласованным окном;
если это неприемлемо, сначала рассматриваются native reload/transaction paths,
а не добавляется собственная платформа.

### Проверенный срез 2026-11-06

`rules/pilot.json` теперь единственный сервисный каталог: enabled/reason, exact
domains и глобальные исключения с причиной. Отключение последнего сервиса даёт
пустые AGH rules, закрытый relay и отсутствие Traefik TCP router. Render выдаёт
`candidate-not-applied`, а не утверждение об активном состоянии.

`tools/source_proposals.py` получает raw diff двух выбранных community-файлов и
лицензию на immutable SHA. Он не изменяет каталог и не применяет правила.
Live fetch исходного pin прошёл, изменений источника на тот момент не было.

Native AGH DoT на disposable CA: шесть проверок PASS, включая REFUSED для
неизвестного/пустого ID, отзыв телефона и сохранение ACL/admin/router DoH при
замене custom rules и их откате. Тестовый CA не установлен в систему. Optional
`settings.dot` генерирует native TLS и отдельный ограниченный localhost lab port;
этот Compose-путь целиком ещё не проверен. Обычный DNS при DoT отключён.

Отдельный native HAProxy experiment: 15 проверок PASS — verified origin TLS,
CNAME/обновление public A, private/metadata/self denial, NXDOMAIN/AAAA-only/timeout
fail-closed. Проверялся именно выбранный адрес и отсутствие соединений с
калиброванным private trap. Контейнеры/сеть удалены, прежние container IDs совпали.
Это доказательство механизма. Renderer теперь поддерживает optional `origin_dns`
с отдельным deny artifact и immutable policy fingerprint; его native syntax
проверена на pinned HAProxy. Default fixed-origin baseline сохранён. Полный
интегрированный runtime dynamic+DoT пока не принят.

До полного product DONE остаются приёмка интегрированного runtime, один bounded
apply/readback/rollback для всех трёх consumers с сохранением живого AGH state,
конкретный private deployment package и реальная device/service приёмка. Текущий
bootstrap render нельзя использовать как обновление работающего AGH. Следующий
шаг — интеграция проверенных native механизмов и rehearsal итогового пакета;
для внедрения остаётся обеспечить серверный DNS/certificate. Issue #3 не даёт production-допуск.
