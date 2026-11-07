# Product GOAL #12: универсальный частный Smart DNS

Источник требований: [issue #12](https://github.com/Kwentin3/smart-dns/issues/12),
расширяющий [issue #3](https://github.com/Kwentin3/smart-dns/issues/3).
Это единая текущая запись продуктовой задачи; [рефакторинг](refactor.md) остаётся
завершённым инфраструктурным этапом. Product GOAL **не завершён**.

## LemonFox: суффикс и сохранность после обновления, 2026-11-07

Владелец поручил добавить `lemonfox.ai` как suffix через существующий CLI и
проверить workflow добавления/refresh. Код, лимиты, источник community и настройки
клиентов не меняются при добавлении; обычный refresh сохраняет свои review gates.
Реальную расшифровку владелец проверит в своём приложении; API-ключи не нужны
для операторской сетевой приёмки.

- [x] До изменения native `matches`; LemonFox отсутствует в принятом источнике
  и active scope, пять hostnames дают direct DoH/DoT; 35 baseline checks PASS.
- [x] Выполнить штатное `smart-dns add lemonfox --suffix lemonfox.ai --reason ...`.
- [x] Проверить actual, DNS/TLS/API reachability без ключа и контрольные маршруты.
- [x] Выполнить штатный `smart-dns refresh`, подтвердить неизменность локальной
  записи/исключений и повторить затронутые wire checks.

После add actual `matches`, поколение `4e706888…`; после обычного refresh —
`matches`, поколение `fa1115bc…`, findings пусты. Fancy source штатно обновился с
`25e7b1912eca4b31d44906af0df10f00c85ab268` до
`c02a150c417a6b3c39636653dbcc52f0e5f1dfaa`; локальный catalog после refresh
побайтово совпал с принятым после add. Итог: 2510 native rules,
114 exact + 1141 suffix wire roots; LemonFox — одна включённая ручная запись
`lemonfox` с единственным suffix `lemonfox.ai`.

Внешние проверки после add и после refresh: **36/36 PASS** в каждом прогоне.
Через DoH/DoT apex, `www`, `api`, `eu-api`, `output.lemonfox.ai` направлены на relay;
для API проверены также AAAA/HTTPS/SVCB suppression и второй существующий ClientID.
TLS к `api.lemonfox.ai`, `eu-api.lemonfox.ai`, `www.lemonfox.ai` через relay
подтверждён публичным CA. GET API без ключа вернул JSON `401 authentication-required`:
это подтверждает сетевую доступность, а не успешную расшифровку или причину прежней ошибки.
Прежний AI-маршрут, direct и отказ неизвестному ClientID сохранены.

Код оператора, settings, sources, клиентский admission и 24 защищённых контейнера
(ID/время запуска/конфигурация/сети) не изменились. Три соседних HTTPS-маршрута
совпали с последней принятой baseline по статусу и проверенному сертификату.
Приватные receipts сохранены в `.local/lemonfox-add/`; они не публикуются.
Операторская приёмка добавления/обновления завершена. **Осталась пользовательская
проверка STT в приложении владельца**; #12 остаётся открытым.

Отдельная процедура полного отката не вводится. Штатное обратное действие для
этой записи — `smart-dns off lemonfox --reason ...`: оно снимает маршрут, сохраняя
запись и причину в каталоге. Команды `remove` в текущем CLI нет. Встроенное
аварийное восстановление существующего оператора остаётся без изменений;
дополнительный rollback rehearsal на production не выполняется.

## Production rollout #14, 2026-11-07

Владелец разрешил [полное развёртывание](https://github.com/Kwentin3/smart-dns/issues/14)
проверенного PR #13 и необходимый `max_policy_entries=4096`.
[Уточнение приоритета](https://github.com/Kwentin3/smart-dns/issues/12#issuecomment-6705462632):
широкие suffix и их побочный охват приняты как компромисс; ручное сужение каждого
имени не требуется. Ранее записанный вопрос о широте больше не блокирует rollout.

Граница: один штатный service-only rollout существующего Smart DNS, прежний
baseline/OFF/exclusions/ClientID и рабочий откат сохранены. Общий Traefik, Hermes,
соседние приложения, сети/порты/firewall/DNS и сертификаты не меняются. При дрейфе
или неготовом откате остановка до изменения; production не используется для lab.

- [x] Read-only actual совпал с последним принятым поколением `f17746a8…`;
  канонические catalog/registry совпали с сохранённой baseline, findings пусты.
- [x] Внешний baseline: 64 DNS/TLS checks PASS; новые не-AI примеры пока direct.
- [x] Кандидат и restore подготовлены на актуальных приватных settings через
  существующие `prepare_catalog` / `product.prepare` / `validate_candidate`;
  old manifest воспроизведён точно, infrastructure неизменна, требуется 4096.
- [x] Сверить соседние маршруты, подготовить rollback/pointer publication и
  выполнить один controlled rollout с фиксацией actual и protected state.
- [x] Внешние DoH/DoT/direct/denied, новые не-AI DNS/TLS, ресурсы и соседние
  маршруты после применения; краткий отчёт и сохранённый путь отката.

Actual `smart-dns status=matches`, поколение `239c889b…`: 2508 native rules,
114 exact + 1140 suffix wire roots. ClientID/24 protected containers и их
конфигурация/сети сохранены; новый relay единственный пересозданный контейнер.
64 внешних DNS/TLS checks и 12 соседних route comparisons PASS. Старые два TLS
verification errors не изменились. Единственное изменённое поле settings —
согласованный лимит 4096; существующие shortcut/refresh service указывают новый
проверенный source, timer сохранён и не запускался принудительно.
[Production evidence и границы проверки](reports/2026-11-07/production-fancy-rollout.md).

Следующий шаг — пользовательская приёмка основных функций не-AI ресурсов и
устройств. Исходный source pin Fancy применён без замены:
`25e7b1912eca4b31d44906af0df10f00c85ab268`.
#12 остаётся открытым до пользовательских функций/устройств. Прежние запреты на
activation ниже относятся к repo-only этапу и заменены этим узким допуском #14.

## Текущий срез #12, 2026-11-07

Результат: универсальное расширяемое GEO-покрытие из поддерживаемых community
реестров, единое управление, безопасные обновления и доказанное выборочное
проксирование разных категорий. AI-пилот и 492 upstream suffixes — исходная
проверенная опора, а не конечная граница продукта.

Поручено исследование и подготовка изменений в репозитории. Новый допуск на
изменение VPS, общего Traefik или расширение фактически включённых правил из #12
не следует; этот срез не меняет production. Состояние прошлых развёртываний ниже
приведено по их evidence, новый live readback в этом срезе не выполнялся.

Владельцы сохраняются: `registry.py` получает upstream facts, `catalog.py` хранит
локальные разрешения и предпочтения, `render.py` проецирует их в native AGH /
HAProxy / Traefik, `product.py` координирует readback/apply/rollback. Clients/admin
остаются у AGH, расписание у systemd. Панель, база и второй DNS/proxy не нужны.

Текущий кандидат добавляет `smart-dns list` / `show ID`: чтение accepted discovery
и desired policy из путей одного deployment manifest без пароля, сети и применения.
Видны происхождение, ON/OFF/discovered, определения, pending/unsupported, исключения;
runtime, network path и user functionality явно `not-checked`. `status` остаётся
штатным способом native readback. Новый неподдерживаемый predicate источника
теперь останавливает refresh на review до изменения принятого набора/runtime.

Исследование трёх актуальных pinned источников завершено. Готовый Fancy GEO
JSON v3 даёт 613 exact + 692 suffix predicates сверх сохранённого baseline;
его source profile подключён тонкой адаптацией существующего загрузчика.
Приватный кандидат сохраняет прежние grants и добавляет `community-geo`.
После миграции Fancy становится единственным обновляемым upstream, а прежний
itdog baseline сохраняется как frozen local policy с provenance; второй
live source owner не создаётся. Проверено 152 unit/behavior checks, 35 Windows
AGH wire cases и полный Linux Docker-provider прогон: 52 wire/readback checks,
восемь реальных CLI-вызовов / 60 checks, включая OFF/exclude после refresh,
source outage и rollback. Полные 2508 native AGH rules и Docker label 94,282 bytes
совпали с compiler; pinned images и cleanup подтверждены. Для полной политики нужен явный
`max_policy_entries: 4096`; production остаётся с прежними settings.
[Сравнение, компромиссы и границы проверки](reports/2026-11-07/universal-geo-candidate.md).

Обязательный остаток #12:

- [x] Сверить актуальные pinned корпуса нескольких реестров, пересечения и
  реальные exact/suffix границы с действующим набором; показать непокрытое.
- [x] Выбрать минимальный поддерживаемый source path для дополнительного GEO
  покрытия; не строить платформу объединения источников без необходимости.
- [x] Подготовить и проверить конкретную расширенную policy и обновление через
  существующих владельцев. Native Docker-provider lab выполнена на изолированном
  GitHub runner, source revision `1a1bbfe`, [run 42360351223](https://github.com/Kwentin3/smart-dns/actions/runs/42360351223).
  Артефакт прочитан обратно, checksum входов совпал с локальной репетицией.
  Реальные refresh были без изменения upstream; changed-source Fancy production
  не заявляется. На production lab не запускалась; новые полномочия остаются
  предложением до допуска.
- [x] После отдельного допуска применить проверенный артефакт, подтвердить
  native actual, отрицательные/direct cases, сохранение OFF/exclusions и rollback.
- [ ] Подтвердить основные функции репрезентативных не-AI ресурсов, ordinary
  sites и смену сети; отделить source coverage, routing и пользовательскую приёмку.

Поставка разрешённой repo-части — [PR #13](https://github.com/Kwentin3/smart-dns/pull/13).
В [ревью владельца](https://github.com/Kwentin3/smart-dns/pull/13#pullrequestreview-5811444613)
merge этого repo-only среза разрешён после фиксации трёх release questions;
допуск на активацию Fancy из этого решения не следует. Перед запуском остаются
явные решения: побочный охват широких suffix и нужные сужения, ручная проверка
актуальности frozen grants, ограниченная приёмка влияния на сайты/ресурсы/Hermes
с согласованным бюджетом 4096 и откатом. [Подробные ограничения и сценарий](reports/2026-11-07/universal-geo-candidate.md#release-questions-before-activation).
Следующий этап — сверка live baseline, отдельное согласование конкретного
расширения и лимита, service-only rollout/readback и пользовательские сценарии.
Готовность текущего этапа и
готовность всего продукта различаются. Полный GOAL
остаётся открытым, пока обязательный остаток не закрыт evidence. Историческое
утверждение ниже, что осталась только приёмка телефона, относится к объёму #3;
#12 расширяет этот объём.

## Переход от пилота к эксплуатации, 2026-11-07

Владелец поручил превращать пилот в полноценный продукт, не ожидая полного
прогона телефона. Граница поставки: существующие AGH/HAProxy/Traefik, приватный
каталог как единственный владелец предпочтений и штатные Certbot/systemd.
Для DNS-01 отдельно согласован узкий native acme-dns с его client и собственной
embedded state. Самописная панель и платформа управления не создаются.

Состояние обязательного объёма:

- [x] Исправить приоритет OFF отдельного сервиса над включённым GEO-набором;
  общий домен другого включённого сервиса показывать как зависимость.
- [x] Дать одну операторскую команду для статуса, включения, отключения, добавления,
  применения и отката; публиковать предпочтения после native readback.
- [x] Автоматизировать безопасные обновления известного источника. Расширение
  approved roots, удаления и изменения лицензии остаются на review; при ошибке
  сохраняется принятый набор. Новый product refresh заменил proposal-only timer.
- [x] Завершить автоматическое продление DoT-сертификата. Владелец добавил
  A/NS/CNAME в VK WorkSpace. Native DNS-01 прошёл staging и production issuance;
  новый сертификат до 2027-02-05 опубликован в AGH без restart. Certbot сохранил
  authenticator и deploy hook; повторный `renew --dry-run` без их CLI overrides
  выполнил оба DNS challenges успешно. Существующий timer обслуживает lineage,
  admission/admin и чужие контейнеры сохранены. Внешние DoH/DoT: 6/6 PASS.
  [Проверенный этап](reports/2026-11-07/acme-renewal-candidate.md).
- [x] Проверить команды и изменения политики в изолированной лаборатории, затем
  применить проверенный артефакт без изменения общего edge и чужих сервисов.
- [ ] Получить полную пользовательскую приёмку Wi-Fi → мобильная сеть, сообщения,
  файла и обычных сайтов. Подтверждение Gemini уже получено; полный прогон отложен.

Критерий готовности: команды отражают фактическую конфигурацию, OFF действует
при пересечении с GEO-группой, обновление/откат сохраняют clients/admin и чужие
контейнеры, продление больше не требует ручных TXT, пользовательский сценарий
подтверждён. Сейчас GOAL остаётся открытым. Код `8764162` прошёл 134 tests на
Windows/Linux, native GEO/CLI/certificate проверки и CI, применён на VPS; actual
совпадает с desired. Все четыре группы ON, native rules и защищаемые контейнеры
сохранены. Новый systemd refresh выполнен успешно, прежний timer выключен.
Техническая эксплуатация и автопродление проверены. Обязательный остаток всего
GOAL — пользовательский прогон Wi-Fi → mobile, сообщений/файла и обычных сайтов;
владелец его отложил. До этого весь продукт не считается принятым.
[Evidence](reports/2026-11-07/product-controls.md).

## Расширение GEO-профиля, 2026-11-07

Владелец указал на продуктовый пробел: широкий каталог был доставлен, но работали
только два AI-сервиса; Gemini оставался OFF. Новый запрос — раскатать полный
готовый GEO-набор. Прежний узкий пилот не является конечным объёмом задачи и не
требует отдельного согласования каждого ресурса внутри выбранного набора.

Выбран полный профиль itdog GeoBlock + Google AI: 465 и 28 суффиксов,
492 уникальных, pin `eb64def4353f8e1b9cc483858021979a3481c76e`. Это специальный
GEO-корпус, а не смешанный индекс из стран/вендоров/категорий Meta. У источника
нет объявленной лицензии: полные snapshots/каталог/предложения остаются приватными;
в Git — код адаптера, provenance и результаты без полного набора.

Границы прежние: существующий collector → private snapshot → обычная catalog
projection → native compiler → service-only apply/readback/rollback. Старый
принятый AI-набор сохраняется как локальная baseline. Никаких новых DNS/proxy,
панелей, БД, изменений общего edge или Hermes. Native timer собирает приватные
предложения отдельно от публичного Meta discovery; автоматического расширения
approved roots и unattended deploy нет. Последний рабочий набор сохраняется при
ошибке источника. Собственные зоны/адреса и destination-IP guards сохраняются.

Готовность этого среза: реальный профиль целиком прошёл native lab и transport
полного Docker label; применён на VPS, actual status совпадает с desired,
Gemini/API и выборка других GEO-ресурсов дают правильные DoH/DoT и origin TLS,
обычные сайты остаются direct; приватный source timer выполнен/активен. Google
может дополнительно проверять аккаунт и собственную геолокацию VPS — DNS/TLS не
доказывают работу залогиненного Gemini. Приватный кандидат прошёл 101 unit test,
53 native GEO checks и проверку systemd templates. Оператор `6ebfabd` применил
профиль на production: actual status `matches`, admission/protected containers
сохранены, все четыре service groups ON. Снаружи прошли 180 DoH/DoT/origin checks;
анонимные Gemini `/app` и `/` отвечают HTTP 200. Владелец подтвердил для Gemini
«Заработал». Private timer активен, первое
native выполнение завершилось Result=success/exit0 и `changed=false`. Канонические
GEO inputs — private `.local/policy/rules/`, public Meta в Git — discovery/example.
[Evidence](reports/2026-11-07/geoblock-profile.md).

До GEO-расширения: готовый index 2019 source lists, выбранные definitions,
8 reviewed namespaces ChatGPT/Claude на production, actual status `matches` и 96
внешних DoH/DoT/origin-TLS checks. Новые roots/unsupported predicates остаются на
review. Ежедневный workflow доставлен в `main`, включён и фактически запущен;
реальные устройства/смена сети и функции приложений ещё не приняты. Подробная
проверяемая граница — [registry acceptance](reports/2026-11-06/registry-acceptance.md).

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
Дополнительно real historical comparison двух immutable upstream snapshots
выдал diff OpenAI (15 строк) и Anthropic (23 строки), лицензия не менялась.
Это демонстрация предложений; принятый pin и каталог не изменялись.

Native AGH DoT на disposable CA: шесть проверок PASS, включая REFUSED для
неизвестного/пустого ID, отзыв телефона и сохранение ACL/admin/router DoH при
замене custom rules и их откате. Тестовый CA не установлен в систему. Optional
`settings.dot` генерирует native TLS и отдельный ограниченный localhost lab port;
общий Compose-путь теперь проверен на Linux. Обычный DNS при DoT отключён.

Отдельный native HAProxy experiment: 15 проверок PASS — verified origin TLS,
CNAME/обновление public A, private/metadata/self denial, NXDOMAIN/AAAA-only/timeout
fail-closed. Проверялся именно выбранный адрес и отсутствие соединений с
калиброванным private trap. Контейнеры/сеть удалены, прежние container IDs совпали.
Это доказательство механизма. Renderer теперь поддерживает optional `origin_dns`
с отдельным deny artifact и immutable policy fingerprint; его native syntax
проверена на pinned HAProxy. Default fixed-origin baseline сохранён.

Общий native runtime dynamic+DoT: 10 проверок PASS. DoH проверяет тестовый CA
и hostname; DoT проходит через отдельный HA frontend; оба origin проверены
с публичным CA через relay и edge. Этот CA не установлен в trust store ОС.

`tools/service_policy.py` — ограниченная lab-only операция, не daemon и не новый
реестр. Она перепроверяет candidate существующим renderer, проверяет actual AGH
rules/ACL/profile и mounted relay policy/image/labels, затем останавливает только
relay, заменяет custom rules native API и запускает только relay новой генерации.
AGH/edge/соседние сервисы не перезапускаются. Client admission и users не пишутся.
Native AGH может переписать собственный YAML; immutable snapshot содержит только
производные service rules и fingerprint начального bootstrap. Это не второй
актуальный реестр клиентов и не аудит всех текущих admin settings.

Пять operation checks PASS: отказ реальной Docker-команды после записи native
rules → восстановление прежних правил/relay; disable одного сервиса; all-off;
restore; возврат телефона только отдельным native ACL действием. При каждом
service update/rollback отозванный телефон оставался запрещённым, обычные DNS
ответы и affected TLS path проверялись по сети, три protected контейнера сохранили
ID/StartedAt. Cleanup — PASS, 15 прежних container IDs совпали; временные
контейнеры/сети/remote каталог/operator lock удалены. Независимое review среза — PASS.
[Evidence и ограничения](reports/2026-11-06/product-native-acceptance.md).

Private deployment candidate сформирован локально и в Git не публикуется:
два новых ограниченных контейнера AGH/HAProxy, отдельная DNS-сеть, public TCP/853,
localhost admin port и использование текущего Docker provider общего edge.
Shared edge override добавляет DNS-сеть и фильтрацию access-log полей, сохраняя
его остальные команды и сети. Это требует краткого пересоздания общего edge;
изменение журналов затрагивает его общую observability и требует явного допуска.
Оба Compose-документа проверены native `compose config -q` на фактической текущей
конфигурации без применения. Целевой сертификат/DNS challenge ещё не подготовлены;
connection strings имеют статус NOT_DEPLOYED. До выдачи рабочего подключения
нужны отдельно разрешённые certificate/DNS/logging/rollout и canary/runtime checks.

До полного product DONE остаются допуск и приёмка private deployment и
реальная device/service приёмка. Текущий
bootstrap render нельзя использовать как обновление работающего AGH. Следующий
Допуск получен в чате 2026-11-06: «даю апрув. аккуратнее с траефиком ;)» на
подготовленный двухконтейнерный пакет, DNS/certificate и согласованный shared-edge
override. Новый допуск имеет приоритет над исходным ограничением issue #3.
Следующий шаг — DNS/certificate и сохранение точного rollback до изменения edge;
далее canary/runtime проверки и реальный пользовательский сценарий.

### Разрешённый rollout: техническая приёмка завершена

Точная текущая версия/health общего Traefik подтверждены. Private backup исходных
Compose/env/inspect и container ID/StartedAt сохранён на сервере в каталоге модуля.
Пакет размещён отдельно, два pinned image загружены; оба сервиса работают.
`compile_production` теперь единственный production adapter: output совпал с ранее
согласованным пакетом; native render на системном Python 3.9 дал те же артефакты.
58 unit checks PASS. Production service operation сохраняет identity остальных
контейнеров хоста и не управляет shared edge.

Владелец добавил A/TXT для DNS-01. После первой secondary validation NXDOMAIN
новая проверка завершилась выпуском сертификата; срок — 2027-02-04, продление
пока ручное. Временные TXT больше не нужны, wildcard A остаётся для bootstrap.

Общий Traefik пересоздан один раз: image, исходные flags и сетевые адреса сохранены,
добавлена только согласованная DNS-сеть и фильтрация access-log fields. Остальные
контейнеры не перезапускались. Все 14 контрольных результатов до/после совпали
(включая две прежние TLS-ошибки, которые не исправлялись в этой задаче).

Canary обнаружил сохранение ID в ошибке strict SNI AGH. Штатный structured logger
отключён через `log.enabled: false` без перезаписи native ACL/admin. Legacy logger
в pinned версии отдельный; поэтому проверены actual Docker/raw logs на success,
deny и malformed/TLS error paths. Новый canary и действующие IDs не найдены;
оба временных ClientID отозваны, исходная утечка хранится как positive control
с уже недействующим тестовым ID. Проверка не заявляет отсутствие любых неизвестных
внешних sinks и должна повторяться при изменении logging/TLS/runtime inputs.

На production прошли failure-after-rules-write/rollback, disable, all-off, restore
и сохранение отозванного клиента. Три exact login hosts ChatGPT добавлены вручную
по официальным рекомендациям с references в каталоге; blanket suffix не включён.
Для всех пяти текущих hosts проверены public DoH/DoT и origin CA/TLS извне VPS.
Native accepted generation определяется из mounted relay/Compose metadata;
bootstrap input не используется для восстановления live allowed_clients.

Независимое review технического rollout — PASS.
[Production evidence и ограничения](reports/2026-11-06/production-pilot.md).
Обязательный остаток до product DONE включает и управление реестром, и реальную
работу устройств/сервисов. Предыдущее сведение остатка только к пользовательскому
тесту было ошибочным; владелец явно напомнил об исходной продуктовой цели.

- Расширяемый каталог геосервисов на готовом источнике, а не ограничение двумя
  вручную заданными сервисами/пятью hosts. Полнота всего интернета не обещается;
  включение выбранного сервиса должно учитывать его необходимые домены.
- Действующее автоматическое получение изменений реестра. На момент этого
  уточнения downloader был ограничен двумя source files, а workflow находился в
  незамерженном PR и по расписанию не работал. Новый срез ниже заменяет downloader;
  artifact с diff сам по себе не является работающим обновлением каталога.
- Безопасный путь обновления одобренных правил и предложения новых scopes с
  понятным результатом/активным состоянием/rollback. Текущий native resolver
  автоматически обновляет IP уже разрешённых hosts, но не перечень доменов.
- Приёмка системного DoT home→mobile и DoH роутера, ChatGPT login/message/file/
  CDN/reopen и обычного сайта напрямую. Обе строки уже выданы в private chat;
  в Git они не публикуются, результат практического теста пока не получен.

Нового допуска на согласованный rollout не требуется. Работа над реестром и его
автоматизацией может продолжаться независимо от ожидания теста устройств.
Полный GOAL не закрыт.

### Следующий срез: реестр и действующая автоматизация

Выбран готовый generated Sing-box JSON каталог MetaCubeX/meta-rules-dat (`sing`),
а не новый парсер Geosite. Проверенный immutable pin содержит 2019 списков:
это сервисы, категории и attribute-варианты, не доказательство 2019 геосервисов.
Source owner задаёт exact/suffix и raw unsupported правила; включение и допустимые
границы остаются у локального каталога. Неподдержанные regex/compound predicates
явно показываются, а не расширяют маршрут и не пропадают молча.

Границы: upstream JSON → `rules/registry.json` (accepted source snapshot/index),
локальные selection/approved scope/manual overrides → `rules/pilot.json`,
производная native policy → прежние AGH/Traefik/HAProxy. Live ACL/admin остаются
у AGH. Новый source snapshot не разрешает сам по себе новые roots/scopes.

Последовательность: готовый широкий index + выборочные definitions; projection
одобренных scopes с native suffix/exclusions; единый GitHub Actions scheduler и
видимые proposal PR; затем согласованное применение принятой политики с actual
readback/wire/rollback. Проверенные source изменения должны попасть в default
branch и быть запущены там, иначе расписание не считается работающим. Вторая
подсистема source downloading на VPS не создаётся.

Native AGH experiment уже подтвердил 72 suffix/exclusion DNS cases и cleanup.
Дополнительная проверка выявила duplicate A при overlapping exact+suffix:
исправлен минимизацией wire patterns; повторный native прогон прошёл 72 случая.
Полный native suffix путь принят на Linux: 33 route/DNS/exclusion checks,
native HA syntax в обоих origin modes и Traefik TCP routing для 2048 patterns.
Найден и исправлен native HA word-limit defect; повторные checks и cleanup PASS.

Проверяемый результат текущего среза ведётся в
[registry acceptance](reports/2026-11-06/registry-acceptance.md): широкий accepted
index, selected definitions, CLI/projection и единый ежедневный proposal workflow.
Прежние exact smoke consumers теперь читают ту же projection и явно отказываются
от suffix policy. Read-only desired→actual status и service-only применение
подтверждены на production. Полное product DONE требует ещё реальной приёмки
устройств/основных функций. Mixed-case SNI admission через оба hop доказан отдельно;
TLS timeout воспроизведён прямым запросом к тому же origin IP и имеет неизвестную
внешнюю причину. Обычные lowercase подключения проходят. Исправленный оператор
`5a5ab39` применил восемь reviewed namespaces; status-only показал переход от
desired/actual drift к matches, внешние 96 checks PASS. Первый отказ после rules
write автоматически вернул прежнее поколение с readback; причина сверки Compose
literal-dollar labels устранена. Admission/protected containers сохранены.

Workflow находится в default `main` после merge PR #4 и имеет state `active`.
Ежедневное расписание — 06:23 UTC / 09:23 Москва. Первый фактический запуск
[42276996672](https://github.com/Kwentin3/smart-dns/actions/runs/42276996672)
выполнен вручную на default branch: collect, artifact upload/download и candidate
identity validation PASS. Artifact прочитан обратно: `changed=false`, upstream
commit и accepted/candidate checksums совпадают. PR-публикация корректно пропущена;
первый реальный changed-source PR и будущий scheduled tick ещё не наблюдались.
Auto-merge/deploy нет; новые risky scopes не активируются из внешнего списка.

На закрытии предыдущего этапа владелец ответил «Ещё не проверял» для Huawei/Keenetic,
ChatGPT login/message/file и Wi-Fi → mobile. Позже сообщил «работает» и указал на
невключённый Gemini; это не подтверждает автоматически все функциональные проверки.
GEO-профиль теперь включён целиком, подтверждён wire/readback и анонимным HTTP;
запрошен результат повторного открытия Gemini с реальной сессией. Endpoint-строки
прежние. После GEO-rollout владелец подтвердил «Заработал» для Gemini: этот
продуктовый пробел закрыт. Все прочие функции/смену сети из этого ответа не выводим.
Issue #3 и полный GOAL остаются открыты до необходимой продуктовой приёмки.
Renewal DNS-01 сертификата пока ручной. Ранее принятые native checks повторяются
только при изменении входов/условий или новом расхождении.

07 ноября фактический changed-source путь публичного discovery прошёл полностью:
[run 42346695609](https://github.com/Kwentin3/smart-dns/actions/runs/42346695609)
создал [PR #7](https://github.com/Kwentin3/smart-dns/pull/7). PR blob совпал с
artifact checksum, candidate contracts PASS; лицензия и выбранные AI definitions
не изменились. После review PR принят: index теперь 2021, новые category entries
не активировались на VPS. Приватный GEO-source и его accepted policy не менялись.
Естественный timer tick/changed-source GEO proposal ещё не наблюдались.
