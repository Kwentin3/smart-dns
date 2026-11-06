# Инженерный аудит по 11 вопросам PR #2

Основание: [комментарий 6686203479](https://github.com/Kwentin3/smart-dns/pull/2#issuecomment-6686203479).
Проверен код `fa65c017bf8cd728f477c4f1946884cd01ec1c9a`, сохранённые конфигурации,
логи и [результаты повторного стенда](review-results.json). Семь runtime/test-файлов
совпадают с хешами проверенного архива. Это аудит пригодности и предпосылок,
а не ещё одно заключение о возможности merge и не разрешение production.

Это историческое состояние `fa65c017`. Последующие исправления и повторная
приёмка описаны в [результате рефакторинга](refactor-acceptance.md); исходные
находки не следует переносить на изменённый код без сверки версии.

PASS относится только к явно названной проверке. FAIL означает установленное
несоответствие указанному свойству; отсутствие проверки обозначено NOT_TESTED.
В этом аудите не запускались production-команды, новый Linux-стенд или модельные
вызовы. Единственный новый эксперимент — ошибка записи renderer в локальном
временном каталоге; каталог удалён. Runtime и конфигурации проекта не изменены.

## 1. Что обещаем пользователю?

**PASS: технический TLS-маршрут. NOT_TESTED: работа ChatGPT/Claude как продуктов.**
В [probe.py:51](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/probe.py#L51) проверяется TLS handshake с CA/hostname,
без HTTP-запроса, входа, сообщения или файла. Два точных имени не доказывают
полноту login/CDN/API-зависимостей. Утверждение «сервисы работают» пока необоснованно.

Минимальная продуктовая приёмка: один согласованный браузер и сервис, чистая
сессия с выбранным DoH без VPN/скрытого DNS fallback → вход → новое сообщение с
ответом → небольшой несекретный файл с проверкой его содержимого → повторное
открытие сессии. Одновременно проверить обычный сайт напрямую и фактическое
прохождение выбранного сервиса через relay. Добавлять только наблюдённые
необходимые hosts после review. Альтернатива — честно оставить обещание на уровне
TLS-пилота, не расширяя домены и поддерживаемые устройства заранее.

## 2. Действительно ли DNS частный?

**PASS: проверенные POST DoH и plain DNS. NOT_TESTED: все пути доступа.**
[Native receipt](native-results.json) доказывает REFUSED без ответов для missing/
unknown ClientID, UDP drop и TCP REFUSED на localhost. [Linux receipt](review-results.json)
подтверждает отказ через edge и исключение 12 отрицательных URL по RouterName.
Публикации DNS-порта нет, но listener существует. GET, отзыв ID после restart,
прямой HTTP/DNS порт контейнера и доступ из соседней сети отдельно не проверялись.
Безопасность после изменения ACL через management также не доказана.

Минимум — сначала закрыть управление из вопроса 3, затем проверить эти несколько
входов тем же нативным владельцем admission. IP прокси в allowed_clients не добавлять.
Альтернатива — оставить узкую формулировку гарантии только для проверенных путей.

## 3. Кто управляет AGH?

**FAIL: административная аутентификация отсутствует. NOT_TESTED: захват из peer-контейнера.**
[render.py:64](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/render.py#L64) задаёт HTTP `0.0.0.0:3000` и `users: []`;
у сервисов одна неразделённая Compose-сеть. Внешний фильтр URL не защищает прямое
обращение peer к API. В pinned AGH [проверка аутентификации отключена без users](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/home/authhttp.go#L487).
[Нативный access/set](https://github.com/AdguardTeam/AdGuardHome/blob/003d6e1e15e04127f6d6d5e2f5c1aa843130752a/internal/dnsforward/access.go#L242)
позволяет изменять ACL: доступный незащищённый management потенциально ослабляет
и DNS admission. Это цепочка по исходникам, не выполненная атака и не находка
экспонированного production API — Smart DNS там не развёрнут.

Наименьший кандидат — штатная учётная запись AGH с password hash и проверка
неавторизованного API. Альтернатива — отдельная сеть edge↔AGH с явно принятой
границей доверия к edge. Новый auth-сервис или база пользователей не нужны.

## 4. Где может утечь ClientID?

**PASS: секрет не найден в проверенных lab-логах. NOT_TESTED: production logging/backup.**
[probe_review.py](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/probe_review.py) проверяет отсутствие временного ID
в actual edge logs. Это не проверка всех ошибок, tracing, браузерных экспортов и
бэкапов. В private evidence ID намеренно сохраняется в settings и effective AGH
config; в Linux-архиве settings имеет mode 0664, config — 0600. Это не доказательство
публичной утечки, но `.gitignore` не ограничивает чтение локальными пользователями
и не защищает копии/архивы. Опубликованные receipts секрета не содержат.

Штатный кандидат Traefik 3.6.25 — [router-specific accesslogs=false](https://github.com/traefik/traefik/blob/v3.6.25/docs/content/reference/routing-configuration/http/routing/observability.md#L57):
сохраняет логи остальных сервисов. Он не покрывает rejected URL и чужой router,
debug/error/tracing. После отдельного разрешения нужен синтетический canary и
поиск его raw/encoded форм на success/deny/error во всех действующих sinks;
никаких реальных ClientID в тестовый отчёт. Альтернатива — отдельные обезличенные
DoH-журналы. Для private inputs/архивов достаточно ограниченных прав и retention,
а не нового хранилища секретов ради пилота. Production-вариант здесь не проверен.

## 5. Что ограничивает злоупотребления?

**PASS: лимиты новых lab-контейнеров. NOT_TESTED: нагрузка, безопасная для Hermes.**
[render.py:74](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/render.py#L74) и [:87](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/render.py#L87)
задают relay maxconn 256/timeouts, по 128 MiB/0.5 CPU/100 PID и ротацию логов.
По [pinned limiter](https://github.com/AdguardTeam/dnsproxy/blob/acf2b30e05202e171bbbaf4a3176ea07edb964b3/ratelimit/ratelimit.go#L51)
`dns.ratelimit:20` ограничивает только UDP; DoH throttling нет. Обладатель ID может
нагружать DoH, любой клиент — два разрешённых SNI. Это ограниченный публичный relay,
а не relay с персональной авторизацией. Bandwidth quota и согласованного порога
остановки нет. Smoke stats не являются нагрузочной приёмкой.

Лимиты новых контейнеров не ограничивают работу общего production Traefik и
канал хоста. Минимальный следующий шаг — согласованный бюджет requests/concurrency/
трафика, штатные router limits и bounded load test с latency/errors существующих
сервисов и условием остановки. Альтернатива — пока не открывать публичный пилот.
Значения безопасной нагрузки из текущих данных вычислить нельзя.

## 6. Можно удалить Smart DNS независимо?

**PASS: отдельный lab-project и соседний HTTP fixture. NOT_TESTED: общий production edge.**
В двух прогонах удалены собственные контейнеры/сеть; набор 15 прежних container ID
не изменился. Это доказывает отсутствие их пересоздания, но не доступность Hermes.
HTTP fixture проверен до удаления; after-delete пользовательский сценарий Hermes
не выполнялся. На production Smart DNS не ставился и не удалялся.

Минимум после согласования интеграции — before/after HTTP-проверки конкретных
существующих routes и удаление только новых services/labels; общий edge не
перезапускать. Альтернатива — отдельный ingress/IP, но доказанной необходимости
для этого усложнения пока нет. [Откат](../../rollback.md) остаётся процедурой,
не записью исполненной production-проверки.

## 7. Сколько живёт фиксированный origin?

**PASS: адрес публичный и текущий TLS проверен. NOT_TESTED: срок, регион и refresh.**
[run_lab.sh:19](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/run_lab.sh#L19) выбирает первый отсортированный public A;
срок пригодности и географическая политика не проверяются. Сертификат может быть
исправен при HTTP geoblock или сломанном продукте. DNS/CDN change не расширит
направления relay, но может прекратить работу. Гарантированного срока нет.

Минимум — время/источник resolution в private записи, approved origins и короткий
HTTP/product smoke при регрессии; затем reviewed refresh и существующий stop-first
порядок. Альтернатива — небольшой вручную одобренный резерв адресов. Runtime
resolver с произвольным fallback не требуется.

## 8. Кто определяет домены и что при частичном отказе?

**PASS: генерация из одного списка. FAIL: безопасная перезапись существующего output.
NOT_TESTED: исполненный update/restore.**
[pilot.json](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/rules/pilot.json) — authority; реестры только предложения.
[Контракт](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tests/test_render.py#L42) сравнивает фактические три host sets.
При этом [render.py:108](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/render.py#L108) пишет файлы по очереди.

Новый локальный fault injection: сгенерирован старый набор из двух hosts; в его
временном output `haproxy.cfg` заменён каталогом; запущен render нового набора с
одним host. CLI завершился с exit 1, **DNS уже содержал один новый host, старый
Compose — два**. Политика не была развёрнута; fixture удалён. Это подтверждённый
mixed output, а не утверждение о production-инциденте. Runbook предписывает новый
каталог и тем самым снижает риск; CLI это требование не обеспечивает.

Минимальный кандидат — отказ от записи в занятый output, новый каталог и readback
перед использованием. Альтернатива — сохранить строго ручной staging с запретом
активации после ошибки. Нужен один намеренно неудачный update/restore в стенде,
не новый deployment controller. `snapshot.sha256` охватывает лишь rules/origins
([:58](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/render.py#L58)); ClientID, upstream, relay A и images могут
измениться без смены SHA. Это документированный rule fingerprint, не идентичность
всего поколения. Для приёмки нужны private hashes inputs/output и effective AGH
rules/Docker labels, как в сохранённом расширенном receipt.

## 9. Какие устройства поддержаны?

**NOT_TESTED: ни одна полная device-конфигурация.** Запуск Windows-бинарника AGH —
не тест Windows DNS client. Для iOS/iPadOS описан DoH profile, для Windows/browser —
URL/template; установка, bootstrap, strict fallback и смена сети не проверены.
[Исследование клиентов](../../dns-research.md#client-delivery) отделяет Android
Private DNS hostname/DoT от произвольного URL DoH. У текущего Compose нет DoT
listener: обещать этот штатный Android-сценарий текущим артефактом нельзя.

Минимум — принять один браузер/OS/network switch, затем расширять матрицу.
Альтернатива для Android-пилота — конкретный клиент с custom DoH, без обещания
системного Private DNS. DoT — отдельный дизайн и согласование: hostname ClientID
не подменяет защищённый URL-секрет и имеет другую видимость в DNS/SNI.

## 10. Что с AAAA, HTTPS/SVCB, QUIC и ECH?

**PASS: ответы AAAA/HTTPS/SVCB NODATA для двух точных имён.
NOT_TESTED: фактическое поведение реальных клиентов.** [Пробы](review-results.json)
проверяют DNS wire, а не браузерный fallback. У стенда нет UDP website relay;
TCP fallback QUIC, cached Alt-Svc/ECH и альтернативный resolver не испытаны.
NODATA не удаляет старые настройки из кеша. Политика двух apex не покрывает
неучтённые поддомены/CDN. Обход/неработоспособность конкретного клиента не доказаны.

Минимум — записать эту границу и проверить выбранный браузер с чистым и тёплым
кешем. Альтернатива — ограничить поддержку проверенным TCP-клиентом; универсальный
прокси и глобальное отключение IPv6/QUIC не следуют из задачи.

## 11. Что стоит упростить или рефакторить?

**PASS: нативные владельцы и малая область пилота. Есть конкретные дефекты harness/evidence.**
Собственного DNS/proxy/control plane нет. Сохранить два точных host, ручные origins
и stop-first проще, чем строить автоматический updater.

**HAProxy потенциально можно убрать:** у Traefik 3.6.25 есть native TCP service с
[numeric servers[].address](https://github.com/traefik/traefik/blob/v3.6.25/pkg/config/dynamic/tcp_config.go#L112)
и TLS passthrough. Точный HostSNI может вести прямо на approved public IPv4:443,
без runtime resolver. Но address исключён из Docker labels; текущий Docker
provider получает backend IP контейнера, а не произвольный external endpoint
([builder](https://github.com/traefik/traefik/blob/v3.6.25/pkg/provider/docker/config.go)).
Например, file provider решает это штатно, но сейчас выключен. Его включение
затрагивает static configuration общего edge, требует отдельного согласования
и потенциального restart/recreation. Это реальная альтернатива «меньше runtime
компонентов ценой более широкого инфраструктурного изменения», подтверждённая
схемой/source, но не runtime-тестом. Рассмотреть перед production; не внедрять
в текущем PR и не превращать в условие завершения изолированного пилота.

Небольшие кандидаты для отдельного согласования, в порядке пользы:

1. Закрыть management нативным средством и добавить direct-peer negative test;
   не вводить второго владельца пользователей.
2. Запретить in-place render и читать effective configuration после изменения;
   не создавать транзакционный deployment framework.
3. Исправить точность evidence: [run_lab.sh:75](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/run_lab.sh#L75)
   inspect'ит tags, хотя запуск идёт по digest. Минимум — inspect image IDs
   работающих контейнеров/locked references. Факт запуска неправильного образа
   **не установлен**; текущие сохранённые digests совпали с lock.
4. Сузить название `direct-unmodified`: [probe.py:40](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/probe.py#L40)
   для subdomain допускает даже SERVFAIL, если нет relay IP. Для этого случая
   доказано «не увидели rewrite», а не неизменность полного ответа. Минимум —
   проверить deterministic fixture answer или назвать результат точнее.
5. Устранить окно cleanup в [test_native_agh.py:33](https://github.com/Kwentin3/smart-dns/blob/fa65c017bf8cd728f477c4f1946884cd01ec1c9a/tools/test_native_agh.py#L33):
   thread уже стартует, а `try/finally` начинается после чтения/compile/write.
   Ошибка этого setup оставит thread вне cleanup. Это вывод по коду, ветка не
   воспроизводилась. Минимум — охватить setup существующим finally. Параллельные
   lab runs не обещать: project/ports фиксированы; достаточно preflight.

## Решение по этапу

Изолированный пилот остаётся полезным техническим результатом. Оснований считать
его готовым private production-сервисом нет. Для следующего небольшого изменения
обоснованы management boundary и безопасная публикация generated output; прочие
проверки организовать вокруг одного реального пользовательского сценария.
В этом аудите реализован только отчёт. Исправления, новые допуски и product scope
не выдаются за уже согласованные или выполненные.
