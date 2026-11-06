# Приёмка KISS/native рефакторинга, 2026-11-06

Контракт: [порученный в чате GOAL и точная граница допуска](../../refactor.md#что-именно-было-поручено),
сформулированный после [аудита 11 вопросов](engineering-audit.md). Этот этап меняет только исходники
и изолированный стенд. Production, Hermes, общий Traefik, firewall, system DNS
и пользовательские устройства не изменялись. Это не приёмка ChatGPT/Claude
как продуктов и не разрешение deployment.

## Выбор минимальной схемы

Сохранены AGH + существующая схема Docker labels + HAProxy. Внешние реестры
остаются предложениями, custom DNS/proxy/user database/deploy controller не добавлены.
Удаление HAProxy рассмотрено и отклонено для этого среза: Traefik TCP
[inFlightConn](https://github.com/traefik/traefik/blob/v3.6.25/pkg/middlewares/tcp/inflightconn/inflight_conn.go)
считает по remote IP, а не заменяет global maxconn 256. Его
[passthrough proxy](https://github.com/traefik/traefik/blob/v3.6.25/pkg/tcp/proxy.go)
не заменяет idle timeout 60s HAProxy. Прямая external TCP service также требует
другого provider/static configuration общего edge. Сохранять готовый компонент
проще, чем добавлять ограничитель или ослаблять принятые гарантии.

AGH использует native users/bcrypt и ClientID admission. Traefik использует
native Host overwrite, rateLimit, inFlightReq и router observability. Собственный
render только проверяет/представляет данные и публикует новый комплект файлов.

## Идентичность и результаты

Linux input archive SHA256:
`dd9e56f639779ca642420b8803c361323c9c08d30e54c356090f5d2ead0ace35`.
Сверен перед распаковкой. [Публичный receipt](refactor-results.json) содержит
хеши десяти runtime/test/config inputs; их байты сравнены с архивом и текущим
кандидатом. Raw evidence сохранён локально под ignored `.local/refactor-final/`,
native stdout — `.local/refactor-native-results.json`. В публичных артефактах
нет настоящих ClientID, infrastructure адресов или operator credentials.

Версии/образы: неизменённый [images.lock.json](../../../config/images.lock.json).
Receipt теперь сравнивает Image ID **работающего контейнера** с image ID locked
reference и сохраняет RepoDigests, не подменяя проверку mutable tag.
Windows AGH v0.107.80 — прежний checksum-verified бинарник; его ZIP SHA256:
`46f69352b088595ff2764917d1209a69a3e8fa7a60a643201fd0d4da3d9c94bb`.

| Проверяемое свойство | Статус и фактический результат |
| --- | --- |
| Native admin boundary | PASS: без credentials/с неверным паролем 401, с верным — 200; anonymous POST access/set — 401 |
| Прямой доступ из DNS-сети | PASS: edge peer получил management 401 и anonymous GET DoH REFUSED; прямой обычный UDP/TCP DNS не дал полезных ответов |
| DNS admission и отзыв | PASS: native GET/POST по ClientID без admin credentials; revoked ID REFUSED, восстановленный ID снова работает |
| DNS/TLS/SNI | PASS: 17 Linux probes; exact rewrites, NODATA AAAA/HTTPS/SVCB, verified origin TLS, direct relay rejects и соседний HTTP router |
| URL и журналирование | PASS: 21 probes; 12 отрицательных URL оставили unmatched-router запись, 3 легитимных дали проверенный DNS wire без DoH access-log записи; sampled saved logs не содержат временный ID |
| Реальные native inFlightReq | PASS: восемь запросов удержаны настоящим UDP upstream fixture, девятый — 429 и не достиг upstream; соседний router — 200; после release восемь завершились |
| Реальные native rateLimit | PASS: последовательные 120 requests, 39 ответов и 81 HTTP 429 за 0.097s; case/port Host variants использовали общий бюджет; последующий DNS request восстановился |
| Effective policy | PASS: user_rules из native API, actual Docker HostSNI label и HAProxy ACL содержали одни и те же два hosts |
| Публикация output | PASS: 18 контрактных тестов, включая occupied-output refusal, частичную I/O ошибку со staging cleanup и неизменность accepted output |
| Cleanup при ошибке native harness setup | PASS: настоящий child process/UDP thread завершились при invalid rules до запуска AGH; нет зависшего thread |
| Native Windows | PASS: 12 checks; deterministic upstream доказывает A для обычного имени и subdomain, admin/GET/revoke/plain denial |
| Неудачный запуск/restore | PASS: собственные DNS/relay остановлены; relay с deliberately invalid native config завершился exit 1; accepted services восстановлены, прошли 16 probes |
| Независимость в стенде | PASS: edge и соседний HTTP контейнер сохранили ID/StartedAt; соседний route отвечал во время заполненного DoH и ошибки relay |
| Завершение стенда | PASS: EXIT cleanup удалил 4 своих контейнера и обе сети; 15 прежних container IDs сохранены; отдельный post-collection readback — ниже |

Нативные лимиты относятся к одному router/process: canonical Host → 20/s burst
40 → 8 in-flight. Это намеренный общий lab budget; anonymous requests тоже его
расходуют. Из проверки не следует per-ID fairness, bandwidth quota, sustained
production capacity или доказанная защита ресурсов Hermes.

Локальные native/контрактные проверки и первый Linux-кандидат уже прошли до
окончательного архива. Финальный прогон повторён после уточнения имён результатов
DNS и сохранения direct-peer/rollback receipts; это не альтернативный набор inputs.
Первый вызов финальной SSH-команды не стартовал стенд из-за PowerShell quoting;
исправлен только способ вызова, после чего команда прогона завершилась exit 0.

## Публикация и восстановление без второго control plane

`write_new` отказывает существующему output, готовит файлы в sibling staging и
публикует rename после всех записей. Ошибка не публикует частичный каталог и не
перезаписывает принятый. Это атомарная публикация локальных файлов, не атомарное
обновление AGH/Traefik/HAProxy; сохраняется stop-first порядок.

Fault injection относится только к собственному relay в стенде. Его конфигурация
намеренно испорчена **после** generation для проверки startup failure/restore;
это не разрешение применять кандидата после неуспешной проверки native syntax.
DNS был остановлен на время отказа. Общий lab edge и unrelated fixture не
перезапускались; production service этой проверкой не затрагивался.

Linux settings и effective AGH config в private archive имеют mode 0600;
output directory закрыт от других пользователей хоста. Публичный пароль/hash
fixture используется только в disposable lab, не является готовым production
credential. Runtime Python-зависимости остаются stdlib.

## Оставшиеся границы

NOT_TESTED: sustained/host-wide load и bandwidth, реальное production logging
всех sinks, устройства/сеть/fallback, полный login/CDN/uploads, QUIC/ECH/cache,
проверка географической политики/срока годности origin. Relay остаётся публичным
для фиксированных approved targets. Production integration и её приёмка требуют
отдельного разрешения. Эти пункты не подменяют завершённый scope рефакторинга.

Post-collection cleanup: временная копия эксперимента удалена после сохранения
private evidence. Отдельный readback подтвердил отсутствие собственных контейнеров,
сетей и каталога; существующих контейнеров осталось 15. Native AGH process и
localhost listeners также отсутствуют. Private evidence и ранее загруженные образы
сохранены для readback/reproduction; работающих пилотных сервисов нет.

Независимое evidence-review — PASS. Ревьюер сопоставил десять source hashes с
архивом, текущими файлами и public receipt; сверил raw ответы, limits/rollback,
actual image identity, конфигурации и cleanup. Повторных запусков при ревью не
было; данные не подменены пересказом или результатами прежнего кандидата.
