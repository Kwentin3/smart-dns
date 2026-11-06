# Smart DNS: текущий GOAL рефакторинга

Источник: решение владельца в чате 2026-11-06 и [аудит](reports/2026-11-06/engineering-audit.md).
Результат: минимальный нативный пилот с защищённым управлением AGH, согласованной
подготовкой файлов, действующими DoH limits/logging и проверенным lab rollback.
Production, Hermes и общий Traefik не меняются. Полные сервисы/устройства вне этапа.

Решение по составу: сохранить HAProxy и Docker provider. Native Traefik TCP
inFlightConn считает по source IP, не заменяет global maxconn и idle timeout HAProxy.
Убирать HAProxy ценой нового ограничителя или изменения shared edge не проще.

Владельцы: rules/pilot.json → render (только проверка/представление) → native
AGH DNS/admission/admin; Docker labels → native Traefik HTTP/SNI/middleware;
HAProxy → fixed origin/глобальный connection cap/idle timeout. У runtime нет
нового владельца пользователей, маршрутов или обновлений.

Проверяемые срезы: native AGH authentication и direct/GET/revocation; новый
неперезаписываемый output при ошибке; native aggregate DoH rate/concurrency и
router logging; точные DNS/TLS/SNI/path guards; неуспешное обновление/restore;
identity образов по работающим контейнерам; bounded cleanup и readback.

Проверено: 18 контрактных тестов, 12 native AGH checks, 17 Linux probes,
21 URL/SNI checks, реальные rate/concurrency bounds, direct-peer admission,
effective policy и rollback с неизменными edge/neighbor ID/StartedAt.
Evidence и границы: [refactor acceptance](reports/2026-11-06/refactor-acceptance.md).
Собственные lab-контейнеры/сети/каталоги и native процессы убраны; private evidence
сохранён локально. Независимое evidence-review — PASS: source/archive identity,
native boundaries, фактические лимиты, rollback и cleanup подтверждены.
Поставка — [PR #2](https://github.com/Kwentin3/smart-dns/pull/2); точный commit и
CI-state читаются из нативных GitHub checks, не дублируются этим документом.
Следующий этап: только отдельно согласованные production integration и
пользовательская приёмка; обязательных runtime-работ этого GOAL не осталось.
