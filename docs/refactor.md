# Smart DNS: текущий GOAL рефакторинга

Источник поручения: переписка с владельцем 2026-11-06, после [аудита](reports/2026-11-06/engineering-audit.md).
Результат: минимальный нативный пилот с защищённым управлением AGH, согласованной
подготовкой файлов, действующими DoH limits/logging и проверенным lab rollback.
Production, Hermes и общий Traefik не меняются. Полные сервисы/устройства вне этапа.

## Что именно было поручено

[11 инженерных вопросов](https://github.com/Kwentin3/smart-dns/pull/2#issuecomment-6686203479)
были материалом для аудита. Позже в текущем чате владелец попросил сформулировать
GOAL рефакторинга, уточнил «напомню максимально kiss, максимально нативно» и после
описания объёма написал: «Возьми а работу этот гоал».

Описанный перед этой репликой объём: проверить необходимость компонентов,
закрыть управление AGH штатной защитой, безопасно готовить согласованные
конфигурации, использовать native DoH limits/logging, проверить затронутое
поведение/ошибки/откат в изолированном стенде. Production и Hermes были исключены.

Это фиксация поручения из чата автором изменений; отдельной публичной записи
утверждения в GitHub нет. Поручение разрешало исходники и lab-проверки. Оно не
утверждало готовность production, каждый инженерный выбор как решение владельца
или изменение существующего общего edge. Ревью PR также не заменяет этот допуск.

## Результат этапа

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

## Отдельный release gate

Статус production readiness — **NOT_TESTED**. До разрешённого пилотного использования
нужны следующие наблюдения на точной согласованной версии private integration:

| Граница | Наблюдаемое доказательство готовности |
| --- | --- |
| Допуск и доступ | Владелец отдельно разрешил private Compose/сети/certificates/origins/limits/logging и rollback window; рабочий закрытый admin path проверен, management/API не опубликован |
| DoH и секрет | Реальный клиент проверяет CA/hostname/срок DoH-сертификата; valid ID работает, anonymous/unknown/revoked GET/POST не дают полезного ответа. Синтетический ID-canary не найден в перечисленных actual logs/error/tracing/diagnostic sinks за окно success/deny/error, включая unmatched/encoded URL; в отчёте нет реального секрета |
| Заявленные устройства | Зафиксированы OS/version/client/mode; каждый заявленный сценарий проходит bootstrap, смену сети и согласованный strict fallback. Непроверенные платформы не объявляются поддержанными; Android Private DNS не приравнивается к custom DoH URL |
| Пользовательский результат | Для каждого заявленного сервиса: вход, новое сообщение и ответ, небольшой несекретный upload с проверкой содержимого, CDN/assets и повторное открытие сессии. Подтверждены нужный relay path и обычный сайт напрямую |
| Ресурсы и восстановление | На отдельно подготовленном/разрешённом объёме наблюдаются лимиты, ресурсы и контрольные сценарии Hermes/сайтов. При withdrawal/restore меняются только новые services/labels; общий edge сохраняется, прежний DNS/доступ клиента восстанавливается с учётом фактических TTL/cache, временные ресурсы удалены |

Для canary фиксируются набор sinks, версия и окно наблюдения: отсутствие совпадений
в этих источниках не доказывает отсутствие неизвестного журнала. Lab budgets и
lab rollback не заменяют эти проверки. До этого gate завершён только изолированный
рефакторинг; новые production-действия выполняются после отдельного разрешения.
