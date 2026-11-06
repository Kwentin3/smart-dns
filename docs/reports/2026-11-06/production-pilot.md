# Production pilot: техническая приёмка

Владелец отдельно разрешил подготовленный пакет и попросил осторожно обращаться
с Traefik. Принят **технический rollout**, не полная продуктовая цель #3.
Авторитетная запись задачи: [product-goal](../../product-goal.md).

## Подтверждено

- Два новых digest-pinned компонента: AGH 0.107.80 и HAProxy 3.2.26. Фактические
  memory/CPU/PID limits — 128 MiB / 0.5 CPU / 100 каждый. Админка только localhost;
  публичны DoH через текущий HTTPS ingress и DoT TCP/853. Plain DNS не опубликован.
- Общий Traefik 3.6.25 пересоздан с исходным образом, исходными flags/сетевыми
  адресами, одной новой DNS-сетью и согласованным access-log allowlist. Точный
  backup исходных Compose/env/ACME сохранён приватно на сервере для rollback.
- Все 14 контрольных HTTP/TLS результатов и fingerprints до/после совпали.
  Две старые TLS-ошибки остались прежними; утверждение о здоровье всех сайтов
  этим отчётом не делается. Остальные контейнеры не перезапускались.
- Public CA/hostname проверены для реальных DoH/DoT строк; DoT bootstrap проверен
  извне VPS. Unknown/anonymous/revoked получают отказ, public management — 404,
  direct native admin — 401 без учётных данных. Обычный DNS ответ не переписывается.
- Production operation прошла настоящий отказ команды после native rules write
  с восстановлением, disable, all-off и restore. Отзыв клиента сохранился. Native
  API/labels/mounts/image readback и wire DNS/TLS проверки подтверждают изменённый путь;
  receipt одной операции сам по себе wire acceptance не заменяет.
- В каталоге пять exact hosts: ChatGPT и три проверенных имени входа плюс Claude
  baseline. Для всех проверены DoH/DoT rewrite и public-CA origin TLS через VPS.
  Где официальный источник задаёт suffix, разрешён только вручную выбранный exact host.
- 58 unit checks PASS; renderer фактически выполнен на системном Python 3.9,
  артефакты сопоставлены с согласованным production пакетом.

## Privacy gate

Первый canary дал одно совпадение в native AGH strict-SNI warning. Этот тестовый
ID отозван. Штатный `log.enabled: false` подавляет соответствующий structured
logger; legacy logger в pinned версии отдельный, поэтому полная тишина не заявляется.

Новый canary прошёл POST/GET, Host variants, unknown/missing IDs, unmatched/encoded
paths, wrong Host, invalid DNS и outside-SAN TLS errors. После завершения окна —
ноль совпадений в Docker API logs и raw json-file logs edge/AGH/relay. После
production операций и использования настоящих строк повторно проверены live IDs:
ноль совпадений. Canary отозван и получает REFUSED по обоим публичным протоколам.
Старый неактивный canary оставлен в приватном evidence как positive control.

Область доказательства — перечисленные sinks/inputs и pinned runtime. Результат
не исключает неизвестные внешние sinks. Query logging и statistics отключены;
DoT hostname ID остаётся видимым в bootstrap DNS/TLS SNI согласно принятому компромиссу.

## Остаток и эксплуатация

Сертификат выдан до **2027-02-04**. DNS-01 в этом пилоте ручной; unattended renewal
не настроен. После нового выпуска нужно установить пару только в модуль и
перезапустить только AGH. Текущий shared-edge сертификат DoH обслуживает его
существующий native resolver. Временные challenge TXT можно удалить, wildcard A
нужен для телефона. Настоящие IDs, ключи и connection strings не публикуются в Git.

Системное подключение реальных устройств, смена сети, ChatGPT login/message/file/
CDN и повторная сессия пока **NOT_TESTED**. Наличие origin TLS не доказывает
региональную политику или полноту приложения. Claude пока только TLS baseline.

Собственные observer/checker/fault-shim процессы завершены; временные ClientID
отозваны. Два module containers/network и приватные source/backups/evidence
оставлены намеренно: рабочий пилот, обслуживание и проверяемый rollback.
Выборка evidence без ключей/паролей/ACL/raw logs хранится локально в
`.local/production-live-evidence/`; серверные оригиналы сохранены у оператора.
Независимое evidence-review технического этапа — PASS.
