# Issue #3: native runtime и service operation

Принимается изолированный repo/lab срез, **не весь продукт и не production**.
Текущая цель и обязательный остаток: [product-goal](../../product-goal.md).

## Фактический результат

- 52 контрактных теста PASS, включая реальные мутации candidate файлов/manifest:
  ручное удаление HA guard, правка deny policy, forged hash, подмена каталога,
  изменение инфраструктуры/клиентов/admin не проходят повторный render.
- 10 native integrated checks PASS: проверяемые CA/hostname DoH и DoT, admission,
  revoke/restore, обычный DNS напрямую, public-CA TLS двух origin через relay/edge.
- 5 native service checks PASS: отказ после actual native rules write и real
  rollback; disable; all-off; restore; отдельный явный возврат телефона.
- Во всех изменениях сервисов телефон оставался отозванным. AGH, edge и соседний
  сайт сохранили ID/StartedAt. Cleanup `0`, 15 существовавших container IDs совпали;
  owned containers/networks/check containers/remote directory/operator lock убраны.

Использованы digest-pinned AGH 0.107.80, Traefik 3.6.25 и HAProxy 3.2.26 из
[lock](../../../config/images.lock.json). На контейнер — 128 MiB/0.5 CPU/100 PID;
syntax checker — 64 MiB/0.5 CPU/64 PID. Все опубликованные test ports — localhost.
Ни production mounts, ни пользовательские сервисные аккаунты не использовались.

Frozen input SHA256:
`ecf9025c7c4304118ef51b48b06fdbe0ca075c2a2902614687e001d5eeaaa0cf`.
Проверенные source SHA256:

| Файл | SHA256 |
| --- | --- |
| `tools/render.py` | `145e29e77150799cedd04853fb15c2c14eb1c0f15af54e28a7028f736ff4e19c` |
| `tools/service_policy.py` | `6a7a73efce50701e4597d998beaa35389560006efe7e163c58035d25f45b29d7` |
| `tools/probe_integrated.py` | `b5a6490131ae99cb92a84ccdf8f204bc6ccb6265898085620abf32d2d99f87d0` |

Оригинальные receipts и frozen fixtures сохранены оператором приватно в
`.local/product-policy-receipt/` и `.local/product-policy-input.tar.gz`.
Независимое review проверило соответствие исходников native input и receipts — PASS.

После этого native input добавлена переносимость записи: `write_new` фиксирует LF,
чтобы hashes соответствовали байтам и при генерации на Windows. Это проверяет
52-й тест; в native run было 51. Текущий renderer повторно сопоставлен с четырьмя
native generations: HA/deny bytes, snapshots и relay definitions идентичны.

## Границы доказательства

Первый integrated прогон отклонил default certificate: file provider не смог
прочитать disposable TLS directory. Права fixture исправлены; неудачный прогон и
cleanup сохранены. Ошибка не обходилась отключением проверки сертификата.

Fault injection один раз отклонил native `compose up` после записи правил; остальные
Docker/API операции, включая rollback, выполнялись реально. Проверяется восстановление
после отказа команды, а не каждая возможная Docker/сетевая авария.

Bootstrap fingerprint сравнивает намерение; native API и mounted files/labels с
fresh relay start и wire checks подтверждают затронутый путь. Полная интроспекция
всех live HAProxy/AGH настроек не заявляется. Receipt операции сам требует внешнюю
wire acceptance; эти проверки выполнены в данном стенде.

Stop-first прерывает также DoT, проходящий через relay. Для обновлений нужен один
оператор; при native конфликте ACL не восстанавливается из старого snapshot.
При неудаче rollback операция пытается оставить relay закрытым и сообщает partial failure.

Открыты production certificate/logging/capacity, реальные устройства/смена сети,
региональная политика и вход/сообщения/файлы/CDN. Два apex host не означают полного
покрытия ChatGPT/Claude. Рабочий VPS и Hermes не изменялись.
