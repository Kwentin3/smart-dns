# Production GEO rollout: issue #14

Выполнен [разрешённый rollout](https://github.com/Kwentin3/smart-dns/issues/14)
полного кандидата PR #13. [Решение владельца](https://github.com/Kwentin3/smart-dns/issues/12#issuecomment-6705489539)
разрешает широкий профиль и необходимый лимит 4096. Побочное проксирование страниц
внутри широких suffix принято; индивидуальное сужение доменов не выполнялось.
Полный PRODUCT GOAL #12 остаётся открытым до пользовательской приёмки.

## Идентичность и допуск

| Объект | Проверенный результат |
| --- | --- |
| Исходный срез | `9980f679b5b244340832b0d2de30dd6505352901`, merged PR #13; 28 source/config файлов сверены по SHA256 |
| Frozen Fancy source | `25e7b1912eca4b31d44906af0df10f00c85ab268`; новая upstream версия не подставлялась |
| Прежнее принятое поколение | `f17746a8b6fb9ca0fb66d4139b57a565c1ce079342e2df476e6759efbe245cc8` |
| Новое actual/desired поколение | `239c889b7d081458fdd2ac4fed5278a163eda994aa23ebc3263a9458514f8bca` |
| Enforcement scope | `2e815b2927ecd1d292b2d6258a1a734b40ed577e8dd69da1b0d0ee52c92bc136`, совпал с native acceptance PR #13 |
| Политика | 2508 native AGH rules; минимизированный wire scope: 114 exact + 1140 suffix roots |
| Бюджет | `max_policy_entries=4096`; прежний 2048 отклонял полный кандидат |

До изменения `smart-dns status` показывал `matches`, findings отсутствовали,
actual generation совпал с последней технической приёмкой. Канонические catalog
и registry побайтово/семантически сверены с приватным сохранённым baseline.
Прежний manifest точно воспроизведён действующим compiler. Кандидат и restore
прошли `validate_candidate` в обоих направлениях: non-service infrastructure
не меняется. Приватный payload на сервере сверён с локальным SHA256.

## Выполнение

Выполнен один вызов существующего production `service_policy` на применение
кандидата; штатный оператор остановил/пересоздал только relay и заменил native
service rules AGH. Запуск занял около 29 секунд до итогового readback; это время
всей операции, не измерение непрерывности соединений.

Использованы прежние владельцы `prepare_catalog`, `product.prepare`,
`validate_candidate` и native operator. Приватный одноразовый orchestration script
держал существующий product lock, проверял baseline перед изменением и все четыре
canonical inputs перед каждой публикацией. Backup, input/source hashes и journal
сохранены до изменения. Новый controller, сервис, БД, панель или timer не создавались.

`product apply/rollback` публикует только catalog/registry. Поэтому для этой
миграции дополнительно согласованно опубликованы settings с единственным
изменённым полем `max_policy_entries` и source declaration Fancy. Существующие
shortcut и refresh service переключены на проверенный source release; расписание
и файл timer сохранены. Refresh во время frozen rollout не запускался.
После daemon-reload ближайший запуск мог сместиться внутри прежней randomized
задержки до 300 секунд; неизменность точного next-run timestamp не заявляется.

Все прежние service states/OFF/exclusions и GEO/AI grants сохранены через
проверенную catalog projection; включён `community-geo`. Прежний itdog baseline
теперь frozen local policy с provenance, а обновляемый upstream — Fancy. Это
сохраняет ранее принятые grants, но не даёт автоматической проверки их устаревания;
ограничение из PR #13 остаётся видимым, новый source merger не добавлен.

## Приёмка по фактическому пути

| Проверка | До | После |
| --- | --- | --- |
| Native literal `smart-dns status` | `matches`, прежнее поколение | `matches`, новое поколение; canonical input bytes совпадают с подготовленным кандидатом |
| Внешние DNS/TLS | 64/64 PASS | 64/64 PASS: 58 DNS requests и 6 TLS handshakes |
| Обе действующие идентичности | DoH/DoT работают | DoH/DoT работают; actual native admission сохранён полностью |
| Посторонние/отсутствующие ClientID | REFUSED | REFUSED |
| Обычное контрольное имя | Положительный direct DNS | Положительный direct DNS |
| Новые не-AI samples | Direct DNS, relay TLS отказ | Tailscale/networking, ActiveState/developer tools, Epic Games/games: relay A, подавление AAAA/HTTPS/SVCB, origin TLS с проверкой CA через фактический ingress |
| Соседние маршруты, включая Hermes/auth/dashboard | 12 observations | 12/12 совпали по HTTP status/certificate fingerprint либо классу прежней TLS ошибки |
| Соседние контейнеры и DNS | Исходные 24 protected identities | IDs/StartedAt, Config/HostConfig/Mounts и сети совпали; пересоздан только relay |
| Сертификаты и hook | Прежние served fingerprints/hook | Проверенные fingerprints и hook сохранились; сертификаты не выпускались/не заменялись |

Для соседних маршрутов до изменения задан новый явный ограниченный baseline:
литеральные Host из реальных non-Smart-DNS Traefik labels, HTTPS `GET /`, совпадающие
SNI/Host, без redirects. Десять сертификатов проверены CA; два прежних TLS verification
errors повторились без нового отказа. Ответы 200/302/401 подтверждают этот маршрут
и его границу авторизации, не пользовательскую функцию приложения.

Общий Traefik/Hermes/Authelia и соседние приложения не пересоздавались; их
конфигурация, сети и порты сохранены. Ручные firewall/system DNS изменения не
выполнялись. Production не использовался для сборки, lab или load test.

## Ограниченное наблюдение ресурсов и восстановление

До rollout: около 1164 MiB MemAvailable, unhealthy containers отсутствовали.
После внешних проверок: около 1113 MiB MemAvailable, unhealthy containers нет.
Точечный `docker stats`: relay 14.18 MiB / 128 MiB, CPU 0.51%, 3 PIDs;
AGH 27.79 MiB / 128 MiB, CPU 0.06%, 9 PIDs. Прежние CPU/memory/PID limits
сохранены. Это ограниченные замеры, не peak/capacity или длительная нагрузочная
гарантия. По этим проверкам оснований откатывать здоровый rollout не обнаружено.

Прежний source release, исходные bytes всех четырёх inputs, source bindings и
полностью подготовленная native restore generation сохранены приватно. Откат
проверен подготовкой и валидацией до rollout; фактический откат production при
здоровом результате не запускался. Для этой source/limit миграции нужен сохранённый
task-specific путь восстановления, включающий settings/source bindings; обычный
`smart-dns rollback` сам по себе не возвращает все эти файлы.

Точная команда, пути архивов и guard на ожидаемое поколение находятся в приватном
операторском receipt `.local/issue14/operator-receipt.private.json`. Эти restore
артефакты/source releases оставлены намеренно; прежний certificate hook также
продолжает использовать свой неизменённый source release. При последующем drift
helper останавливается и требует сверки текущего состояния, не перезаписывает его.

Приватные preflight/postflight/native/внешние квитанции сохранены в `.local/issue14/`.
Полные списки, ClientID, адреса, конфигурации и служебные payloads в Git не включены.

## Что ещё не принято

DNS/TLS не доказывают Tailscale login/peer traffic, ActiveState account/download,
Epic account/store/game/download, AI-сессию или всю базу доменов. Не проверены
обычное устройство, Wi-Fi → mobile, реальный browser/download/egress и основные
функции выбранных приложений. 1305 новых matchers не объявляются работающими
сервисами. Эти пункты остаются пользовательской приёмкой открытого #12; #14
фиксирует техническое production-применение и наблюдаемые проверки.
