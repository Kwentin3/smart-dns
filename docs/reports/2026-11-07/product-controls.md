# Управление и эксплуатация: проверенный срез

Полный product GOAL остаётся открытым: пользователь отложил полный прогон телефона
и поручил продолжить превращение пилота в продукт. Gemini подтверждён владельцем.

Исправлена наблюдаемая ошибка: OFF ChatGPT не снимал маршрутизацию тех же доменов,
которые разрешала включённая GEO-группа. Каталог теперь различает отдельный сервис
и группу; OFF сервиса задаёт исключение из группового разрешения. Пересечение с
другим включённым сервисом сохраняется явно как shared routing. AGH/HAProxy/Traefik
получают результат одного compiler, без второго реестра разрешений.

Новый `product.py` объединяет status/on/off/add/exclude/include/apply/rollback/refresh.
Предпочтения публикуются после native apply; при конфликте или неуспешном readback
восстанавливается фактическая принятая политика, а внешняя правка сохраняется.
Гонка между atomic write и последующим чтением устранена: владелец сериализации
возвращает точные записанные байты, recovery использует их для проверки владения.

Refresh переиспользует collector и catalog projection. Новые roots не включаются
скрыто, удаления выбранных правил и изменения лицензии требуют review. Принятый
snapshot обновляется только вместе с успешно применённой конфигурацией.
Systemd templates используют тот же CLI с отдельным бюджетом на восстановление.

## Evidence

- Windows и Linux: 134 unit tests PASS. Compiler и файловые архивы настоящие; внешние IO в unit tests
  подменяются на своих границах.
- Linux native GEO: 61 checks PASS. OFF снимает rewrite и admission в relay при
  включённой GEO-группе; Gemini/Claude сохраняются, ON восстанавливает DNS/TLS.
  Native ACL, исходные policy inputs и чужие контейнеры сохранены, cleanup PASS.
- Linux CLI: реальные process/flock/archive/CAS/default subprocess/service_policy
  и Docker прошли status → off → rollback → exclude → include → refresh,
  actual=`matches`, четыре native
  child receipts `applied-and-readback`, admission/protected services неизменны.
  Все сервисы в этом fixture OFF, DNS discovery отключён отдельным transport
  override; общий edge лаборатории не получает тестовые маршруты. Эффективное
  ON/OFF-поведение проверено предыдущим отдельным native fixture.
- Linux AGH: действующая native выдача нового сертификата после замены файлов
  подтверждена проверенной TLS-сессией без restart. Inode каталога, ACL и rules
  сохранены; неверная пара отвергнута, cleanup PASS. Сертификаты и CA одноразовые,
  production keys и клиентские секреты не попадали в лабораторию.
- `systemd-analyze verify` для новых service/timer templates — PASS.

Private receipts: `.local/product-controls/{evidence,cli-evidence,certificate-evidence}`.
Первая CLI-репетиция была отклонена до изменений: fixture не содержал второго
защищаемого сервиса; добавлен изолированный existing-site witness, повтор PASS.

## Граница готовности

Deploy hook проверен; автоматический выпуск пока не настроен. Нужно выбрать
поддерживаемый доступ к DNS-панели или делегировать ACME-проверку. Штатный Certbot
остаётся владельцем сертификата. Два отдельных файла не образуют crash-atomic
пару: hook проверяет readback/restore, но SIGKILL между заменами требует диагностики.
Полная приёмка телефона, файлов и смены сети остаётся обязательным шагом всего GOAL.

## Production rollout

Артефакт `8764162f4e2954a7ad85e48675a01302a617ef2c` прошёл CI и применён на VPS
через тот же CLI/native operator. Actual generation:
`f17746a8b6fb9ca0fb66d4139b57a565c1ce079342e2df476e6759efbe245cc8`, status=`matches`.
Все четыре группы ON; native service rules и canonical inputs не изменились.
Все контейнеры, кроме разрешённого relay, сохранили ID/StartedAt, включая AGH
и общий edge. Сборки и rehearsal на production не выполнялись.

`smart-dns status` установлен как тонкий shortcut к pinned operator. Новый
systemd refresh впервые выполнен с Result=success/exit0; ежедневный timer активен,
прежний proposal-only timer отключён. Certbot deploy hook ограничен собственной
lineage, проверил текущую пару и вернул `unchanged`; выпуск/renewal не запускался,
остальные сертификаты и shared Traefik не изменялись.

Private production receipts: `.local/product-controls/production/`.
Внешний прогон после rollout: 180 DoH/DoT/origin-TLS checks PASS, включая обычные
сайты и отказ неизвестному клиенту. Это подтверждает transport, но не подменяет
приёмку функций приложений и устройств. Временные лабораторные каталоги,
контейнеры, сети и locks удалены; frozen inputs и receipts сохранены локально.
