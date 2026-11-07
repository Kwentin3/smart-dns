# Автопродление: проверенный кандидат для VK WorkSpace

Статус: source/lab READY; production НЕ РАЗВЁРНУТ. Это следующий срез существующего
[GOAL](../../product-goal.md), а не подтверждение завершения продукта.

Владелец подтвердил DNS-панель VK WorkSpace / biz.mail.ru. Официальная
[API-документация](https://workspace.vk.ru/docs/saas/api) описывает OAuth и операции
с доменами/пользователями, но не определяет ENS TXT read/create/delete.
[DNS-хостинг](https://workspace.vk.ru/docs/saas/ru/get-started/additional/dns-hosting)
описывает создание записей в панели. Поддерживаемый API для автоматизации здесь
не подтверждён; это не доказательство его отсутствия. VK Cloud DNS — другой сервис.

Выбран source-only кандидат: собственный ограниченный
[acme-dns](https://github.com/acme-dns/acme-dns/tree/v2.0.2) и его готовый
[native client](https://github.com/acme-dns/acme-dns-client/tree/v0.3).
[CNAME/NS delegation поддерживается Let's Encrypt](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge).
Публичная тестовая служба auth.acme-dns.io не используется. Перенос всей зоны,
новый сторонний аккаунт и изменение shared Traefik не требуются.

## Владельцы и границы

- Certbot 1.12.0 остаётся владельцем ACME account, lineage, issuance и renewal.
  Существующий certbot.timer активен; второй scheduler не создаётся.
- acme-dns владеет исключительно authoritative challenge namespace и своей
  SQLite state. Native API обновляет TXT. Публичны только DNS UDP/TCP 53;
  API слушает 127.0.0.1:15380, регистрация в штатном режиме выключена.
- Native acme-dns-client — Certbot authenticator. Хранит отдельные credentials
  в `/etc/acmedns/clientstorage.json` (0600, каталог 0700); ClientID не нужны.
- Проверенный `certificate_deploy.py` публикует Certbot lineage в существующий
  TLS-каталог AGH и проверяет выдаваемый fingerprint. AGH применяет пару без restart.
- Клиенты, admin и пользовательская DNS policy остаются в существующих owners.

Нового прикладного кода нет: [TOML](../../../config/acme-dns.example.cfg),
[systemd unit](../../../config/smart-dns-acme.service.in) и
[binary lock](../../../config/acme-dns-binaries.lock.json). Linux amd64 binaries
статически слинкованы, архивы и исполняемые файлы проверены по SHA256; на production
ничего не собирается. Для systemd 247 исключены более новые SocketBindAllow/Deny.

## Конкретное внедрение после разрешения

1. Сохранить текущую renewal config, пару TLS, состояния и identity защищаемых
   сервисов. Не копировать account keys и production data на полигон.
2. Установить pinned binaries в `/usr/local/lib/smart-dns-acme/` (root-owned 0755),
   config в `/etc/smart-dns/` (0755/0644, credentials в ней нет), render unit.
   `DynamicUser` и `StateDirectory` создают приватную native state; лимиты сервера:
   64 MiB, CPU 10%, 32 tasks. На текущем VPS проверены amd64, назначенный публичный
   IPv4, свободные UDP/TCP 53 и loopback TCP 15380. Host INPUT policy ACCEPT;
   внешняя доступность 53 ещё НЕ ПРОВЕРЕНА.
3. Включить регистрацию только на время локального bootstrap. Выполнить без verbose:
   `acme-dns-client register -d BASE -s http://127.0.0.1:15380 -allow 127.0.0.1/32`.
   CNAME/CAA wizard отклонить; прочитать фактически созданный private account,
   проверить file modes. Exit 0 сам по себе не доказывает успешную регистрацию.
   Выключить регистрацию, restart только новой ACME-службы; убедиться в отказе
   `/register` и работоспособности `/update`.
4. Проверить DNS снаружи по UDP и TCP до запроса изменения зоны. Затем выдать
   владельцу три точные записи. Для generic `BASE=dns.example.net`:

   | Тип | Имя в зоне example.net | Значение |
   | --- | --- | --- |
   | A | `ns-acme` | публичный IPv4 VPS |
   | NS | `acme-auth` | `ns-acme.example.net.` |
   | CNAME | `_acme-challenge.dns` | `UUID.acme-auth.example.net.` из native registration |

   NS hostname расположен вне делегированной child zone, отдельный glue не нужен.
   Старые TXT у `_acme-challenge.dns` удалить перед CNAME: они не могут сосуществовать
   с alias. Обнаружены три прежние challenge TXT; остальные DNS-записи не меняются.
5. Дождаться authoritative delegation/CNAME readback. Выполнить Certbot staging
   dry-run с native `--manual-auth-hook /usr/local/lib/smart-dns-acme/acme-dns-client`,
   exact base и wildcard. Проверить оба TXT и успешную ACME validation.
6. Один штатный вызов сохраняет authenticator config в прежнюю lineage. Параметры
   SMART_DNS_* должны быть явно заданы по private deployment и фактическим SAN;
   перед вызовом сверить существующий base/wildcard и сохранить именно этот набор:

   ```sh
   certbot certonly --non-interactive --cert-name "$SMART_DNS_CERT_NAME" \
     --manual --preferred-challenges dns \
     --manual-auth-hook "$SMART_DNS_ACME_CLIENT" --force-renewal \
     -d "$SMART_DNS_CERT_BASE" -d "*.$SMART_DNS_CERT_BASE"
   ```

   Текущая lineage содержит одну версию; многократный force-renewal не требуется.
7. Проверить renewal config и `certbot renew --cert-name CERT_NAME --dry-run` уже
   без CLI override authenticator. Deploy hook должен проверить новую пару;
   внешний DoT handshake/fingerprint, admission и защищаемые сервисы сохраняются.
   Тогда пункт автоматического renewal можно принять. Пока он НЕ ПРИНЯТ.

Откат: вернуть только свою renewal config и TLS через проверенный deploy owner,
остановить/отключить новую ACME-службу, сохранить её private state и client account.
Общий certbot.timer и чужие сертификаты не отключать. Native state и credentials
сохранить согласованно после остановки только ACME-службы; отдельная backup-платформа
не требуется. Владелец может снять три делегирующие записи, если кандидат отменён.

## Evidence и ограничения

Изолированный Linux fixture использовал ровно pinned binaries, отдельную SQLite
state и synthetic domain/account. Containers служили только Linux runtime:
никаких production keys, Docker socket, shared networks или global Traefik labels.
Runtime limits сервера 64 MiB/10%/32 tasks; native RSS около 2.8 MiB. Пройдено:

- native registration и сохранение credentials 0600/0700;
- два разных Certbot-compatible auth hook вызова, одновременно видимые TXT по
  UDP и TCP, authoritative NS и отсутствие recursive answers;
- закрытый `/register`, рабочий `/update` и сохранение state после restart;
- nonzero при неверном ключе, отсутствие credentials/canary в проверенных логах;
- cleanup containers/networks и сохранение ID/StartedAt чужих контейнеров.

Первый прогон выявил реальную ошибку: advertised `loglevel=warning` не принимается
v2.0.2; выбран `error`, повтор пройден. Вторая ошибка была в fixture IP allocation
при recreate; fixture теперь использует native restart с прежним адресом.
Private receipts: `.local/cert-renewal/evidence/`, frozen archive и binary hashes
сохранены локально. Публичная делегация, actual systemd service и staging CA пока
не проверены: они требуют production-внедрения и DNS-записей владельца.

## Почему требуется конкретное согласование

Кандидат добавляет отдельную authoritative службу и публичный UDP/TCP 53.
Прежнее согласование действующего deployment не включало это расширение.
Конфигурация и lab evidence готовы к ревью; до разрешения новая служба на VPS
не запускается. Прежний сертификат и работающий Smart DNS сохраняются.
