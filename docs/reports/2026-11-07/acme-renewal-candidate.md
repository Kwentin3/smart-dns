# Автопродление: native DNS-01 для VK WorkSpace

Статус: автопродление принято в рамках этого среза. Native authoritative служба
развёрнута с отдельным разрешением владельца; после DNS delegation пройдены
staging, production issuance и renewal без auth overrides. Сертификат до
2027-02-05 выдаётся AGH без restart. Полный [GOAL](../../product-goal.md) остаётся
открыт до отложенной пользовательской приёмки устройств и функций приложений.

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
     --server "$SMART_DNS_CA_DIRECTORY" --account "$SMART_DNS_CA_ACCOUNT" \
     --deploy-hook "$SMART_DNS_DEPLOY_HOOK" \
     -d "$SMART_DNS_CERT_BASE" -d "*.$SMART_DNS_CERT_BASE"
   ```

   Текущая lineage содержит одну версию; многократный force-renewal не требуется.
7. Проверить renewal config и `certbot renew --cert-name CERT_NAME --dry-run
   --non-interactive --no-random-sleep-on-renew` уже без CLI override authenticator.
   Последний флаг убирает только native jitter из ограниченной проверки.
   Deploy hook должен проверить новую пару;
   внешний DoT handshake/fingerprint, admission и защищаемые сервисы сохраняются.
   Тогда пункт автоматического renewal можно принять. Эти проверки выполнены ниже.

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
Private lab receipts: `.local/cert-renewal/evidence/`, frozen archive и binary
hashes сохранены локально. Production-проверки приведены ниже.

## Почему требуется конкретное согласование

Кандидат добавляет отдельную authoritative службу и публичный UDP/TCP 53.
Прежнее согласование действующего deployment не включало это расширение.
После source/lab review владелец отдельно разрешил конкретное внедрение.

## Production deployment

Установлен источник `40795ba321e029a1c01ee5d1c9f5a3e21ebbc267`: native binaries
сверены с lock, приватный config получен из проверенного шаблона. Фактический
systemd 247 принял unit, служба active/enabled, DynamicUser/NoNewPrivileges=yes,
MemoryMax=64 MiB, CPUQuota=10%, TasksMax=32. MemoryCurrent около 2.4 MiB.
DNS слушает только назначенный public IPv4:53 UDP/TCP, API — 127.0.0.1:15380.

Native registration завершена, credentials 0600/0700, затем registration закрыта
с проверкой отказа. Согласованная cold backup native state/client account и
прежней renewal config/TLS находится только на VPS. Два native auth hook update
успешны. Внешний probe: шесть PASS по UDP/TCP — NS, оба TXT, отсутствие рекурсии.
Публичное подключение к API отвергнуто; bind дополнительно подтверждён на хосте.

Все Docker ID/StartedAt сохранены; действующая service policy — `matches`.
Shared Traefik, AGH, relay и renewal config не менялись, issuance не запускался.
Владельцу выданы точные A/NS/CNAME для однократной настройки в VK WorkSpace.
Private safe receipts: `.local/cert-renewal/production/`; credentials/backup keys
с VPS в эти локальные receipts не копировались.

Первая установка остановилась до запуска: строгий umask создал новые каталоги
0700; ошибка была в private installer, не в reviewed unit. Task-owned prestart
файлы сверены и удалены, для новых публично читаемых binary/config каталогов
явно выставлены 0755, повторный запуск успешен. Прежний runtime не затронут.

SAN действующей lineage и поддержка точных CLI flags сверены с установленным
Certbot 1.12.0. Его фактический hooks.py прекращает deploy hook при dry-run;
staging-сертификат не публикуется в AGH.

## Принятое автопродление

Владелец добавил три DNS-записи. CNAME подтверждён на обоих authoritative NS,
recursive Cloudflare получил оба TXT из делегированного namespace. Google сначала
отдавал cached NODATA; вызов CA начат после положительного authoritative/recursive
readback, а не по одному сообщению владельца.

1. Certbot staging certonly: exit0, два DNS-01 auth hook и успешная CA validation.
   Renewal config, обе действующие TLS пары, admission/admin и контейнеры неизменны.
2. Production certonly для прежней lineage/account: exit0, новый сертификат
   до 2027-02-05. Native config сохранила `manual_auth_hook` и `renew_hook`, server
   и account прежние. Указан explicit deploy hook с тем же абсолютным путём, что
   у directory hook; Certbot 1.12 дедуплицирует его. Соседние renewal configs сохранены.
3. AGH chain/key байт-в-байт равны новой lineage, UID/GID/mode прежние. Выдаваемый
   проверенной TLS-сессией leaf fingerprint совпал с issued. AGH/relay/shared edge
   и остальные контейнеры сохранили ID/StartedAt; native admission/profile неизменны.
4. Адресный `certbot renew --cert-name … --dry-run --non-interactive
   --no-random-sleep-on-renew` без auth/deploy overrides: exit0, два auth hook взяты
   из сохранённой конфигурации, оба DNS challenges прошли. Fake certificate не
   публиковался: renewal config и все TLS bytes до/после равны.
5. Снаружи после renewal: шесть DoH/DoT проверок PASS — выбранный A перенаправлен,
   обычный сайт имеет положительный direct DNS-ответ, неизвестный ClientID REFUSED.
   Во всех трёх DoT-соединениях system-CA verified leaf совпал с новым issued.

Native существующий certbot.timer active/enabled, команда обслуживает все lineages;
второй scheduler не создавался. У общей certbot.service остаётся прежний failed
result из-за Nginx renewal другой lineage. В Certbot 1.12 ошибка одной lineage
[перехватывается внутри цикла](https://github.com/certbot/certbot/blob/v1.12.0/certbot/certbot/_internal/renewal.py#L406-L469),
а общий failure поднимается после обработки остальных. Адресный renewal нашей
lineage прошёл; чужие Nginx/shared Traefik и certificate settings не изменялись.
Ремонт старой чужой lineage находится вне этого среза.

Private evidence: `production/staging-result.json`, `issuance-result.json`,
`renewal-check-result.json`, `scheduler-proof.json`, `external-tls-dns.json`
под `.local/cert-renewal/`. Полные private keys и backup credentials остаются
только на VPS. Логи этих трёх native вызовов проверены на отсутствие секретов.
Пользовательские phone/network/message/file сценарии этим этапом не подтверждены.
