# VPN Guard

Системная утилита для **macOS и Windows 11**. Она разрешает работу заданного стороннего приложения (`Target`) только тогда, когда внешний IP компьютера относится к разрешённой стране. Иначе приложение принудительно завершается.

VPN Guard не VPN-клиент: он не подключает VPN и не управляет им. Он проверяет фактический внешний IP и следит за процессами приложения.

**Главный принцип — fail closed.** Если разрешённая сеть не подтверждена, работа приложения запрещена. Единственное разрешающее состояние — `ALLOWED`. Все остальные (`INITIALIZING`, `CHECKING`, `BLOCKED`, `UNKNOWN`) означают завершение приложения.

## Как это работает

```text
                ┌──────────────── Guard (FSM) ────────────────┐
 Network monitor│  network change / wake → CHECKING (сразу)   │
 (события ОС +  │  GeoIP check (single-flight, debounce)      │
  опрос 1 с)  ──┤  → ALLOWED / BLOCKED / UNKNOWN              │
 Power events ──┤  периодическая проверка каждые 30 с         │
                └───────────────┬─────────────────────────────┘
                                │ Allowed()?
 Process monitor (каждые 500 мс + сразу при смене состояния)
   нашёл процесс приложения и state != ALLOWED → завершить
```

### Проверка сети
- Внешний IP и страна определяются по HTTPS. Основной сервис — [IPinfo Lite](https://ipinfo.io/developers/lite-api): бесплатный, без лимита запросов, нужен токен. Запасной — Cloudflare `https://1.1.1.1/cdn-cgi/trace`: работает без токена и без DNS.
- Политика `first_success`: используется первый успешный ответ. Политика `all_agree`: должны ответить все сервисы, и их ответы должны совпасть.
- IPv4 и IPv6 проверяются отдельно, каждое соединение принудительно идёт по своему семейству адресов. Если у машины есть глобальный IPv6-адрес, страна должна быть разрешённой **и по IPv4, и по IPv6**. Иначе приложение могло бы уходить в сеть по IPv6 мимо VPN. Если IPv6-маршрута нет совсем (ENETUNREACH, обычная ситуация, когда VPN блокирует IPv6), IPv6 считается неопасным.
- Любая ошибка даёт `UNKNOWN`, то есть блокировку: timeout, DNS, TLS, HTTP 429/5xx, невалидный JSON, неизвестная страна (`XX`, `T1`, …), редирект, слишком большой ответ.
- Каждая проверка открывает новое соединение без keep-alive и без системного прокси. Так измеряется egress по текущему маршруту.

### Изменения сети
- macOS: события routing socket (`PF_ROUTE`). Windows: `NotifyRouteChange2`, `NotifyUnicastIpAddressChange`, `NotifyIpInterfaceChange`. Дополнительно раз в секунду опрос.
- По событию пересчитывается «отпечаток» сети:
  - маршруты по умолчанию и split-default маршруты VPN (`0/1`, `128/1`);
  - статические host-маршруты до VPN-сервера, по ним видна смена страны VPN;
  - IPv4-адреса интерфейсов и наличие глобального IPv6.
- Если отпечаток изменился, состояние **мгновенно** становится `CHECKING` и приложение запрещено. Шум (ARP, ротация временных IPv6-адресов) отпечаток не меняет и приложение не убивает.
- Пачка событий (Wi-Fi + route + utun) порождает один HTTP-запрос (debounce 300 мс, single-flight). Результат проверки, начатой **до** очередного изменения сети, отбрасывается: устаревший `ALLOWED` применён быть не может.
- Sleep/wake: на macOS через IOKit (`IORegisterForSystemPower`), на Windows через `SERVICE_CONTROL_POWEREVENT`. Запасной детектор — разрыв часов больше 5 с. После выхода из сна старый `ALLOWED` недействителен.
- Периодическая проверка (30 с) не снимает `ALLOWED` на время запроса, но её результат может перевести состояние в `BLOCKED` или `UNKNOWN`. После `UNKNOWN` повтор идёт через 5 с.

### Идентификация приложения
Имя процесса само по себе ничего не решает. `/Applications/AnotherApp.app/Contents/MacOS/Target` не считается контролируемым приложением.

| | macOS | Windows |
|---|---|---|
| 1 | исполняемый файл внутри заданного бандла (основной процесс, helpers, XPC) | исполняемый файл внутри каталога установки (`C:\Program Files\Target\…`) |
| 2 | любой `.app` с тем же `CFBundleIdentifier` (скопированный бандл) | тот же `OriginalFilename` (VERSIONINFO) **и** валидная подпись Authenticode того же издателя (скопированный exe) |
| 3 | подпись с тем же Team ID и signing identifier | — |

Дополнительно завершаются все **потомки** найденных процессов. Защита от переиспользования PID: потомок должен стартовать позже родителя.

Bundle ID, Team ID и издатель проверяются при старте. Если `team_id` или `publisher` заданы в конфиге и не совпадают с реальными, демон переходит в fail-closed.

### Завершение
- macOS: `SIGTERM`, затем через `terminate_timeout_ms` (2 с) `SIGKILL`.
- Windows: сразу `TerminateProcess` для всего дерева процессов. Служба работает в session 0 и не может отправить `WM_CLOSE` окнам пользователя, поэтому мягкого шага нет.
- Перед отправкой сигнала каждый раз сверяются PID и время старта процесса, чтобы не задеть чужой процесс с тем же PID.

### Ошибка конфигурации
Демон **не завершается** при ошибке конфигурации, он переходит в fail-closed (`BLOCKED`, `config_error` в `status`). Приложение при этом продолжает блокироваться. Если файл не читается совсем, используется последняя валидная секция `application`: демон хранит её в `.last-known-application.json` рядом с конфигом.

Изменения конфига подхватываются на лету (опрос раз в 5 с). Перечитывание начинается с нового `CHECKING`, поэтому запущенное приложение при этом будет завершено.

## Конфигурация

macOS: `/etc/vpn-guard/config.json` (`root:wheel`, `600`).
Windows: `%ProgramData%\VPNGuard\config.json` (доступ только у SYSTEM и Administrators).

Один файл подходит для обеих платформ, каждая ОС читает свою секцию `application`. Полный пример лежит в [config.example.json](config.example.json).

| Поле | По умолчанию | Описание |
|---|---|---|
| `application.darwin.path` | — | путь к `.app` |
| `application.darwin.bundle_id` | — | обязательный, сверяется с `Info.plist` |
| `application.darwin.team_id` | из подписи | если задан, должен совпасть с подписью бандла |
| `application.windows.path` | — | путь к `.exe` |
| `application.windows.publisher` | из подписи | имя подписанта Authenticode; если задано, должно совпасть |
| `allowed_countries` | — | ISO 3166-1 alpha-2, непустой список |
| `process_check_interval_ms` | 500 | интервал проверки процессов |
| `network_check_interval_seconds` | 30 | периодическая перепроверка IP |
| `unknown_retry_seconds` | 5 | повтор после `UNKNOWN` |
| `network_timeout_ms` | 3000 | таймаут одного HTTP-запроса |
| `network_debounce_ms` | 300 | склейка пачки сетевых событий |
| `terminate_timeout_ms` | 2000 | задержка перед SIGKILL |
| `geoip.policy` | `first_success` | `first_success` \| `all_agree` |
| `geoip.ipv6` | `auto` | `auto` \| `required` \| `disabled` |
| `geoip.providers[]` | cloudflare | `{type: ipinfo_lite, token}` \| `{type: cloudflare_trace}`; `url`/`url_v6` переопределяют адреса (только https) |
| `logging.level` | `info` | `debug` \| `info` \| `warn` \| `error` |

Неизвестные поля считаются ошибкой: опечатка не должна молча отключить проверку. Токен IPinfo передаётся в заголовке `Authorization` и в логи не попадает.

## Сборка

Нужен Go 1.25+. Бинарник для macOS собирается только на Mac (используется cgo: IOKit, Security, libproc). Windows кросс-компилируется с любой ОС.

```bash
make test
```
```bash
make vet
```
```bash
make darwin
```
```bash
make windows
```
```bash
make dist
```

- `make vet` проверяет код для обеих ОС;
- `make darwin` собирает universal-бинарник `bin/darwin/vpn-guard` (arm64 + x86_64);
- `make windows` собирает `bin/windows-{amd64,arm64}/vpn-guard.exe`;
- `make dist` складывает zip-архивы для установки в `dist/`.

## Установка

### macOS
```bash
sudo scripts/darwin/install.sh --config /path/to/config.json
```
Скрипт:
1. проверяет, что это macOS и что запущен от root;
2. ставит `/usr/local/bin/vpn-guard`, `/etc/vpn-guard/config.json` и `/Library/LaunchDaemons/com.vpnguard.daemon.plist` с правами `root:wheel`;
3. регистрирует демон через `launchctl bootstrap` и запускает его;
4. проверяет, что демон работает.

Существующий конфиг не перезаписывается без `--force-config`.

LaunchDaemon: `RunAtLoad` + `KeepAlive`, `ThrottleInterval 2`. Работает от root, стартует при загрузке, без входа пользователя.

Удаление:
```bash
sudo scripts/darwin/uninstall.sh
```
Флаг `--purge` дополнительно удаляет конфиг и логи.

### Windows 11
PowerShell от администратора:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -Config C:\path\config.json
```
Служба `VPNGuard` запускается автоматически и работает под LocalSystem. Recovery actions: перезапуск через 1 с / 1 с / 5 с, в том числе при ненулевом коде выхода. Бинарник ставится в `%ProgramFiles%\VPNGuard`, конфиг и логи лежат в `%ProgramData%\VPNGuard`. Остановить службу может только администратор.

Удаление: `scripts\windows\uninstall.ps1`, флаг `-Purge` удаляет конфиг и логи.

## Диагностика

```bash
vpn-guard status
```
```bash
vpn-guard check
```
```bash
vpn-guard validate
```
```bash
vpn-guard version
```

- `vpn-guard status` показывает состояние демона (`--json` для машинного вывода);
- `vpn-guard check` запускает принудительную проверку через демон, `-local` проверяет без демона (нужен доступ к конфигу);
- `vpn-guard validate` проверяет конфиг и идентичность приложения.

Пример вывода `vpn-guard status`:

```text
VPN Guard 1.0.0

Application:   /Applications/Target.app
Bundle ID:     com.vendor.target

State:         ALLOWED
External IP:   203.0.113.15
Country:       TH
Required:      TH
Last check:    2026-10-07 21:15:34
Target PID:    12345
```

Логи:
- macOS: `/var/log/vpn-guard.log` (ротация по 10 МБ) и `/var/log/vpn-guard-error.log`;
- Windows: `%ProgramData%\VPNGuard\logs\`.

Для разработки демон можно запустить без root: `vpn-guard run -console -config ./config.json`, адрес сокета статуса задаётся переменной `VPN_GUARD_IPC_ADDR`.

## Структура

```text
cmd/vpn-guard/        CLI и точка входа демона
internal/config/      загрузка/валидация конфига (+ секции по ОС)
internal/guard/       конечный автомат состояний
internal/network/     GeoIP-провайдеры, checker, монитор сети (_darwin/_windows)
internal/process/     поиск, идентификация и завершение процессов (_darwin/_windows)
internal/service/     launchd / Windows SCM, события sleep/wake
internal/daemon/      связывает компоненты, fail-closed режим
internal/ipc/         канал статуса демон ↔ CLI (unix socket / loopback TCP)
internal/logging/     логгер key=value с ротацией
deploy/darwin/        LaunchDaemon plist
scripts/darwin|windows/  установка и удаление
```

## Ограничения V1

- **Это не сетевой kill switch.** Между отключением VPN и завершением приложения есть окно: до ~1 с по событию сети и до 30 с, если смена сервера VPN никак не отразилась на маршрутах и адресах. В это окно приложение может отправить трафик мимо VPN. Гарантию даст только V2 (Network Extension / WFP).
- Запуск приложения не запрещается, оно завершается после обнаружения (≤ 1 с при интервале 500 мс).
- Проверяется маршрут **демона**. Если VPN туннелирует только отдельные приложения (per-app / split tunnel) или работает как системный прокси, маршрут Target может отличаться.
- Пользователь с правами root или администратора может отключить демон.
- Любое значимое изменение сети, выход из сна и перечитывание конфига переводят состояние в `CHECKING`. По ТЗ это означает завершение запущенного приложения, даже если после проверки сеть окажется разрешённой.
- Подделанная копия приложения (с изменённым bundle ID или битой подписью) за пределами каталога установки не распознаётся.

## Соответствие критериям приёмки (§40)

| Тест | Чем обеспечено |
|---|---|
| 1. VPN TH → работает | `ALLOWED` после проверки |
| 2/3. VPN OFF или DE → завершение ≤ 1 с | скан раз в 500 мс, `BLOCKED` |
| 4/5. VPN отключился или сменил страну | событие сети → `CHECKING` → завершение → новая проверка |
| 6. Wi-Fi отключился | смена отпечатка / `UNKNOWN` |
| 7. GeoIP недоступен | `UNKNOWN` (= блокировка), повтор через 5 с |
| 8. Перезагрузка без VPN | LaunchDaemon / служба Automatic, старт в `CHECKING` |
| 9. Sleep/wake | IOKit / SCM power events + детектор разрыва часов |
| 10. Сбой демона | `KeepAlive` / SCM recovery actions |
