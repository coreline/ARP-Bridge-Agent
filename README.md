# ARP Bridge Agent

ABAP-мост между локальным Eclipse ADT и SAP-системой, до которой есть доступ только из браузера.

## Зачем нужен

Частая ситуация: рабочая SAP-система видна лишь из браузера внутри RDP/Citrix. Ставить стороннее ПО нельзя, а в Eclipse ADT нужен обычный HTTPS-эндпоинт до SAP.

Решение: пакет разворачивает в SAP ICF-сервис `/sap/bc/zarp`, который отдаёт страницу с агентом. Открытая в браузере RDP/Citrix страница держит соединение с Relay-сервером и выполняет запросы к `/sap/bc/adt/...` **на том же origin** — то есть под существующей SAP-сессией пользователя.

## Как это работает

```text
Eclipse ADT (локальный ПК)
      │ HTTPS  https://<arp-id>.<relay-server>/sap/bc/adt/...
      ▼
Central Relay
      ▲
      │ WSS  wss://<relay-server>/agent   ← исходящее соединение
      │
ARP Bridge Agent: страница /sap/bc/zarp
      │ fetch() same-origin, под SAP-сессией браузера
      ▼
SAP ICM / ADT API   /sap/bc/adt/...
```

## Требования

- SAP NetWeaver 7.40 и выше, либо любой S/4HANA.
- [abapGit](https://github.com/abapGit/abapGit) для установки.

## Установка

1. **abapGit → New repository:** URL этого репозитория, целевой пакет (например `ZARP`).
   `.abapgit.xml` в корне, подкаталог указывать не нужно.
2. **Домен релея:** константа `gc_relay_host` в `src/zcl_arp_agent.clas.abap`,
   значение должно совпадать с доменом Central Relay.
3. **SICF:** активировать `/default_host/sap/bc/zarp`, на вкладке **Logon** оставить
   требование SAP logon.
4. **Проверка:** `SA38` → `ZARP_AGENT` → «Service ZARP found…».

## Использование

1. Войти в SAP-порт в браузере на RDP/Citrix.
2. Выполнить `ZARP_AGENT` — URL собирается из профильных параметров (`icm/server_port_N`, `icm/HTTP/port`, `SAPLOCALHOSTFULL`) и страница открывается сама.
3. На странице скопировать значение из строки **URL** (кнопка ⧉).
4. Создать в Eclipse ADT ABAP Project с этим URL.
5. Держать вкладку агента открытой: закрытие обрывает WSS, и релей перестаёт проксировать.

Страница агента показывает статус SAP и релея, готовый URL, подключённых Eclipse-клиентов (IP, обратное DNS-имя, User-Agent, последняя активность), счётчики и журнал последних 20 запросов. Тела запросов и ответов нигде не сохраняются — только метаданные.
