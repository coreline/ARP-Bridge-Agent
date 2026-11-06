CLASS zcl_arp_agent DEFINITION
  PUBLIC
  FINAL
  CREATE PUBLIC.

  PUBLIC SECTION.
    INTERFACES if_http_extension.

  PRIVATE SECTION.
    CONSTANTS gc_relay_host TYPE string VALUE 'arp.abap4.ru'.
    CLASS-DATA mv_html TYPE string.
ENDCLASS.



CLASS ZCL_ARP_AGENT IMPLEMENTATION.


  METHOD if_http_extension~handle_request.
    DATA: lv_action TYPE string,
          lv_json   TYPE string,
          lv_arp_id   TYPE string,
          lv_identity TYPE string,
          lv_hash     TYPE string,
          lv_html     TYPE string.

    lv_action = server->request->get_form_field( name = 'action' ).

    IF lv_action = 'health'.
      lv_json = '{"status":"ok","agent":"ARP"}'.
      server->response->set_status( code = 200 reason = 'OK' ).
      server->response->set_content_type(
        content_type = 'application/json; charset=utf-8' ).
      server->response->set_cdata( data = lv_json ).
      RETURN.
    ENDIF.

    " Если ARP-ID не передан, вычисляем стабильный идентификатор
    " из SAP application server host, SID, клиента и пользователя.
    lv_arp_id = server->request->get_form_field( name = 'arpId' ).

    IF lv_arp_id IS INITIAL.
      lv_identity = |{ sy-host }-{ sy-sysid }-{ sy-mandt }-{ sy-uname }|.

      TRY.
          cl_abap_message_digest=>calculate_hash_for_char(
            EXPORTING
              if_algorithm = 'SHA256'
              if_data      = lv_identity
            IMPORTING
              ef_hashstring = lv_hash ).
        CATCH cx_abap_message_digest.
          server->response->set_status(
            code = 500 reason = 'ARP-ID generation failed' ).
          server->response->set_content_type(
            content_type = 'text/plain; charset=utf-8' ).
          server->response->set_cdata(
            data = 'Unable to calculate SHA-256 hash for ARP-ID' ).
          RETURN.
      ENDTRY.

      " Первые 16 байт SHA-256 в hex = 32 символа ARP-ID.
      lv_arp_id = lv_hash(32).
    ELSE.
      " Явно переданный ARP-ID проверяем, не подменяя его.
      TRANSLATE lv_arp_id TO LOWER CASE.

      IF strlen( lv_arp_id ) <> 32
         OR lv_arp_id CN '0123456789abcdef'.
        server->response->set_status(
          code = 400 reason = 'Invalid ARP-ID' ).
        server->response->set_content_type(
          content_type = 'text/plain; charset=utf-8' ).
        server->response->set_cdata(
          data = 'ARP-ID must contain exactly 32 hexadecimal characters' ).
        RETURN.
      ENDIF.
    ENDIF.

    TRANSLATE lv_arp_id TO LOWER CASE.

    " HTML и JavaScript хранятся в классе и инициализируются один раз
    " в рамках текущего ABAP internal session.
    " Формируем шаблон при каждом запросе, чтобы после активации
    " класса не использовать старый шаблон из class-data.
    mv_html =
         '<!doctype html>'
        && cl_abap_char_utilities=>newline
        && '<html lang="ru">'
        && cl_abap_char_utilities=>newline
        && '<head>'
        && cl_abap_char_utilities=>newline
        && '  <meta charset="utf-8">'
        && cl_abap_char_utilities=>newline
        && '  <meta name="viewport" content="width=device-width, initial-scale=1">'
        && cl_abap_char_utilities=>newline
        && '  <title>ARP Bridge Agent</title>'
        && cl_abap_char_utilities=>newline
        && '  <style>'
        && cl_abap_char_utilities=>newline
        && '    :root { color-scheme: light; font-family: Arial, sans-serif; }'
        && cl_abap_char_utilities=>newline
        && '    body { margin: 24px; color: #20242a; background: #f5f7fa; }'
        && cl_abap_char_utilities=>newline
        && '    h1 { margin: 0 0 18px; font-size: 24px; }'
        && cl_abap_char_utilities=>newline
        && '    .panel { background: white; border: 1px solid #dce2e9; border-radius: 10px; padding: 16px; margi'
        && 'n: 12px 0; }'
        && cl_abap_char_utilities=>newline
        && '    .line { margin: 9px 0; }'
        && cl_abap_char_utilities=>newline
        && '    .label { display: inline-block; min-width: 125px; color: #596574; }'
        && cl_abap_char_utilities=>newline
        && '    code { overflow-wrap: anywhere; }'
        && cl_abap_char_utilities=>newline
        && '    .ok { color: #137333; font-weight: 700; }'
        && cl_abap_char_utilities=>newline
        && '    .bad { color: #b3261e; font-weight: 700; }'
        && cl_abap_char_utilities=>newline
        && '    .muted { color: #697586; }'
        && cl_abap_char_utilities=>newline
        && '    .stats { display: flex; flex-wrap: wrap; gap: 22px; }'
        && cl_abap_char_utilities=>newline
        && '    .stat strong { display: block; font-size: 22px; margin-top: 4px; }'
        && cl_abap_char_utilities=>newline
        && '    table { width: 100%; border-collapse: collapse; font-size: 13px; }'
        && cl_abap_char_utilities=>newline
        && '    th, td { text-align: left; padding: 9px 7px; border-bottom: 1px solid #e7ebf0; vertical-align: t'
        && 'op; }'
        && cl_abap_char_utilities=>newline
        && '    th { color: #596574; }'
        && cl_abap_char_utilities=>newline
        && '    td.path { max-width: 560px; overflow-wrap: anywhere; }'
        && cl_abap_char_utilities=>newline
        && '    .table-wrap { overflow-x: auto; }'
        && cl_abap_char_utilities=>newline
        && '  </style>'
        && cl_abap_char_utilities=>newline
        && '</head>'
        && cl_abap_char_utilities=>newline
        && '<body>'
        && cl_abap_char_utilities=>newline
        && '  <h1>ARP Bridge Agent</h1>'
        && cl_abap_char_utilities=>newline
        && '  <section class="panel">'
        && cl_abap_char_utilities=>newline
        && '    <div class="line"><span class="label">SAP:</span><span id="sap" class="muted">Проверка...</span>'
        && '</div>'
        && cl_abap_char_utilities=>newline
        && '    <div class="line"><span class="label">Relay:</span><span id="relay" class="muted">Подключение...'
        && '</span></div>'
        && cl_abap_char_utilities=>newline
        && '    <div class="line"><span class="label">URL:</span><code id="arpUrl">__ARP_ID__.__RELAY_HOST__</code>'
        && '<button id="copyUrl" type="button" title="Копировать URL" aria-label="Копировать URL" style="margin-left:8px;border:0;background:transparent;cursor:pointer;font-size:16px;padding:2px 6px">⧉</button>'
        && '<span id="copyStatus" class="muted" style="margin-left:6px;font-size:12px"></span></div>'
        && cl_abap_char_utilities=>newline
        && '  </section>'
        && cl_abap_char_utilities=>newline
        && '  <section class="panel">'
        && cl_abap_char_utilities=>newline
        && '    <h2 style="font-size:17px;margin-top:0">Подключённые Eclipse ADT клиенты</h2>'
        && cl_abap_char_utilities=>newline
        && '    <div id="clientNotice" class="muted" style="margin-bottom:10px">Ожидание информации о клиентах...</div>'
        && cl_abap_char_utilities=>newline
        && '    <div class="table-wrap">'
        && cl_abap_char_utilities=>newline
        && '      <table>'
        && cl_abap_char_utilities=>newline
        && '        <thead><tr><th>Статус</th><th>IP</th><th>Клиент</th><th>Последняя активность</th></tr></thead>'
        && cl_abap_char_utilities=>newline
        && '        <tbody id="clientRows"><tr><td colspan="4" class="muted">Клиентов пока нет</td></tr></tbody>'
        && cl_abap_char_utilities=>newline
        && '      </table>'
        && cl_abap_char_utilities=>newline
        && '    </div>'
        && cl_abap_char_utilities=>newline
        && '    <p class="muted" style="font-size:12px;margin-bottom:0">Все клиенты подключаются автоматически.</p>'
        && cl_abap_char_utilities=>newline
        && '  </section>'
        && cl_abap_char_utilities=>newline
        && '  <section class="panel">'
        && cl_abap_char_utilities=>newline
        && '    <div class="stats">'
        && cl_abap_char_utilities=>newline
        && '      <div class="stat"><span class="muted">HTTP-запросов</span><strong id="requestCount">0</strong>'
        && '</div>'
        && cl_abap_char_utilities=>newline
        && '      <div class="stat"><span class="muted">Успешных ответов (2xx/3xx)</span><strong id="successCoun'
        && 't">0</strong></div>'
        && cl_abap_char_utilities=>newline
        && '      <div class="stat"><span class="muted">Ошибок (4xx/5xx)</span><strong id="errorCount">0</strong'
        && '></div>'
        && cl_abap_char_utilities=>newline
        && '      <div class="stat"><span class="muted">Передано данных</span><strong id="bytesCount">0 B</stron'
        && 'g></div>'
        && cl_abap_char_utilities=>newline
        && '    </div>'
        && cl_abap_char_utilities=>newline
        && '  </section>'
        && cl_abap_char_utilities=>newline
        && '  <section class="panel">'
        && cl_abap_char_utilities=>newline
        && '    <h2 style="font-size:17px;margin-top:0">Последние HTTP-запросы</h2>'
        && cl_abap_char_utilities=>newline
        && '    <div class="table-wrap">'
        && cl_abap_char_utilities=>newline
        && '      <table>'
        && cl_abap_char_utilities=>newline
        && '        <thead><tr><th>Время</th><th>IP</th><th>Метод</th><th>URL</th><th>Ответ</th><th>Длительность</th><th>Размер</th></tr></thead>'
        && cl_abap_char_utilities=>newline
        && '        <tbody id="requestRows"><tr><td colspan="7" class="muted">Запросов пока не было</td></tr></tbody>'
        && cl_abap_char_utilities=>newline
        && '      </table>'
        && cl_abap_char_utilities=>newline
        && '    </div>'
        && cl_abap_char_utilities=>newline
        && '    <p class="muted" style="font-size:12px;margin-bottom:0">Отображаются только метаданные запросов '
        && 'и ответов. Содержимое запросов и ответов не записывается в журнал страницы.</p>'
        && cl_abap_char_utilities=>newline
        && '  </section>'
        && cl_abap_char_utilities=>newline
        && '<script>'
        && cl_abap_char_utilities=>newline
        && '(() => {'
        && cl_abap_char_utilities=>newline
        && '  "use strict";'
        && cl_abap_char_utilities=>newline
        && '  const ARP_ID = "__ARP_ID__";'
        && cl_abap_char_utilities=>newline
        && '  const RELAY_HOST = "__RELAY_HOST__";'
        && cl_abap_char_utilities=>newline
        && '  const RELAY_URL = `wss://${RELAY_HOST}/agent`;'
        && cl_abap_char_utilities=>newline
        && '  const HEARTBEAT_INTERVAL = 30000;'
        && cl_abap_char_utilities=>newline
        && '  const MAX_ROWS = 20;'
        && cl_abap_char_utilities=>newline
        && '  const rows = [];'
        && cl_abap_char_utilities=>newline
        && '  let requestCount = 0, successCount = 0, errorCount = 0, bytesCount = 0;'
        && cl_abap_char_utilities=>newline
        && '  let socket = null, heartbeatTimer = null, reconnectTimer = null;'
        && cl_abap_char_utilities=>newline
        && '  let reconnectDelay = 1000, stopped = false;'
        && cl_abap_char_utilities=>newline
        && cl_abap_char_utilities=>newline
        && '  const el = id => document.getElementById(id);'
        && cl_abap_char_utilities=>newline
        && '  const setStatus = (id, value, good) => {'
        && cl_abap_char_utilities=>newline
        && '    const node = el(id); node.textContent = value;'
        && cl_abap_char_utilities=>newline
        && '    node.className = good === true ? "ok" : good === false ? "bad" : "muted";'
        && cl_abap_char_utilities=>newline
        && '  };'
        && cl_abap_char_utilities=>newline
        && '  const formatBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n/1024).toFixed(1)} KB` : `${(n/1'
        && '048576).toFixed(2)} MB`;'
        && cl_abap_char_utilities=>newline
        && '  const escapeHtml = value => String(value).replace(/[&<>"'']/g, c => ({"&":"&amp;","<":"&lt;",">":"&'
        && 'gt;",''"'':"&quot;","''":"&#39;"}[c]));'
        && cl_abap_char_utilities=>newline
        && '  const fullArpUrl = `${ARP_ID}.${RELAY_HOST}`;'
        && cl_abap_char_utilities=>newline
        && '  el("arpUrl").textContent = fullArpUrl;'
        && cl_abap_char_utilities=>newline
        && '  el("copyUrl").addEventListener("click", async () => {'
        && cl_abap_char_utilities=>newline
        && '    try { await navigator.clipboard.writeText(`https://${fullArpUrl}`); el("copyStatus").textContent = "Скопировано"; }'
        && cl_abap_char_utilities=>newline
        && '    catch (error) { el("copyStatus").textContent = "Не удалось скопировать"; }'
        && cl_abap_char_utilities=>newline
        && '  });'
        && cl_abap_char_utilities=>newline
        && cl_abap_char_utilities=>newline
        && '  async function checkSap() {'
        && cl_abap_char_utilities=>newline
        && '    try {'
        && cl_abap_char_utilities=>newline
        && '      const response = await fetch(window.location.pathname + "?action=health", { credentials: "same'
        && '-origin", cache: "no-store" });'
        && cl_abap_char_utilities=>newline
        && '      if (!response.ok) throw new Error(`HTTP ${response.status}`);'
        && cl_abap_char_utilities=>newline
        && '      const data = await response.json();'
        && cl_abap_char_utilities=>newline
        && '      setStatus("sap", data.status === "ok" ? "OK" : "Ошибка", data.status === "ok");'
        && cl_abap_char_utilities=>newline
        && '    } catch (error) { setStatus("sap", `Ошибка: ${error.message}`, false); }'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  function base64ToBytes(base64) {'
        && cl_abap_char_utilities=>newline
        && '    if (!base64) return new Uint8Array(0);'
        && cl_abap_char_utilities=>newline
        && '    const binary = atob(base64), bytes = new Uint8Array(binary.length);'
        && cl_abap_char_utilities=>newline
        && '    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);'
        && cl_abap_char_utilities=>newline
        && '    return bytes;'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  function bytesToBase64(buffer) {'
        && cl_abap_char_utilities=>newline
        && '    const bytes = new Uint8Array(buffer), chunkSize = 0x8000; let binary = "";'
        && cl_abap_char_utilities=>newline
        && '    for (let i = 0; i < bytes.length; i += chunkSize) binary += String.fromCharCode(...bytes.subarra'
        && 'y(i, Math.min(i + chunkSize, bytes.length)));'
        && cl_abap_char_utilities=>newline
        && '    return btoa(binary);'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  function renderStats() {'
        && cl_abap_char_utilities=>newline
        && '    el("requestCount").textContent = requestCount;'
        && cl_abap_char_utilities=>newline
        && '    el("successCount").textContent = successCount;'
        && cl_abap_char_utilities=>newline
        && '    el("errorCount").textContent = errorCount;'
        && cl_abap_char_utilities=>newline
        && '    el("bytesCount").textContent = formatBytes(bytesCount);'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  function renderRows() {'
        && cl_abap_char_utilities=>newline
        && '    el("requestRows").innerHTML = rows.length ? rows.map(row => `<tr>'
        && cl_abap_char_utilities=>newline
        && '      <td>${escapeHtml(row.time)}</td><td>${escapeHtml(row.ip || "—")}</td><td>${escapeHtml(row.method)}</td>'
        && cl_abap_char_utilities=>newline
        && '      <td class="path">${escapeHtml(row.path)}</td>'
        && cl_abap_char_utilities=>newline
        && '      <td>${escapeHtml(row.status)}</td><td>${escapeHtml(row.duration)}</td><td>${escapeHtml(formatB'
        && 'ytes(row.bytes))}</td>'
        && cl_abap_char_utilities=>newline
        && '    </tr>`).join("") : ''<tr><td colspan="7" class="muted">Запросов пока не было</td></tr>'';'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  function addRequestRow(row) { rows.unshift(row); if (rows.length > MAX_ROWS) rows.pop(); renderRow'
        && 's(); }'
        && cl_abap_char_utilities=>newline
        && cl_abap_char_utilities=>newline
        && '  function renderClients(clients) {'
        && cl_abap_char_utilities=>newline
        && '    const list = Array.isArray(clients) ? clients : [];'
        && cl_abap_char_utilities=>newline
        && '    el("clientNotice").textContent = `Подключено клиентов: ${list.length}`;'
        && cl_abap_char_utilities=>newline
        && '    el("clientRows").innerHTML = list.length ? list.map(client => {'
        && cl_abap_char_utilities=>newline
        && '      const status = client.pending ? "Ожидает подтверждения" : client.revoked ? "Отключён" :'
        && 'client.approved ? "Разрешён" : "Не подключён";'
        && cl_abap_char_utilities=>newline
        && '      const when = new Date(client.lastSeen || client.createdAt).toLocaleString();'
        && cl_abap_char_utilities=>newline
        && '      const clientInfo = `${client.domain ? client.domain + " · " : ""}${client.userAgent || "Не определён"}`;'
        && cl_abap_char_utilities=>newline
        && '      return `<tr><td>${escapeHtml(status)}</td><td>${escapeHtml(client.ip || "—")}</td><td>${escapeHtml(clientInfo)}</td><td>${escapeHtml(when)}</td></tr>`;'
        && cl_abap_char_utilities=>newline
        && '    }).join("") : `<tr><td colspan="4" class="muted">Клиентов пока нет</td></tr>`;'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  async function handleHttpRequest(msg) {'
        && cl_abap_char_utilities=>newline
        && '    const started = performance.now();'
        && cl_abap_char_utilities=>newline
        && '    const method = String(msg.method || "GET").toUpperCase();'
        && cl_abap_char_utilities=>newline
        && '    const path = typeof msg.path === "string" ? msg.path : "";'
        && cl_abap_char_utilities=>newline
        && '    requestCount++; renderStats();'
        && cl_abap_char_utilities=>newline
        && '    const row = { time: new Date().toLocaleTimeString(), ip: msg.clientIp || "—", method, path, status: "Выполняется", duration: "—", bytes: 0 };'
        && cl_abap_char_utilities=>newline
        && '    addRequestRow(row);'
        && cl_abap_char_utilities=>newline
        && '    try {'
        && cl_abap_char_utilities=>newline
        && '      if (typeof msg.requestId !== "string" || !msg.requestId || !path) throw new Error("Invalid HTT'
        && 'P request");'
        && cl_abap_char_utilities=>newline
        && '      const allowed = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];'
        && cl_abap_char_utilities=>newline
        && '      if (!allowed.includes(method)) throw new Error("Unsupported HTTP method");'
        && cl_abap_char_utilities=>newline
        && '      if (!path.startsWith("/") || path.startsWith("//") || path.includes("\\") || /[\r\n]/.test(pat'
        && 'h)) throw new Error("Invalid SAP path");'
        && cl_abap_char_utilities=>newline
        && '      const url = new URL(path, window.location.origin);'
        && cl_abap_char_utilities=>newline
        && '      if (url.origin !== window.location.origin) throw new Error("Cross-origin path rejected");'
        && cl_abap_char_utilities=>newline
        && '      const headers = new Headers(), source = msg.headers && typeof msg.headers === "object" ? msg.h'
        && 'eaders : {};'
        && cl_abap_char_utilities=>newline
        && '      const forbidden = ["host", "cookie", "origin", "content-length", "connection", "transfer-encod'
        && 'ing"];'
        && cl_abap_char_utilities=>newline
        && '      for (const [name, value] of Object.entries(source)) if (!forbidden.includes(name.toLowerCase()'
        && ') && typeof value === "string") headers.set(name, value);'
        && cl_abap_char_utilities=>newline
        && '      const body = msg.bodyBase64 ? base64ToBytes(msg.bodyBase64) : undefined;'
        && cl_abap_char_utilities=>newline
        && '      const response = await fetch(url.toString(), { method, headers, body: ["GET", "HEAD"].includes'
        && '(method) ? undefined : body, credentials: "same-origin", cache: "no-store", redirect: "follow" });'
        && cl_abap_char_utilities=>newline
        && '      const responseHeaders = {}; response.headers.forEach((value, name) => { responseHeaders[name] '
        && '= value; });'
        && cl_abap_char_utilities=>newline
        && '      const responseBody = await response.arrayBuffer(), responseBytes = responseBody.byteLength;'
        && cl_abap_char_utilities=>newline
        && '      if (response.status >= 200 && response.status < 400) successCount++; else errorCount++;'
        && cl_abap_char_utilities=>newline
        && '      bytesCount += responseBytes; row.status = `${response.status} ${response.statusText}`; row.byt'
        && 'es = responseBytes;'
        && cl_abap_char_utilities=>newline
        && '      row.duration = `${Math.round(performance.now() - started)} ms`; renderStats(); renderRows();'
        && cl_abap_char_utilities=>newline
        && '      socket.send(JSON.stringify({ type: "http_response", requestId: msg.requestId, status: response'
        && '.status, statusText: response.statusText, headers: responseHeaders, bodyBase64: bytesToBase64(respon'
        && 'seBody) }));'
        && cl_abap_char_utilities=>newline
        && '    } catch (error) {'
        && cl_abap_char_utilities=>newline
        && '      errorCount++; row.status = "502 Agent error"; row.duration = `${Math.round(performance.now() -'
        && ' started)} ms`;'
        && cl_abap_char_utilities=>newline
        && '      const errorBytes = new TextEncoder().encode(String(error && error.message ? error.message : er'
        && 'ror));'
        && cl_abap_char_utilities=>newline
        && '      row.bytes = errorBytes.byteLength; bytesCount += row.bytes; renderStats(); renderRows();'
        && cl_abap_char_utilities=>newline
        && '      if (socket && socket.readyState === WebSocket.OPEN && typeof msg.requestId === "string") socke'
        && 't.send(JSON.stringify({ type: "http_response", requestId: msg.requestId, status: 502, statusText: "A'
        && 'gent fetch failed", headers: { "content-type": "text/plain; charset=utf-8" }, bodyBase64: bytesToBas'
        && 'e64(errorBytes) }));'
        && cl_abap_char_utilities=>newline
        && '    }'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  function stopHeartbeat() { if (heartbeatTimer) { clearInterval(heartbeatTimer); heartbeatTimer = n'
        && 'ull; } }'
        && cl_abap_char_utilities=>newline
        && '  function connectRelay() {'
        && cl_abap_char_utilities=>newline
        && '    if (stopped) return;'
        && cl_abap_char_utilities=>newline
        && '    setStatus("relay", "Подключение...", null);'
        && cl_abap_char_utilities=>newline
        && '    try {'
        && cl_abap_char_utilities=>newline
        && '      socket = new WebSocket(RELAY_URL);'
        && cl_abap_char_utilities=>newline
        && '      socket.onopen = () => {'
        && cl_abap_char_utilities=>newline
        && '        reconnectDelay = 1000; setStatus("relay", "Соединение установлено", true);'
        && cl_abap_char_utilities=>newline
        && '        socket.send(JSON.stringify({ type: "register", arpId: ARP_ID }));'
        && cl_abap_char_utilities=>newline
        && '        stopHeartbeat(); heartbeatTimer = setInterval(() => { if (socket && socket.readyState === We'
        && 'bSocket.OPEN) socket.send(JSON.stringify({ type: "heartbeat", timestamp: Date.now() })); }, HEARTBEA'
        && 'T_INTERVAL);'
        && cl_abap_char_utilities=>newline
        && '      };'
        && cl_abap_char_utilities=>newline
        && '      socket.onmessage = event => {'
        && cl_abap_char_utilities=>newline
        && '        try {'
        && cl_abap_char_utilities=>newline
        && '          const msg = JSON.parse(event.data);'
        && cl_abap_char_utilities=>newline
        && '          if (msg.type === "heartbeat_ack") return;'
        && cl_abap_char_utilities=>newline
        && '          if (msg.type === "registered") { setStatus("relay", "Зарегистрирован", true); return; }'
        && cl_abap_char_utilities=>newline
        && '          if (msg.type === "client_list") { renderClients(msg.clients); return; }'
        && cl_abap_char_utilities=>newline
        && '          if (msg.type === "client_pending") {'
        && cl_abap_char_utilities=>newline
        && '            setStatus("relay", "Новый Eclipse ADT клиент подключён", true);'
        && cl_abap_char_utilities=>newline
        && '            return;'
        && cl_abap_char_utilities=>newline
        && '          }'
        && cl_abap_char_utilities=>newline
        && '          if (msg.type === "client_action_result") {'
        && cl_abap_char_utilities=>newline
        && '            if (!msg.ok) console.warn("Client action failed:", msg.error);'
        && cl_abap_char_utilities=>newline
        && '            return;'
        && cl_abap_char_utilities=>newline
        && '          }'
        && cl_abap_char_utilities=>newline
        && '          if (msg.type === "http_request") { handleHttpRequest(msg); return; }'
        && cl_abap_char_utilities=>newline
        && '          console.log("ARP Relay:", msg);'
        && cl_abap_char_utilities=>newline
        && '        }'
        && cl_abap_char_utilities=>newline
        && '        catch (error) { console.error("Invalid Relay message", error); }'
        && cl_abap_char_utilities=>newline
        && '      };'
        && cl_abap_char_utilities=>newline
        && '      socket.onerror = () => setStatus("relay", "Ошибка соединения", false);'
        && cl_abap_char_utilities=>newline
        && '      socket.onclose = () => {'
        && cl_abap_char_utilities=>newline
        && '        stopHeartbeat(); setStatus("relay", "Отключён. Повторное подключение...", false);'
        && cl_abap_char_utilities=>newline
        && '        if (!stopped) { reconnectTimer = setTimeout(connectRelay, reconnectDelay); reconnectDelay = '
        && 'Math.min(reconnectDelay * 2, 30000); }'
        && cl_abap_char_utilities=>newline
        && '      };'
        && cl_abap_char_utilities=>newline
        && '    } catch (error) {'
        && cl_abap_char_utilities=>newline
        && '      setStatus("relay", `Ошибка: ${error.message}`, false);'
        && cl_abap_char_utilities=>newline
        && '      reconnectTimer = setTimeout(connectRelay, reconnectDelay); reconnectDelay = Math.min(reconnect'
        && 'Delay * 2, 30000);'
        && cl_abap_char_utilities=>newline
        && '    }'
        && cl_abap_char_utilities=>newline
        && '  }'
        && cl_abap_char_utilities=>newline
        && '  window.addEventListener("beforeunload", () => { stopped = true; stopHeartbeat(); if (reconnectTime'
        && 'r) clearTimeout(reconnectTimer); if (socket) socket.close(); });'
        && cl_abap_char_utilities=>newline
        && '  checkSap(); connectRelay();'
        && cl_abap_char_utilities=>newline
        && '})();'
        && cl_abap_char_utilities=>newline
        && '</script>'
        && cl_abap_char_utilities=>newline
        && '</body>'
        && cl_abap_char_utilities=>newline
        && '</html>'.

    " Подставляем ARP-ID в копию HTML; исходный шаблон не изменяем.
    lv_html = mv_html.
    REPLACE ALL OCCURRENCES OF '__ARP_ID__' IN lv_html WITH lv_arp_id.
    REPLACE ALL OCCURRENCES OF '__RELAY_HOST__' IN lv_html WITH gc_relay_host.

    server->response->set_status( code = 200 reason = 'OK' ).
    server->response->set_content_type(
      content_type = 'text/html; charset=utf-8' ).
    server->response->set_header_field(
      name = 'Cache-Control' value = 'no-store' ).
    server->response->set_cdata( data = lv_html ).
  ENDMETHOD.
ENDCLASS.
