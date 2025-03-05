export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const path = url.pathname;
        const hostname = url.hostname;

        // Обработка предварительного запроса OPTIONS
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': '*',
                    'Access-Control-Max-Age': '86400'
                }
            });
        }

        // Если путь запроса /dns-query, обрабатываем как сервер DoH
        if (path === '/dns-query') {
            return await DOHRequest(request);
        }

        // Добавляем прокси для запроса информации о геолокации IP
        if (path === '/ip-info') {
            const ip = url.searchParams.get('ip');
            if (!ip) {
                return new Response(JSON.stringify({ error: "Параметр IP не предоставлен" }), {
                    status: 400,
                    headers: {
                        "content-type": "application/json",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }

            try {
                // Используем Worker для проксирования запроса к HTTP API IP
                const response = await fetch(`http://ip-api.com/json/${ip}?lang=ru-RU`);

                if (!response.ok) {
                    throw new Error(`Ошибка HTTP: ${response.status}`);
                }

                const data = await response.json();

                // Возвращаем данные клиенту и добавляем заголовки CORS
                return new Response(JSON.stringify(data), {
                    headers: {
                        "content-type": "application/json",
                        'Access-Control-Allow-Origin': '*'
                    }
                });

            } catch (error) {
                console.error("Ошибка запроса IP:", error);
                return new Response(JSON.stringify({
                    error: `Ошибка запроса IP: ${error.message}`,
                    status: 'error'
                }), {
                    status: 500,
                    headers: {
                        "content-type": "application/json",
                        'Access-Control-Allow-Origin': '*'
                    }
                });
            }
        }

        // Если в параметрах запроса есть domain и doh, выполняем DNS-запрос
        if (url.searchParams.has("domain") && url.searchParams.has("doh")) {
            const domain = url.searchParams.get("domain") || "www.google.com";
            const doh = url.searchParams.get("doh") || "https://cloudflare-dns.com/dns-query";
            const type = url.searchParams.get("type") || "all"; // По умолчанию запрашиваем A и AAAA

            // Если используется текущий сайт, используем сервис DoH Cloudflare
            if (doh.includes(url.host) || doh === '/dns-query') {
                return await handleLocalDohRequest(domain, type, hostname);
            }

            try {
                // В зависимости от типа запроса выполняем разные действия
                if (type === "all") {
                    // Одновременно запрашиваем A, AAAA и NS записи, используя новую функцию запроса
                    const ipv4Result = await querySpecificProvider(doh, domain, "A");
                    const ipv6Result = await querySpecificProvider(doh, domain, "AAAA");
                    const nsResult = await querySpecificProvider(doh, domain, "NS");

                    // Объединяем результаты
                    const combinedResult = {
                        Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
                        TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
                        RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
                        RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
                        AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
                        CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
                        Question: [...(ipv4Result.Question || []), ...(ipv6Result.Question || []), ...(nsResult.Question || [])],
                        Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || []), ...(nsResult.Answer || [])],
                        ipv4: {
                            records: ipv4Result.Answer || []
                        },
                        ipv6: {
                            records: ipv6Result.Answer || []
                        },
                        ns: {
                            records: nsResult.Answer || []
                        }
                    };

                    return new Response(JSON.stringify(combinedResult, null, 2), {
                        headers: { "content-type": "application/json" }
                    });
                } else {
                    // Обычный запрос одного типа, используем новую функцию запроса
                    const result = await querySpecificProvider(doh, domain, type);
                    return new Response(JSON.stringify(result, null, 2), {
                        headers: { "content-type": "application/json" }
                    });
                }
            } catch (err) {
                console.error("Ошибка DNS-запроса:", err);
                return new Response(JSON.stringify({
                    error: `Ошибка DNS-запроса: ${err.message}`,
                    doh: doh,
                    domain: domain,
                    stack: err.stack
                }, null, 2), {
                    headers: { "content-type": "application/json" },
                    status: 500
                });
            }
        }

        return await HTML();
    }
}

// Универсальная функция для запроса DNS
async function queryDns(dohServer, domain, type) {
    // Создаем URL для запроса DoH
    const dohUrl = new URL(dohServer);
    dohUrl.searchParams.set("name", domain);
    dohUrl.searchParams.set("type", type);

    // Пробуем различные форматы заголовков запроса
    const fetchOptions = [
        // Стандартный application/dns-json
        {
            headers: { 'Accept': 'application/dns-json' }
        },
        // Некоторые сервисы используют запросы без указания Accept
        {
            headers: {}
        },
        // Другой вариант - application/json
        {
            headers: { 'Accept': 'application/json' }
        },
        // Для надежности, некоторые сервисы могут требовать явного User-Agent
        {
            headers: {
                'Accept': 'application/dns-json',
                'User-Agent': 'Mozilla/5.0 DNS Client'
            }
        }
    ];

    let lastError = null;

    // Последовательно пробуем различные комбинации заголовков
    for (const options of fetchOptions) {
        try {
            const response = await fetch(dohUrl.toString(), options);

            // Если запрос успешен, парсим JSON
            if (response.ok) {
                const contentType = response.headers.get('content-type') || '';
                // Проверяем, совместим ли тип содержимого
                if (contentType.includes('json') || contentType.includes('dns-json')) {
                    return await response.json();
                } else {
                    // Для нестандартных ответов все равно пытаемся парсить
                    const textResponse = await response.text();
                    try {
                        return JSON.parse(textResponse);
                    } catch (jsonError) {
                        throw new Error(`Не удалось распарсить ответ как JSON: ${jsonError.message}, содержимое ответа: ${textResponse.substring(0, 100)}`);
                    }
                }
            }

            // В случае ошибки записываем и пробуем следующий вариант
            const errorText = await response.text();
            lastError = new Error(`Ошибка сервера DoH (${response.status}): ${errorText.substring(0, 200)}`);

        } catch (err) {
            // Записываем ошибку и пробуем следующий вариант
            lastError = err;
        }
    }

    // Если все попытки провалились, выбрасываем последнюю ошибку
    throw lastError || new Error("Не удалось выполнить DNS-запрос");
}

// Добавляем специальную обработку для определенных сервисов DoH
async function querySpecificProvider(dohServer, domain, type) {
    // Проверяем, является ли сервис известным и требующим специальной обработки
    const dohLower = dohServer.toLowerCase();

    // Специальная обработка для Google DNS
    if (dohLower.includes('dns.google')) {
        const url = new URL(dohServer);
        // Google DNS использует endpoint /resolve
        if (!dohLower.includes('/resolve')) {
            url.pathname = '/resolve';
        }
        url.searchParams.set("name", domain);
        url.searchParams.set("type", type);

        const response = await fetch(url.toString(), {
            headers: { 'Accept': 'application/json' }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ошибка сервиса Google DNS (${response.status}): ${errorText}`);
        }

        return await response.json();
    }

    // Специальная обработка для OpenDNS
    else if (dohLower.includes('opendns.com')) {
        const url = new URL(dohServer);
        url.searchParams.set("name", domain);
        url.searchParams.set("type", type);

        const response = await fetch(url.toString(), {
            headers: {
                'Accept': 'application/dns-json',
                'User-Agent': 'Mozilla/5.0 DNS Client'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ошибка сервиса OpenDNS (${response.status}): ${errorText}`);
        }

        return await response.json();
    }

    // Используем универсальный метод
    return await queryDns(dohServer, domain, type);
}

// Функция для обработки локальных запросов DoH - напрямую вызываем сервис Cloudflare DoH, а не собственный
async function handleLocalDohRequest(domain, type, hostname) {
    // Используем сервис Cloudflare DoH напрямую, чтобы избежать циклических ссылок
    const cfDoH = "https://cloudflare-dns.com/dns-query";

    try {
        if (type === "all") {
            // Одновременно запрашиваем A, AAAA и NS записи
            const ipv4Promise = querySpecificProvider(cfDoH, domain, "A");
            const ipv6Promise = querySpecificProvider(cfDoH, domain, "AAAA");
            const nsPromise = querySpecificProvider(cfDoH, domain, "NS");

            // Ожидаем завершения всех запросов
            const [ipv4Result, ipv6Result, nsResult] = await Promise.all([ipv4Promise, ipv6Promise, nsPromise]);

            // Объединяем результаты
            const combinedResult = {
                Status: ipv4Result.Status || ipv6Result.Status || nsResult.Status,
                TC: ipv4Result.TC || ipv6Result.TC || nsResult.TC,
                RD: ipv4Result.RD || ipv6Result.RD || nsResult.RD,
                RA: ipv4Result.RA || ipv6Result.RA || nsResult.RA,
                AD: ipv4Result.AD || ipv6Result.AD || nsResult.AD,
                CD: ipv4Result.CD || ipv6Result.CD || nsResult.CD,
                Question: [...(ipv4Result.Question || []), ...(ipv6Result.Question || []), ...(nsResult.Question || [])],
                Answer: [...(ipv4Result.Answer || []), ...(ipv6Result.Answer || []), ...(nsResult.Answer || [])],
                ipv4: {
                    records: ipv4Result.Answer || []
                },
                ipv6: {
                    records: ipv6Result.Answer || []
                },
                ns: {
                    records: nsResult.Answer || []
                }
            };

            return new Response(JSON.stringify(combinedResult, null, 2), {
                headers: {
                    "content-type": "application/json",
                    'Access-Control-Allow-Origin': '*'
                }
            });
        } else {
            // Обычный запрос одного типа
            const result = await querySpecificProvider(cfDoH, domain, type);
            return new Response(JSON.stringify(result, null, 2), {
                headers: {
                    "content-type": "application/json",
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
    } catch (err) {
        console.error("Ошибка запроса Cloudflare DoH:", err);
        return new Response(JSON.stringify({
            error: `Ошибка запроса Cloudflare DoH: ${err.message}`,
            stack: err.stack
        }, null, 2), {
            headers: {
                "content-type": "application/json",
                'Access-Control-Allow-Origin': '*'
            },
            status: 500
        });
    }
}

// Функция для обработки запросов DoH
async function DOHRequest(request) {
    const { method, headers } = request;
    const url = new URL(request.url);
    const { searchParams } = url;

    // Обрабатываем запросы DNS over HTTPS
    // Используем безопасный сервис DoH Cloudflare в качестве бэкенда
    const cloudflareDoH = 'https://cloudflare-dns.com/dns-query';

    try {
        // Строим запрос на основе метода и параметров
        let response;

        if (method === 'GET' && searchParams.has('name')) {
            // Обрабатываем запросы DoH в формате JSON
            const name = searchParams.get('name');
            const type = searchParams.get('type') || 'A';

            // Предотвращаем циклические ссылки, проверяем, не идет ли запрос от самого себя
            const cfUrl = new URL(cloudflareDoH);
            cfUrl.searchParams.set('name', name);
            cfUrl.searchParams.set('type', type);

            response = await fetch(cfUrl.toString(), {
                headers: {
                    'Accept': 'application/dns-json',
                    // Добавляем User-Agent, чтобы не быть распознанным как бот
                    'User-Agent': 'DoH Client'
                }
            });
        } else if (method === 'GET' && searchParams.has('dns')) {
            // Обрабатываем GET-запросы в формате base64url
            response = await fetch(`${cloudflareDoH}?dns=${searchParams.get('dns')}`, {
                headers: {
                    'Accept': 'application/dns-message',
                    'User-Agent': 'DoH Client'
                }
            });
        } else if (method === 'POST') {
            // Обрабатываем POST-запросы
            const contentType = headers.get('content-type');
            if (contentType === 'application/dns-message') {
                response = await fetch(cloudflareDoH, {
                    method: 'POST',
                    headers: {
                        'Accept': 'application/dns-message',
                        'Content-Type': 'application/dns-message',
                        'User-Agent': 'DoH Client'
                    },
                    body: request.body
                });
            } else {
                return new Response('Неподдерживаемый формат запроса', { status: 400 });
            }
        } else {
            // Обработка начального запроса
            // Если браузер напрямую обращается к /dns-query, возвращаем простое сообщение
            if (headers.get('accept')?.includes('text/html')) {
                return new Response('DoH endpoint активен. Это интерфейс сервиса DNS over HTTPS, а не веб-страница.', {
                    headers: { 'Content-Type': 'text/plain; charset=utf-8' }
                });
            }
            return new Response('Неподдерживаемый формат запроса', { status: 400 });
        }

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Ошибка Cloudflare DoH (${response.status}): ${errorText.substring(0, 200)}`);
        }

        // Создаем новый объект заголовков ответа
        const responseHeaders = new Headers(response.headers);
        // Устанавливаем заголовки CORS
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
        responseHeaders.set('Access-Control-Allow-Headers', '*');

        // Возвращаем ответ
        return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders
        });
    } catch (error) {
        console.error("Ошибка обработки запроса DoH:", error);
        return new Response(JSON.stringify({
            error: `Ошибка обработки запроса DoH: ${error.message}`,
            stack: error.stack
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}
async function HTML() {
    // Иначе возвращаем HTML страницу
    const html = `<!DOCTYPE html>
<html lang="ru-RU">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS-over-HTTPS Resolver</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <link rel="icon"
    href="https://cf-assets.www.cloudflare.com/dzlvafdwdttg/6TaQ8Q7BDmdAFRoHpDCb82/8d9bc52a2ac5af100de3a9adcf99ffaa/security-shield-protection-2.svg"
    type="image/x-icon">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      min-height: 100vh;
      padding: 0;
      margin: 0;
      line-height: 1.6;
      background: url('https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5B5shLB8bSKIyB9NJ6R1jz/87e7617be2c61603d46003cb3f1bd382/Hero-globe-bg-takeover-xxl.png'),
        linear-gradient(135deg, rgba(253, 101, 60, 0.85) 0%, rgba(255, 156, 110, 0.85) 100%);
      background-size: cover;
      background-position: center center;
      background-repeat: no-repeat;
      background-attachment: fixed;
      padding: 30px 20px;
      box-sizing: border-box;
    }

    .page-wrapper {
      width: 100%;
      max-width: 800px;
      margin: 0 auto;
    }

    .container {
      width: 100%;
      max-width: 800px;
      margin: 20px auto;
      background-color: rgba(255, 255, 255, 0.65);
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
      padding: 30px;
      backdrop-filter: blur(10px);
      -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.4);
    }

    h1 {
      /* Создаем эффект градиента для текста */
      background-image: linear-gradient(to right, rgb(249, 171, 76), rgb(252, 103, 60));
      /* Цвет для браузеров, которые не поддерживают градиентный текст */
      color: rgb(252, 103, 60);
      -webkit-background-clip: text;
      -moz-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
      -moz-text-fill-color: transparent;
      
      font-weight: 600;
      /* Примечание: одновременное использование градиентного текста и эффекта тени может быть несовместимо, временно убираем тень */
      text-shadow: none;
    }

    .card {
      margin-bottom: 20px;
      border: none;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
      background-color: rgba(255, 255, 255, 0.8);
      backdrop-filter: blur(5px);
      -webkit-backdrop-filter: blur(5px);
    }

    .card-header {
      background-color: rgba(255, 242, 235, 0.9);
      font-weight: 600;
      padding: 12px 20px;
      border-bottom: none;
    }

    .form-label {
      font-weight: 500;
      margin-bottom: 8px;
      color: rgb(70, 50, 40);
    }

    .form-select,
    .form-control {
      border-radius: 6px;
      padding: 10px;
      border: 1px solid rgba(253, 101, 60, 0.3);
      background-color: rgba(255, 255, 255, 0.9);
    }

    .btn-primary {
      background-color: rgb(253, 101, 60);
      border: none;
      border-radius: 6px;
      padding: 10px 20px;
      font-weight: 500;
      transition: all 0.2s ease;
    }

    .btn-primary:hover {
      background-color: rgb(230, 90, 50);
      transform: translateY(-1px);
    }

    pre {
      background-color: rgba(255, 245, 240, 0.9);
      padding: 15px;
      border-radius: 6px;
      border: 1px solid rgba(253, 101, 60, 0.2);
      white-space: pre-wrap;
      word-break: break-all;
      font-family: Consolas, Monaco, 'Andale Mono', monospace;
      font-size: 14px;
      max-height: 400px;
      overflow: auto;
    }

    .loading {
      display: none;
      text-align: center;
      padding: 20px 0;
    }

    .loading-spinner {
      border: 4px solid rgba(0, 0, 0, 0.1);
      border-left: 4px solid rgb(253, 101, 60);
      border-radius: 50%;
      width: 30px;
      height: 30px;
      animation: spin 1s linear infinite;
      margin: 0 auto 10px;
    }

    .badge {
      margin-left: 5px;
      font-size: 11px;
      vertical-align: middle;
    }

    @keyframes spin {
      0% {
        transform: rotate(0deg);
      }

      100% {
        transform: rotate(360deg);
      }
    }

    .footer {
      margin-top: 30px;
      text-align: center;
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
    }

    .beian-info {
      text-align: center;
      font-size: 13px;
    }

    .beian-info a {
      color: var(--primary-color);
      text-decoration: none;
      border-bottom: 1px dashed var(--primary-color);
      padding-bottom: 2px;
    }

    .beian-info a:hover {
      border-bottom-style: solid;
    }

    @media (max-width: 576px) {
      .container {
        padding: 20px;
      }

      .github-corner:hover .octo-arm {
        animation: none;
      }

      .github-corner .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
      }
    }

    .error-message {
      color: #e63e00;
      margin-top: 10px;
    }

    .success-message {
      color: #e67e22;
    }

    .nav-tabs .nav-link {
      border-top-left-radius: 6px;
      border-top-right-radius: 6px;
      padding: 8px 16px;
      font-weight: 500;
      color: rgb(150, 80, 50);
    }

    .nav-tabs .nav-link.active {
      background-color: rgba(255, 245, 240, 0.8);
      border-bottom-color: rgba(255, 245, 240, 0.8);
      color: rgb(253, 101, 60);
    }

    .tab-content {
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 0 0 6px 6px;
      padding: 15px;
      border: 1px solid rgba(253, 101, 60, 0.2);
      border-top: none;
    }

    .ip-record {
      padding: 5px 10px;
      margin-bottom: 5px;
      border-radius: 4px;
      background-color: rgba(255, 255, 255, 0.9);
      border: 1px solid rgba(253, 101, 60, 0.15);
    }

    .ip-record:hover {
      background-color: rgba(255, 235, 225, 0.9);
    }

    .ip-address {
      font-family: monospace;
      font-weight: 600;
      min-width: 130px;
      color: rgb(80, 60, 50);
    }

    .result-summary {
      margin-bottom: 15px;
      padding: 10px;
      background-color: rgba(255, 235, 225, 0.8);
      border-radius: 6px;
    }

    .result-tabs {
      margin-bottom: 20px;
    }

    .geo-info {
      margin: 0 10px;
      font-size: 0.85em;
      flex-grow: 1;
      text-align: center;
    }

    .geo-country {
      color: rgb(230, 90, 50);
      font-weight: 500;
      padding: 2px 6px;
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 4px;
      display: inline-block;
    }

    .geo-as {
      color: rgb(253, 101, 60);
      padding: 2px 6px;
      background-color: rgba(255, 245, 240, 0.8);
      border-radius: 4px;
      margin-left: 5px;
      display: inline-block;
    }

    .geo-loading {
      color: rgb(150, 100, 80);
      font-style: italic;
    }

    .ttl-info {
      min-width: 80px;
      text-align: right;
      color: rgb(180, 90, 60);
    }

    .copy-link {
      color: rgb(253, 101, 60);
      text-decoration: none;
      border-bottom: 1px dashed rgb(253, 101, 60);
      padding-bottom: 2px;
      cursor: pointer;
      position: relative;
    }

    .copy-link:hover {
      border-bottom-style: solid;
    }

    .copy-link:after {
      content: '';
      position: absolute;
      top: 0;
      right: -65px;
      opacity: 0;
      white-space: nowrap;
      color: rgb(253, 101, 60);
      font-size: 12px;
      transition: opacity 0.3s ease;
    }

    .copy-link.copied:after {
      content: '✓ Скопировано';
      opacity: 1;
    }

    .github-corner svg {
      fill: rgb(255, 255, 255);
      color: rgb(251,152,30);
      position: absolute;
      top: 0;
      right: 0;
      border: 0;
      width: 80px;
      height: 80px;
    }

    .github-corner:hover .octo-arm {
      animation: octocat-wave 560ms ease-in-out;
    }

    /* Добавляем ключевые кадры для анимации волны осьминога */
    @keyframes octocat-wave {
      0%, 100% { transform: rotate(0); }
      20%, 60% { transform: rotate(-25deg); }
      40%, 80% { transform: rotate(10deg); }
    }

    @media (max-width: 576px) {
      .container {
        padding: 20px;
      }

      .github-corner:hover .octo-arm {
        animation: none;
      }

      .github-corner .octo-arm {
        animation: octocat-wave 560ms ease-in-out;
      }
    }
  </style>
</head>

<body>
  <a href="https://github.com/cmliu/CF-Workers-DoH" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path
        d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2"
        fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path
        d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z"
        fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">Настройки DNS запроса</div>
      <div class="card-body">
        <form id="resolveForm">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">Выберите DoH адрес:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected>Текущий сайт (авто)</option>
              <option value="https://doh.pub/dns-query">doh.pub (Tencent)</option>
              <option value="https://cloudflare-dns.com/dns-query">Cloudflare DNS</option>
              <option value="https://dns.google/resolve">Google (Google)</option>
              <option value="https://dns.twnic.tw/dns-query">Quad101 (TWNIC)</option>
              <option value="custom">Пользовательский...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">Введите пользовательский DoH адрес:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/dns-query">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">Домен для разрешения:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" value="www.google.com"
                placeholder="Введите домен, например example.com">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">Очистить</button>
            </div>
          </div>
          <div class="d-grid">
            <button type="submit" class="btn btn-primary">Разрешить</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>Результат разрешения</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display: none;">Копировать результат</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>Запрос выполняется, пожалуйста, подождите...</p>
        </div>

        <!-- Область отображения результатов, включая вкладки -->
        <div id="resultContainer" style="display: none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation">
              <button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button"
                role="tab">IPv4 адреса</button>
</li>
<li class="nav-item" role="presentation">
  <button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button"
    role="tab">IPv6 адрес</button>
</li>
<li class="nav-item" role="presentation">
  <button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS
    запись</button>
</li>
<li class="nav-item" role="presentation">
  <button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button"
    role="tab">Исходные данные</button>
</li>
</ul>
<div class="tab-content" id="resultTabContent">
<div class="tab-pane fade show active" id="ipv4" role="tabpanel" aria-labelledby="ipv4-tab">
  <div class="result-summary" id="ipv4Summary"></div>
  <div id="ipv4Records"></div>
</div>
<div class="tab-pane fade" id="ipv6" role="tabpanel" aria-labelledby="ipv6-tab">
  <div class="result-summary" id="ipv6Summary"></div>
  <div id="ipv6Records"></div>
</div>
<div class="tab-pane fade" id="ns" role="tabpanel" aria-labelledby="ns-tab">
  <div class="result-summary" id="nsSummary"></div>
  <div id="nsRecords"></div>
</div>
<div class="tab-pane fade" id="raw" role="tabpanel" aria-labelledby="raw-tab">
  <pre id="result">Ожидание запроса...</pre>
</div>
</div>
</div>

<!-- Область сообщений об ошибках -->
<div id="errorContainer" style="display: none;">
  <pre id="errorMessage" class="error-message"></pre>
</div>
</div>
</div>

<div class="beian-info">
<p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="Нажмите, чтобы скопировать">https://<span
        id="currentDomain">...</span>/dns-query</span></strong><br>Сервис разрешения DNS через HTTPS (DoH) на основе Cloudflare Workers</p>
</div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Получение текущего URL и имени хоста
const currentUrl = window.location.href;
const currentHost = window.location.host;
const currentProtocol = window.location.protocol;
const currentDohUrl = currentProtocol + '//' + currentHost + '/dns-query';

// Запись текущего используемого адреса DoH
let activeDohUrl = currentDohUrl;

// Отображение текущего используемого сервиса DoH
function updateActiveDohDisplay() {
  const dohSelect = document.getElementById('dohSelect');
  if (dohSelect.value === 'current') {
    activeDohUrl = currentDohUrl;
  }
}

// Первоначальное обновление
updateActiveDohDisplay();

// Показать поле ввода при выборе пользовательского DoH
document.getElementById('dohSelect').addEventListener('change', function () {
  const customContainer = document.getElementById('customDohContainer');
  customContainer.style.display = (this.value === 'custom') ? 'block' : 'none';

  if (this.value === 'current') {
    activeDohUrl = currentDohUrl;
  } else if (this.value !== 'custom') {
    activeDohUrl = this.value;
  }
});

// Функция кнопки очистки
document.getElementById('clearBtn').addEventListener('click', function () {
  document.getElementById('domain').value = '';
  document.getElementById('domain').focus();
});

// Функция копирования результата
document.getElementById('copyBtn').addEventListener('click', function () {
  const resultText = document.getElementById('result').textContent;
  navigator.clipboard.writeText(resultText).then(function () {
    const originalText = this.textContent;
    this.textContent = 'Скопировано';
    setTimeout(() => {
      this.textContent = originalText;
    }, 2000);
  }.bind(this)).catch(function (err) {
    console.error('Не удалось скопировать текст: ', err);
  });
});

// Форматирование TTL
function formatTTL(seconds) {
  if (seconds < 60) return seconds + 'сек';
  if (seconds < 3600) return Math.floor(seconds / 60) + 'мин';
  if (seconds < 86400) return Math.floor(seconds / 3600) + 'ч';
  return Math.floor(seconds / 86400) + 'д';
}

// Запрос информации о геолокации IP - использование нашего прокси API вместо прямого доступа к HTTP
async function queryIpGeoInfo(ip) {
  try {
    // Использование нашего прокси-интерфейса
    const response = await fetch(\`./ip-info?ip=\${ip}\`);
    if (!response.ok) {
      throw new Error(`HTTP ошибка: ${response.status}`);
    }
    return await response.json();
  } catch (error) {
    console.error('Ошибка запроса геолокации IP:', error);
    return null;
  }
}

// Отображение записей
function displayRecords(data) {
  document.getElementById('resultContainer').style.display = 'block';
  document.getElementById('errorContainer').style.display = 'none';
  document.getElementById('result').textContent = JSON.stringify(data, null, 2);

  // Записи IPv4
  const ipv4Records = data.ipv4?.records || [];
  const ipv4Container = document.getElementById('ipv4Records');
  ipv4Container.innerHTML = '';

  if (ipv4Records.length === 0) {
    document.getElementById('ipv4Summary').innerHTML = `<strong>Записи IPv4 не найдены</strong>`;
  } else {
    document.getElementById('ipv4Summary').innerHTML = `<strong>Найдено ${ipv4Records.length} записей IPv4</strong>`;

    ipv4Records.forEach(record => {
      if (record.type === 1) {  // 1 = A запись
        const recordDiv = document.createElement('div');
        recordDiv.className = 'ip-record';
        recordDiv.innerHTML = `
          <div class="d-flex justify-content-between align-items-center">
            <span class="ip-address">${record.data}</span>
            <span class="geo-info geo-loading">Получение информации о местоположении...</span>
            <span class="text-muted ttl-info">TTL: ${formatTTL(record.TTL)}</span>
          </div>
        `;
        ipv4Container.appendChild(recordDiv);

        // Добавление информации о геолокации
        const geoInfoSpan = recordDiv.querySelector('.geo-info');
        // Асинхронный запрос информации о геолокации IP
        queryIpGeoInfo(record.data).then(geoData => {
          if (geoData && geoData.status === 'success') {
            // Обновление с фактической информацией о геолокации
            geoInfoSpan.innerHTML = '';
            geoInfoSpan.classList.remove('geo-loading');

            // Добавление информации о стране
            const countrySpan = document.createElement('span');
            countrySpan.className = 'geo-country';
            countrySpan.textContent = geoData.country || 'Неизвестная страна';
            geoInfoSpan.appendChild(countrySpan);

            // Добавление информации об AS
            const asSpan = document.createElement('span');
            asSpan.className = 'geo-as';
            asSpan.textContent = geoData.as || 'Неизвестный AS';
            geoInfoSpan.appendChild(asSpan);
          } else {
            // Ошибка запроса или отсутствие результатов
            geoInfoSpan.textContent = 'Ошибка получения информации о местоположении';
          }
        });
      }
    });
  }

  // Записи IPv6
  const ipv6Records = data.ipv6?.records || [];
  const ipv6Container = document.getElementById('ipv6Records');
  ipv6Container.innerHTML = '';

  if (ipv6Records.length === 0) {
    document.getElementById('ipv6Summary').innerHTML = `<strong>Записи IPv6 не найдены</strong>`;
  } else {
    document.getElementById('ipv6Summary').innerHTML = `<strong>Найдено ${ipv6Records.length} записей IPv6</strong>`;

    ipv6Records.forEach(record => {
      if (record.type === 28) {  // 28 = AAAA запись
        const recordDiv = document.createElement('div');
        recordDiv.className = 'ip-record';
        recordDiv.innerHTML = `
          <div class="d-flex justify-content-between align-items-center">
            <span class="ip-address">${record.data}</span>
            <span class="geo-info geo-loading">Получение информации о местоположении...</span>
            <span class="text-muted ttl-info">TTL: ${formatTTL(record.TTL)}</span>
          </div>
        `;
        ipv6Container.appendChild(recordDiv);

        // Добавление информации о геолокации
        const geoInfoSpan = recordDiv.querySelector('.geo-info');
        // Асинхронный запрос информации о геолокации IP
        queryIpGeoInfo(record.data).then(geoData => {
          if (geoData && geoData.status === 'success') {
            // Обновление с фактической информацией о геолокации
            geoInfoSpan.innerHTML = '';
            geoInfoSpan.classList.remove('geo-loading');

            // Добавление информации о стране
            const countrySpan = document.createElement('span');
            countrySpan.className = 'geo-country';
            countrySpan.textContent = geoData.country || 'Неизвестная страна';
            geoInfoSpan.appendChild(countrySpan);

            // Добавление информации об AS
            const asSpan = document.createElement('span');
            asSpan.className = 'geo-as';
            asSpan.textContent = geoData.as || 'Неизвестный AS';
            geoInfoSpan.appendChild(asSpan);
          } else {
            // Ошибка запроса или отсутствие результатов
            geoInfoSpan.textContent = 'Ошибка получения информации о местоположении';
          }
        });
      }
    });
  }

  // Записи NS
  const nsRecords = data.ns?.records || [];
  const nsContainer = document.getElementById('nsRecords');
  nsContainer.innerHTML = '';

  if (nsRecords.length === 0) {
    document.getElementById('nsSummary').innerHTML = `<strong>Записи NS не найдены</strong>`;
  } else {
    document.getElementById('nsSummary').innerHTML = `<strong>Найдено ${nsRecords.length} записей серверов имен</strong>`;

    nsRecords.forEach(record => {
      if (record.type === 2) {  // 2 = NS запись
        const recordDiv = document.createElement('div');
        recordDiv.className = 'ip-record';
        recordDiv.innerHTML = `
          <div class="d-flex justify-content-between align-items-center">
            <span class="ip-address">${record.data}</span>
            <span class="text-muted">TTL: ${formatTTL(record.TTL)}</span>
          </div>
        `;
        nsContainer.appendChild(recordDiv);
      }
    });
  }

  // Когда пользователь переключается на вкладку IPv4 или IPv6, убедитесь, что отображается загруженная информация о геолокации
  document.getElementById('ipv4-tab').addEventListener('click', function() {
    // Если есть еще загружаемая информация о геолокации, можно обработать здесь
  });

  document.getElementById('ipv6-tab').addEventListener('click', function() {
    // Если есть еще загружаемая информация о геолокации, можно обработать здесь
  });

  // Отображение кнопки копирования
  document.getElementById('copyBtn').style.display = 'block';
}

// Отображение ошибки
function displayError(message) {
  document.getElementById('resultContainer').style.display = 'none';
  document.getElementById('errorContainer').style.display = 'block';
  document.getElementById('errorMessage').textContent = message;
  document.getElementById('copyBtn').style.display = 'none';
}

// Отправка формы и выполнение запроса DNS
document.getElementById('resolveForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const dohSelect = document.getElementById('dohSelect').value;
  let doh;

  if(dohSelect === 'current') {
    doh = currentDohUrl;
  } else if(dohSelect === 'custom') {
    doh = document.getElementById('customDoh').value;
    if (!doh) {
      alert('Введите пользовательский адрес DoH');
      return;
    }
  } else {
    doh = dohSelect;
  }

  const domain = document.getElementById('domain').value;
  if (!domain) {
    alert('Введите домен для разрешения');
    return;
  }

  // Отображение состояния загрузки
  document.getElementById('loading').style.display = 'block';
  document.getElementById('resultContainer').style.display = 'none';
  document.getElementById('errorContainer').style.display = 'none';
  document.getElementById('copyBtn').style.display = 'none';

  try {
    // Выполнение запроса, параметры передаются через GET, type=all означает запрос A и AAAA одновременно
    const response = await fetch(`?doh=${encodeURIComponent(doh)}&domain=${encodeURIComponent(domain)}&type=all`);

    if (!response.ok) {
      throw new Error(`HTTP ошибка: ${response.status}`);
    }

    const json = await response.json();

    // Проверка, содержит ли ответ ошибку
    if (json.error) {
      displayError(json.error);
    } else {
      displayRecords(json);
    }
  } catch (error) {
    displayError('Ошибка запроса: ' + error.message);
  } finally {
    // Скрытие состояния загрузки
    document.getElementById('loading').style.display = 'none';
  }
});

// Выполнение после загрузки страницы
document.addEventListener('DOMContentLoaded', function() {
  // Использование локального хранилища для запоминания последнего использованного домена
  const lastDomain = localStorage.getItem('lastDomain');
  if (lastDomain) {
    document.getElementById('domain').value = lastDomain;
  }

  // Отслеживание изменений ввода домена и сохранение
  document.getElementById('domain').addEventListener('input', function() {
    localStorage.setItem('lastDomain', this.value);
  });
});

// Выполнение после загрузки страницы
document.addEventListener('DOMContentLoaded', function() {
  // Использование локального хранилища для запоминания последнего использованного домена
  const lastDomain = localStorage.getItem('lastDomain');
  if (lastDomain) {
    document.getElementById('domain').value = lastDomain;
  }

  // Отслеживание изменений ввода домена и сохранение
  document.getElementById('domain').addEventListener('input', function() {
    localStorage.setItem('lastDomain', this.value);
  });

  // Обновление отображения текущего домена
  document.getElementById('currentDomain').textContent = currentHost;

  // Установка функции копирования ссылки DoH
  const dohUrlDisplay = document.getElementById('dohUrlDisplay');
  if (dohUrlDisplay) {
    dohUrlDisplay.addEventListener('click', function() {
      const textToCopy = currentProtocol + '//' + currentHost + '/dns-query';
      navigator.clipboard.writeText(textToCopy).then(function() {
        dohUrlDisplay.classList.add('copied');
        setTimeout(() => {
          dohUrlDisplay.classList.remove('copied');
        }, 2000);
      }).catch(function(err) {
        console.error('Ошибка копирования:', err);
      });
    });
  }
});
</script>
</body>

</html>`;

    return new Response(html, {
        headers: { "content-type": "text/html;charset=UTF-8" }
    });
}

