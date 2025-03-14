# CF-Workers-DoH
![img](./img.png)

CF-Workers-DoH — это сервис HTTPS (DoH), построенный на основе Cloudflare Workers. Он позволяет выполнять DNS-запросы через протокол HTTPS, повышая безопасность и защиту приватности запросов.

## 🚀 Способы развертывания

- **Workers** Скопируйте код из файла: [_worker.js](https://github.com/cmliu/CF-Workers-DoH/blob/main/_worker.js), затем нажмите Сохранить и развернуть.
- **Pages** Сделайте Fork репозитория, затем подключите GitHub и разверните в один клик.

## 📖 Инструкция по использованию

Например, домен проекта **Workers `doh.090227.xyz`；

В клиенте или приложении, поддерживающем DoH, установите адрес DoH следующим образом:
```url
https://doh.090227.xyz/dns-query
```

## 💡 Технические особенности
- Основан на бессерверной архитектуре Cloudflare Workers
- Реализован с использованием нативного JavaScript

## 📝 Лицензия
Проект открыт для использования, вы можете свободно развертывать и изменять его!

## 🙏 Благодарности
[tina-hello](https://github.com/tina-hello/doh-cf-workers)、Cloudflare、GPT
