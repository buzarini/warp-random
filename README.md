# WARP Random

Веб-генератор конфигураций AmneziaWG для Cloudflare WARP с маскировкой трафика под QUIC.

## Возможности

- Генерация готового `.conf` для AmneziaWG (WARP)
- Три режима endpoint: авто, IP, домен
- Выбор диапазона IP-адресов Cloudflare
- Настройка `I1`: QUIC-маскировка (5 уровней оптимизации)
- Проверка существования домена через Google DoH с фолбэком
- Скачивание файла конфигурации в один клик

## Благодарности

- Код `quic.js` взят из [mini_quic_generator](https://github.com/SagePtr/mini_quic_generator) от [SagePtr](https://github.com/SagePtr/mini_quic_generator)
- Идея основана на проекте [warp-config-generator](https://github.com/DikozImpact/domain-redirect/tree/9748e5dd5b2ee165a835aca2dcf6bc7712cd1933) от [DikozImpact](https://github.com/DikozImpact)

## Лицензия

Проект распространяется под лицензией MIT.