# Установка и проверка White Hide на macOS

Для Mac с M1, M2, M3 или M4 скачайте `White-Hide-macOS-arm64.dmg` из Assets нужного [GitHub Release](https://github.com/sonnygalyeon/whitelist-hide/releases). `White-Hide-macOS-intel.dmg` предназначен для Intel. Закройте работающий White Hide и остановите сессию перед заменой приложения.

1. Скачайте DMG и `SHA256SUMS.txt` из одного релиза.
2. Откройте DMG и перетащите `White Hide.app` в **Программы / Applications**, подтвердив замену старой версии.
3. Извлеките DMG и запускайте приложение из **Программ**.
4. Если macOS сообщает о непроверенном разработчике, откройте **Системные настройки → Конфиденциальность и безопасность → Всё равно открыть**. Разрешайте запуск только своего проверенного скачивания.

## Что исправлено в rc.3

В rc.2 не была настроена подпись целого `.app` и его ресурсов. [Нативный аудит опубликованных DMG](https://github.com/sonnygalyeon/whitelist-hide/actions/runs/36855499499) подтвердил: оба образа целы, но ARM64 `.app` возвращает `code has no resources but signature indicates they must be present`, а Intel — `code object is not signed at all`. Подпись, которую компоновщик создаёт для отдельных ARM64 executable, не заменяет подпись приложения. Ранее проверялись SHA-256 скачанного DMG и нативные движки, но не подпись упакованного `.app`.

В rc.3 `utunws` подписывается перед вычислением SHA-256 в его манифесте. Tauri подписывает helper и внешнюю оболочку `.app` в правильном порядке. После упаковки CI проверяет DMG через `hdiutil verify`, копирует приложение, проверяет `codesign --verify --deep --strict`, каждую Mach-O подпись, архитектуру и зависимости. Дополнительно сверяется SHA-256 движка, проверяются все шесть профилей из DMG и восьмисекундный запуск GUI без подключения сети.

Это **ad-hoc подпись**: она защищает целостность пакета, но не удостоверяет издателя через Apple. Developer ID и notarization отсутствуют, поэтому автоматическое одобрение Gatekeeper не заявляется. Факт отклонения/одобрения `spctl` сохраняется в отчёте CI отдельно от проверки целостности.

## Если сообщение «повреждено» сохраняется

Не удаляйте карантин и не переподписывайте скачанное приложение: сначала проверьте причину. Следующие команды только читают метаданные и проверяют файлы:

```bash
sw_vers
uname -m
hdiutil verify "$HOME/Downloads/White-Hide-macOS-arm64.dmg"
shasum -a 256 "$HOME/Downloads/White-Hide-macOS-arm64.dmg"
codesign --verify --deep --strict --verbose=2 "/Applications/White Hide.app"
codesign --display --verbose=4 "/Applications/White Hide.app"
spctl --assess --type execute --verbose=4 "/Applications/White Hide.app"
```

Сравните SHA-256 с соответствующей строкой `SHA256SUMS.txt`. Сообщение `valid on disk` подтверждает целостность подписи; отрицательный `spctl` у ad-hoc сборки ожидаем и сам по себе не означает повреждения. При несовпадении SHA-256 или ошибке `codesign` повторно скачайте пакет из нужного релиза. Если ошибка повторяется, приложите вывод команд и скриншот сообщения; пароль администратора для этих команд не нужен.

Проверка запуска на CI не подтверждает прохождение Gatekeeper на вашем M4, системные диалоги, доступность YouTube/Discord у вашего провайдера или качество звонков. Проверка сетевой сессии и подписей выполняются раздельно.

Основания: [Tauri — macOS signing](https://v2.tauri.app/distribute/sign/macos/), [Apple — Code Signing In Depth](https://developer.apple.com/library/archive/technotes/tn2206/_index.html), [Apple — безопасное открытие приложений](https://support.apple.com/en-us/102445).
