# Desktop

Tauri 2 + Rust + Vite, русский интерфейс в тёмно-зелёной теме.

Инструкции установки, запуска и восстановления для Windows/macOS/Linux находятся в [основном README](../../README.md).

```bash
npm ci
npm test
npm run dev    # просмотр UI; без управления сетью
npm run build # frontend
```

Полная сборка: [release-desktop.yml](../../.github/workflows/release-desktop.yml). До `npm run tauri:build -- --ci` должны быть подготовлены `src-tauri/binaries/whitelist-hide-helper-<target>` и `src-tauri/resources/whitelist-hide/generated`, включая движок, его зависимости, манифесты и три профиля. Затем `npx tauri icon app-icon.svg` создаёт иконки.

WebView не получает shell/filesystem-доступ. Rust принимает только идентификаторы встроенных профилей. Экспорт отчёта пишет файл с фиксированным префиксом в Downloads.
