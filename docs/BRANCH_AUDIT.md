# Проверка веток — 2026-09-23

Основание: фактические Git refs и различия файлов. Старые ветки не удалялись.

| Ветки | Решение |
| --- | --- |
| `main`, `white-hide-v1-development` (`59de01e`) | Одинаковая база после merge PR #9. |
| `feature/usable-desktop-v1` (`5746576`) | Основная линия новой работы: desktop, elevation и сборка runtime. 18 коммитов сверх main. |
| `feature/desktop-zero-config` (`ae3e195`) | Перенесены отсутствовавшие в новой линии компилятор winws2/Lua и запуск из каталога движка. UI и packager интегрированы по смыслу без отката более новых изменений. |
| `feature/desktop-usable` (`3930717`) | Параллельные ранние варианты тех же Windows/runtime/packaging изменений. Не сливались целиком, чтобы не дублировать устаревшие схемы ресурсов. |
| `feature/release-candidate`, `feature/release-candidate-runtime`, `feature/final-release-candidate`, `feature/v1-finalization` | Исторические итерации runtime, уже включённые/заменённые базой PR #9. Количество ahead-коммитов само по себе не означает наличие недостающего функционала: часть merge выполнялась squash. |
| `feature/config-artifact-trust`, `feature/macos-backend-foundation`, `feature/macos-managed-lifecycle`, `feature/mvp-multistage`, `feature/runtime-cross-platform-foundation`, `feature/runtime-strategy-release`, `feature/source-build-and-strategies`, `feature/v1-runtime` | Ранние этапы, проверены относительно текущих модулей; базовые функции уже присутствуют. |

В последнем старом workflow `35602060202` Windows/macOS bundle jobs успешны, Linux упал с `cannot find -lnfnetlink`. Метаданные статических зависимостей были добавлены, но их сборка не вызывалась. Теперь используется `scripts/build_linux_engine.py` с проверкой SHA-256 и статической линковки.

Новые исправления: протокольно-зависимые аргументы, упаковка Lua, рабочий каталог движка, исполняемый PF anchor, исключение помеченных Linux-пакетов, публикация статуса watchdog, сериализация helper-команд, восстановление после раннего завершения, три GUI-профиля и документация.

`ver1.0` — линия интеграции по запросу владельца. Версия пакета остаётся `1.0.0-rc.1` до подтверждения критериев стабильного выпуска; само имя ветки не служит подтверждением качества.
