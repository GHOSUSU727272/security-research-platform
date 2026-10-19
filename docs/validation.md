# Проверка версий 0.1–0.4

## Анализаторы v0.4 — 2026-09-28

Фактически выполнено на Kali VM (Linux 7.1.5, Python 3.13, Ghidra 12.1.3):
**65 passed**, включая реальные Headless Ghidra, Java post-script, Linux /proc,
GCC ELF fixture, процессные worker'ы и end-to-end Knowledge/Graph/Archive.
Ruff check, Ruff format --check и mypy strict проходят (68 Python-модулей с тестами).
Windows / Python 3.12.14: **61 passed, 4 skipped**; Linux/Ghidra-зависимые проверки
пропущены на Windows и выполнены в Kali. Последнее изменение Memory snapshot
дополнительно проверено целевым набором: 22 passed, 3 skipped на Windows.

Регрессии включают старые API/CLI, импорт архивов v1/v2, v3 round-trip с plugin
checkpoints, параллельные независимые анализаторы, dedup Functions и calls,
отмену после успешного file checkpoint, invalidation по SHA-256, timeout/capture
бюджеты backend'ов, реальный ELF dynamic linkage и GNU symbol versions, пять
config formats, XML entities/fragment mode, YAML cycles, UTF-8 границу 64 KiB,
SQLite без изменения целевой базы, Memory live/snapshot и отсутствие Ghidra.

KESL 12.5.0-1569 обнаружен в работающей VM через dpkg/ps/find/readlink/ss.
Найден 971 файл; скопировано 969 файлов, 1 295 213 490 байт. Две занятые базы
events.db и events.db.0001 не включены после 30-секундного timeout SQLite Backup.
Данные maps/status/statm/smaps_rollup получены для PID 689, 197464, 197465.
Это PID и снимки на момент сбора, не обещание существования этих PID после reboot.

На реальной небольшой выборке KESL прошли 10 plugin tasks за 11,118 секунд,
без file errors, warnings или truncated результатов. YAML не запускался на
фиктивном KESL-файле: YAML-файлов в корпусе нет, плагин проверен тестами отдельно.
Первый пробный проход выявил multi-root XML; ошибка сохранена в истории, после
добавления явного xml_fragments повторный проход успешен. Уязвимости автоматически
не подтверждались. Полный план из 2 958 задач сохранён в ready и **не запущен**.
Проверен реальный экспорт/импорт KESL в отдельный workspace внутри Kali.

Нагрузочные многочасовые испытания, отключение питания VM, ARM/AArch64 hardware
и произвольные версии Ghidra не проверялись. История проверок предыдущих версий ниже
сохранена как описание состояния на соответствующем этапе.

## Research Engine v0.3

Среда: Windows, CPython 3.12.14. **39 passed, 1 skipped** во всём наборе
(21 тест предыдущих версий и 18 тестов Research Engine). Пропущен исходный
POSIX-тест симлинков. Ruff check/format и mypy strict (Linux platform profile)
проходят для всех 33 production-модулей. Editable package установлен как 0.3.0.

Новые проверки:

- Валидация DAG, циклов, зависимостей, приоритетов и типов YAML.
- Одновременная работа worker'ов, backoff/retries, изоляция ошибки, blocked-потомки.
- Реальный отдельный Python worker (PID отличается от supervisor), AST → Knowledge.
- Принудительный timeout, включая отмену во время создания процесса.
- Пауза из второй DB-сессии, периодический checkpoint и продолжение без потери бюджета.
- Отмена ожидающей и активной задачи, отмена исследования после simulated crash.
- Recovery после переоткрытия базы: completed не повторяются, interrupted retry учитывается.
- Ошибка Knowledge projection исправляется через resume без повторения плагина.
- Round-trip архива с engine-таблицами/checkpoints/timeline/артефактами; импорт v0.2.
- CLI start --prepare / stop / resume / progress / timeline / checkpoints / dashboard.
- Пустой dashboard и экранирование имён исследований/событий.

Linux process-group cleanup и orphan monitoring реализованы, но в этой среде
не выполнялись; CI Ubuntu предусмотрен существующим workflow. Multi-hour soak-test,
реальный power-loss и нагрузка 10 000 задач не проверялись. Recovery-тест моделирует
оборванную running-задачу и открывает новую DB-сессию, а не выключает ОС.

KESL сохранён без запусков и фиктивных результатов. Research-Engine-KESL.html —
страница idle; KESL-v0.3.rpk.zip — переносимая память проекта с добавленной схемой
engine и HTML-артефактом. Исходный архив v0.2 оставлен отдельно.

## Project Knowledge System v0.2

Фактическая среда: Windows, CPython 3.12.14. Набор регрессий включает исходные
тесты v0.1 и тесты новой системы. Проверены:

- Раздельные базы KESL/OTHER, невозможность чтения чужого UUID и cross-project рёбер.
- Валидируемые типы ссылок заметок и транзакционность при ошибках.
- Статусы гипотез, ручной review, приоритеты, прогресс и история ложных срабатываний.
- Инвентаризация функций без вызовов, идемпотентность ingest и сохранение решений.
- Динамические различия как кандидаты, без автоматического подтверждения.
- Полный round-trip памяти, очереди, графа и бинарного вложения между workspace.
- Отклонение повреждённого ZIP, path traversal, повторных ZIP entries и подменённых
  ссылок даже при пересчитанных SHA-256; каталог остаётся неизменным.
- HTML escaping для имени проекта, текста заметки и категории.
- End-to-end CLI: старый scan/status; create/open/scan/status; --legacy;
  list/dashboard/export; блокировка запуска paused-проекта.

Результат: **21 passed, 1 skipped**; Ruff check/format и mypy strict проходят.
Пропущен исходный POSIX-тест симлинков. Linux runtime и нагрузочные испытания
по-прежнему не выполнялись в данной среде.

Начальный KESL создан с версией 12.5 и заметкой scope. Функций, библиотек,
гипотез, находок и запусков нет: целевые файлы не предоставлены. Подготовлены
отдельный переносимый архив KESL.rpk.zip и KESL-dashboard.html.

## Исходная версия v0.1

Дата: 2026-09-28. Фактическая среда: Windows, CPython 3.12.14, отдельный venv.

- pytest: **10 passed, 1 skipped**. Пропущен POSIX-тест исключения симлинков.
- Ruff check: проходит.
- Ruff format --check: проходит.
- mypy strict: проходит для 16 модулей; проверены Windows и Linux platform profiles.
- Editable installation: проходит после создания всех пакетов.
- Установленный CLI: scan → status(done) → report проходит.
- Созданы example-report/report.html, report.md, report.json.

Тесты проверяют восстановление lease после закрытия БД, исчерпание retries,
изоляцию неисправного плагина, таймаут subprocess, ограничение stdout,
дедупликацию, экранирование HTML, сохранение комментариев, сравнение кодов выхода,
валидацию YAML, блокировку параллельного scheduler, ограничения индексации
и отказ от открытия неподдерживаемой версии схемы.

Linux/Kali runtime здесь не проверен: WSL не установлен. GitHub Actions workflow
подготовлен для Ubuntu/Python 3.12–3.14, но не запускался. Проверка mypy с
`--platform linux` не заменяет runtime-тесты Linux. Многочасовой soak-test,
проверка отказов питания и нагрузочный тест больших репозиториев не проводились.

## Выполненные этапы

1. Архитектура: разделены контракты, persistence, orchestration и плагины;
   задокументирована семантика at-least-once и границы доверия.
2. Ядро: YAML, SQLite WAL, lease, heartbeat, retries, CLI и process lock.
3. Анализ: индекс, манифесты, AST-рёбра, импорты, чувствительные вызовы;
   контролируемые команды, ограниченные потоки и cleanup.
4. Память и отчёты: fingerprint, приоритеты с причиной, сравнение запусков,
   журнал review_events, произвольные связи и три формата экспорта.
5. Проверки: регрессионные тесты, lint/type checks и CLI smoke-test.

Enterprise-ready статус не заявляется. Приоритет следующей итерации — отдельные
процессы для анализа, Linux runtime/soak-тесты и ограничение размера истории.
# SQLite concurrency regression — v0.4.1

Добавлены девять тестов, включая четыре реальных worker-процесса с барьером,
168 checkpoints, Knowledge ingest и независимый WAL reader при busy_timeout=0.
Kali: 74 passed (включая Ghidra); Windows: 70 passed, 4 skipped.
Ruff и strict mypy проходят. Упавший реальный KESL run успешно возобновлён:
51 → 74 завершённых задачи, затем штатный stop, целостность базы проверена.
Подробности, первопричина и границы гарантии: [SQLite writer](sqlite-writer.md).
