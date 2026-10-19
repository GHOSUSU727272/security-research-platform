> Portfolio release: source code, tests, documentation and example configurations only. Local databases, logs, collected targets and runtime state are intentionally excluded. For authorized lab and research use.

# Security Research Platform · Python 3.12+

Модульная локальная платформа для анализа собственных проектов и авторизованных
Bug Bounty исследований. Рабочая версия 0.4: очередь, Python AST-анализ,
контролируемые команды, история проверок и отчёты. Автоматической эксплуатации нет.
Это проверяемая основа для enterprise-развития, не сертифицированный production-продукт.


## Исправление конкурентной записи SQLite

Research Engine теперь использует supervisor как единственный writer своего
запуска: worker'ы отправляют checkpoints через ограниченную очередь и ждут commit.
Импорт Knowledge больше не удерживает read cursor между write-транзакциями.
Это устраняет воспроизведённый `SQLITE_BUSY_SNAPSHOT` / `database is locked` без
retry/sleep. Существующие проекты, checkpoints, Plugin API и CLI совместимы;
миграция базы не нужна. Прерванное исследование продолжается командой `research resume`.

[Первопричина, протокол записи и ограничения](docs/sqlite-writer.md).
Интеграционный тест запускает четыре реальных worker-процесса одновременно с
импортом Knowledge, checkpoints и WAL reader при `busy_timeout=0`.

## Новое: 11 рабочих анализаторов

ELF (pyelftools), Strings (ASCII/UTF-8/UTF-16), Imports, Callgraph, CFG (Capstone),
Logs (syslog/journal/text), Config (YAML/JSON/XML/INI/TOML), YAML, SQLite,
Memory diagnostics и Ghidra Headless. Каждый автоматически зарегистрирован,
настраивается через YAML и передаёт результаты в существующую память проекта.
Research Engine v0.3 распределяет задачи по worker-процессам; пофайловые SQLite
checkpoints и неизменённые команды resume/stop обеспечивают продолжение работы.
Dashboard дополнен статусом, временем, файлами, статистикой и артефактами плагинов.

[Руководство анализаторов](docs/analyzers.md) · [Каталог плагинов](plugins/README.md) ·
[Архитектура расширения](docs/analyzer-architecture.md).

```bash
research open KESL --root /path/to/authorized/target
research --config config/analyzers.yaml start --plan config/analyzers-plan.yaml
research dashboard --engine --output Research-Engine.html
```

Для фактической установки KESL предусмотрены `python -m core.discovery` и
`python -m core.prepare_kesl`: пути выводятся из базы пакетов и процессов,
генерируется план отдельных задач по файлам. Защищённые файлы собираются отдельным
шагом в снимок, анализ выполняется обычным пользователем. Подробнее в руководстве.

## Новое: Research Engine

Оркестратор с DAG задач, приоритетами, отдельными worker-процессами, retries,
таймаутами, отменой, checkpoints, timeline и передачей результатов в память проекта.

```bash
research open KESL --root /path/to/authorized/target
research start --plan config/research-plan.yaml
# Во втором терминале:
research progress
research stop
research resume
research timeline
research checkpoints
research dashboard --engine --output Research-Engine.html
```

[Руководство Research Engine](docs/research-engine.md) ·
[Архитектура v0.3](docs/research-engine-architecture.md).
Команды v0.1 и v0.2 сохранены. start/resume работают в foreground.

## Project Knowledge System

Независимые проекты с отдельными SQLite-базами, памятью, заметками и графом.
Первый проект — **KESL / Kaspersky Endpoint Security for Linux 12.5**.

```bash
research create KESL
research open KESL
research status
research dashboard --output KESL-dashboard.html
research export --output KESL.rpk.zip
# Перенос в другой workspace/на другую машину:
research --workspace transferred import KESL.rpk.zip
```

Для начала анализа: `research open KESL --root /path/to/authorized/target`.
Для полного рабочего процесса см. [руководство](docs/project-knowledge.md) и
[архитектуру модуля](docs/project-knowledge-architecture.md).
Старые команды сохраняются; `--legacy` выбирает базу v0.1 при активном проекте.

## Быстрый запуск на Linux / Kali

Нужны Python 3.12+ и модуль venv. В корне этого проекта:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
research --legacy --config config/example.yaml scan
research --legacy --config config/example.yaml status
research --legacy --config config/example.yaml report --output state/report
```

По умолчанию анализируется только безопасная статическая фикстура tests/fixtures.
Поменяйте `root` в YAML на каталог своего проекта. Пути `root` и `state`
разрешаются относительно YAML. Храните `state` вне исследуемого дерева.

## Операции

```bash
research enqueue --plugin source  # только добавить в SQLite
research run                      # обработать очередь и выйти
research scan --plugin source     # добавить задачу и обработать очередь
research review FINGERPRINT investigating --comment 'Проверяю происхождение ввода'
research link FINGERPRINT OTHER_FINGERPRINT --reason 'Общий источник входных данных'
research report --output state/report
```

Глобальный `--config PATH` ставится перед именем операции. `FINGERPRINT` берётся
из JSON/HTML отчёта. Статусы: new, investigating, confirmed, dismissed.
Все изменения статуса и комментариев остаются в review_history.

Для динамики установите `allow_dynamic: true` и `command: [python3, -m, pytest, -q]`
в конфигурации, затем `research scan --plugin dynamic`. Команда запускается в root,
без shell, но с правами и окружением пользователя. Используйте изолированную VM.
`attempts: 1` полезно для тестов с внешними эффектами. stdout/stderr сохраняются
ограниченными префиксами; хешируется весь поток. Сравниваются последовательные
запуски одной команды в одном root. Различие вывода само по себе не является багом.

## Состав

| Каталог | Назначение |
|---|---|
| core | Контракты, YAML, CLI, очередь, ProjectManager, KnowledgeEngine, GraphEngine |
| database | SQLite WAL, очередь, схема проектов и памяти, история, связи |
| analysis | Карта файлов, SHA-256, AST, импорты, корреляции, knowledge ingest |
| dynamic | Команды, сбор потоков, завершение группы процессов Linux |
| reports | Атомарный экспорт JSON, Markdown, HTML, project dashboard |
| plugins | Реестр, Python entry points и 11 работающих анализаторов |
| config | Пример конфигурации |
| tests | Регрессионные проверки и фикстуры |
| docs | Архитектура, эксплуатация и расширение |

## Проверка качества

```bash
pytest -q
ruff check .
ruff format --check .
mypy core database analysis dynamic reports plugins
```

Linux CI проверяет Python 3.12–3.14. Результаты фактической локальной проверки
и ограничения описаны в [docs/validation.md](docs/validation.md).

## Семантика анализа

Статические сигналы показывают чувствительные вызовы и путь/строку для проверки.
P1 — eval/exec, pickle.loads, os.system или изменение кода выхода теста;
P2 — остальные чувствительные вызовы и изменения вывода. Это объяснимый приоритет
ручной проверки, а не CVSS; достижимость вызова и доверенность ввода не доказаны.
Автоматического подтверждения уязвимости нет. JSON результатов в SQLite содержит
карту файлов, манифесты, импорты и граф вызовов. Отчёт объединяет сигналы всей истории,
а не только последнего состояния файлов; каждый сигнал ссылается на задачи.

Ограничения и решения: [архитектура](docs/architecture.md),
[эксплуатация](docs/operations.md), [плагины](docs/plugins.md).


## CTF AutoSolver live panel

Start `.venv/bin/python -m ctf.panel --workspace /home/anonim/ctf-workspace`.
The panel binds only to `127.0.0.1:8765`. Use the existing SSH tunnel for Windows.
Optional dependencies: `.venv/bin/python -m pip install -e ".[agent]"`.
See `docs/ctf-agent.md` for supported methods, resource limits and remaining gaps.
