# Project Knowledge System v0.2

## Начало работы

В корне проекта после установки `python -m pip install -e '.[dev]'`:

```bash
research create KESL
research open KESL
research list
research status
research dashboard
research export --output KESL.rpk.zip
```

`KESL` получает название продукта **Kaspersky Endpoint Security for Linux** и
версию **12.5**. Это запись проекта, не утверждение о наличии установленного
продукта или найденных уязвимостей. Исследуемые функции, библиотеки и результаты
изначально отсутствуют. `last_researched_at` остаётся null до первого запуска.

Для других проектов задавайте метаданные явно:

```bash
research create MyProduct --description 'Authorized lab research' --product 'Example' --version 1.0
research open KESL --root /srv/lab/kesl-source
research scan --plugin source
research status
```

У каждой базы отдельные jobs, reviews, notes, граф, SQLite WAL и логи.
`--workspace /srv/research` задаёт каталог проектов (по умолчанию ./state).
`--project KESL` выбирает проект только для данной команды, не меняя open.
Оба флага являются глобальными и ставятся **перед** командой:

```bash
research --workspace /srv/research --project KESL status
```

Выбор `open` сохраняется между процессами. Без выбранного проекта старые команды
используют прежнюю базу из YAML. `research --legacy status` всегда обращается к ней.
Существующая база v0.1 не мигрирует в KESL автоматически и не смешивается с ним.
Проектные команды create/open/list/status/export/import не требуют валидного
target root и не требуют файла YAML. Команды scan/run используют настройки YAML
v0.1, но root берут из локальной привязки выбранного проекта.

## Knowledge Engine

```bash
research knowledge add Functions parse_packet --evidence '{"path":"src/parser.c","line":42}'
research knowledge add Libraries libexample.so --evidence '{"version":"unknown"}'
research knowledge add Hypotheses 'Проверить обработку пустого ввода' --priority 1
research knowledge list Functions --status unreviewed
research knowledge list Libraries --status reviewed
research knowledge list Hypotheses --status open
research knowledge set FUNCTION_UUID reviewed --reason 'Просмотрены реализация и вызывающие функции'
research knowledge set HYPOTHESIS_UUID testing --reason 'Подготовлен ручной тест'
research knowledge set HYPOTHESIS_UUID rejected --reason 'Тест подтвердил ожидаемое поведение'
research knowledge add Experiments 'Сравнение обработки пустого ввода'
research knowledge add InterestingLocations 'parser.c:42' --priority 1
```

Команды добавления возвращают UUID; подставляйте его вместо FUNCTION_UUID и т. п.
Все списки поддерживают `--limit` (1–1000) и `--offset`. evidence — JSON-объект,
поля в нём задаются предметным анализатором/исследователем.

| Сущности | Допустимые состояния |
|---|---|
| Artifacts, Functions, Libraries, Modules | unreviewed, reviewed |
| Hypotheses | open, testing, confirmed, rejected |
| Experiments | planned, running, done, failed |
| Findings | candidate, confirmed, dismissed |
| InterestingLocations | open, reviewed |
| FalsePositives | documented |
| Notes | active, archived |
| ResearchHistory | recorded (история не редактируется через API) |

Смена состояния требует причины. Отклонение Findings создаёт запись FalsePositives
и ребро dismisses. При переоткрытии записи её история остаётся, но текущий счётчик
ложных срабатываний уменьшается. Непроверенная гипотеза никогда не превращается
в подтверждённый результат автоматически.

`research project-status paused|active|completed` меняет статус проекта.
В paused/completed запрещены enqueue/scan/run; чтение и редактирование памяти доступны.

## Заметки и Graph Engine

```bash
research note 'Проследить происхождение параметра' --category manual-review --priority 1 --function FUNCTION_UUID --library LIBRARY_UUID
research graph link HYPOTHESIS_UUID FUNCTION_UUID --relation concerns --reason 'Предполагаемая точка проверки'
research graph link EXPERIMENT_UUID HYPOTHESIS_UUID --relation tests --reason 'Проверка гипотезы'
research graph show FUNCTION_UUID --depth 2
```

`--function` и `--library` повторяются для нескольких ссылок. Несуществующие UUID,
UUID другого проекта и несовпадающие типы заметочных ссылок отклоняются до записи.
Каждая заметка содержит created_at, priority, body, category и рёбра refers_to.
Граф направленный; show обходит обе стороны рёбер на глубину 1–5, не более 1000 узлов.
Рёбра повторно не создаются для одинаковой тройки source/target/relation.

## Результаты запусков

После `research scan`/`run` выполненные и окончательно ошибочные задачи отражаются
в Experiments и ResearchHistory. `research sync` восстанавливает эту проекцию,
если процесс был прерван после сохранения результата, но до обновления знаний.
Повторный sync не дублирует результаты; ручные статусы не сбрасываются.

Статический анализ добавляет индексированные Artifacts, Modules, объявления
Functions, импортируемые Libraries и связи. Чувствительные вызовы создают Findings
и InterestingLocations. Динамические различия становятся кандидатами Findings,
связанными с экспериментом. Исходные результаты и логи stdout/stderr остаются в jobs.
Текущий анализатор функций рассчитан на Python; для ELF/C/C++ данные можно внести
вручную или добавить плагин. Поддержка проекта KESL не означает наличие ELF-анализатора.

Идентичность функции — path+qualified name; смещение строк не сбрасывает review.
Это память исследования, а не утверждение, что функция после изменения кода
снова проверена. Для нового состояния кода создавайте эксперимент и при необходимости
переводите функции обратно в unreviewed. Содержимое первого наблюдения сохраняется
в evidence, последующие снимки доступны через jobs/Artifacts.

Команды v0.1 `review`, `link` и `report` сохраняют прежний формат и таблицы.
Для новых UUID используйте `knowledge set`, `graph link` и `dashboard`.
Автоматического двустороннего переноса статусов между двумя API нет.

## Dashboard

```bash
research dashboard --output KESL-dashboard.html
```

Страница работает офлайн, не требует веб-сервера и не выполняет JavaScript.
Она показывает метаданные, reviewed/total для Functions+Libraries, счётчики,
состояния гипотез, 20 последних запусков, до 20 приоритетных интересных мест
и заметок. Нулевой инвентарь отображается как «No inventory yet», а не 100%.
Все пользовательские поля экранируются; страница содержит ограничивающий CSP.

## Перенос и вложения

```bash
research attach /srv/lab/evidence/test.log --name 'Лог ручного теста'
research export --output KESL.rpk.zip
# На другой машине:
research import KESL.rpk.zip
research open KESL --root /new/lab/kesl-source
research status
```

ZIP содержит manifest.json, data.json (все записи всех таблиц проектной SQLite-базы)
и вложения artifacts/SHA256. Экспорт использует SQLite backup API для согласованного
снимка. Импорт восстанавливает записи только в известную схему с FK и в отдельный
временный каталог; чужие SQL/DDL, пути и плагины не исполняются. Сначала проверяются
размеры, SHA-256, состав архива, типы сущностей, состояния и связи. Только затем
проект публикуется в каталоге. Конфликты имени/ID отклоняются без перезаписи.
SHA-256 обнаруживает повреждение; криптографической подписи/аутентичности архива нет.

История, очередь, исходные результаты и все вложения через attach переносятся.
Внешний каталог root, ОС-окружение, зависимости, установленные плагины и операционные
файлы логов не включаются. Для важных логов используйте attach. Связь с локальным
root после импорта сбрасывается; import ничего не запускает. При следующем явном
run ожидающие задачи привязываются к новому root, старый путь записывается в историю.
Команды динамических задач сохраняются, но выполняются только при allow_dynamic=true.

Лимиты: 256 MiB на вложение, 512 MiB распакованных данных архива, 10 000 ZIP entries.
Экспорт/импорт метаданных пока выполняется в памяти. Для больших проектов нужны
потоковый формат и политика retention; это не облачный многопользовательский сервис.

## Схема SQLite

Projects: id, name, description, product, product_version, created_at,
last_researched_at, status. KnowledgeEntities: id, project_id, kind, name, status,
priority, created_at, updated_at, evidence(JSON), source_key.

Artifacts / Functions / Libraries / Modules / Findings / Hypotheses / Experiments /
InterestingLocations / FalsePositives / ResearchHistory / Notes — нормализованные
таблицы принадлежности с PK/FK id. Общие поля хранятся один раз в KnowledgeEntities.
Например, полное представление Notes получается через JOIN:

```sql
SELECT e.id, e.created_at, e.priority,
       json_extract(e.evidence, '$.category') AS category,
       json_extract(e.evidence, '$.body') AS body
FROM Notes n JOIN KnowledgeEntities e ON e.id = n.id;
```

Relationships: id, project_id, source_id, target_id, relation, reason, created_at;
оба endpoint имеют составные FK (id, project_id). IngestedJobs хранит терминальные
job_id, уже перенесённые в знания. KnowledgeSchema=1 версионирует модуль отдельно
от неизменённого PRAGMA user_version=1 для очереди v0.1.
