# Анализаторы v0.4

Все 11 плагинов зарегистрированы автоматически через существующий Plugin API.
Контракты v0.1–v0.3, entry points, команды и схемы памяти сохранены. Ghidra и
journalctl — внешние установленные инструменты; их отсутствие даёт явную ошибку.
Подробности каждого модуля находятся в plugins/<имя>/README.md.

## Запуск

```bash
research open KESL --root /path/to/snapshot/target
research --config config/analyzers.yaml start --plan config/analyzers-plan.yaml
research progress
research stop
research --config config/analyzers.yaml resume
research dashboard --engine --output Research-Engine.html
research export --output KESL.rpk.zip
```

Глобальные --config, --workspace, --project ставятся перед командой. start/resume
работают в foreground; вторым терминалом можно читать прогресс и запросить stop.
Исходные scan/enqueue/run также поддерживают новые имена --plugin.
Восстановление после перезапуска использует resume, task IDs и durable SQLite.

## Конфигурация и ограничения ресурсов

plugin_options.<имя> содержит настройки анализатора. Общие параметры файловых
плагинов: include/exclude (glob), files (точные относительные пути без обхода всего
дерева), max_file_bytes (по умолчанию Context.max_file_bytes), max_files (10000),
max_result_bytes (64 MiB). Директории из excluded и симлинки пропускаются.
Размеры/ошибки/ограничения явно отражаются в statistics, warnings и truncated.
При ошибке отдельного файла остальные продолжают обрабатываться; итоговый plugin
status становится partial. Завершённая задача с partial не означает полный анализ.

TaskSpec.options — необязательное аддитивное поле: настройки только этого плагина
поверх общих plugin_options. Старые YAML планы и сериализованные Context работают.
Подготовщик KESL формирует отдельную задачу на файл/плагин. Это ограничивает размер
одного результата и позволяет WorkerPool распределять файлы, а не только плагины.
Для больших файлов увеличивайте лимиты осознанно; достигнутый лимит не скрывается.
Ghidra по умолчанию ограничивает heap до 768 MiB через GHIDRA_HEADLESS_MAXMEM
(официальный launcher Ghidra 12.1.3); max_heap_mb настраивается. Число worker'ов
и память JVM нужно согласовывать с RAM VM.

## Checkpoints и отмена

FileAnalyzer хеширует файл и проверяет его размер/mtime после разбора. Успешный
результат коммитится в PluginFileCache до перехода к следующему файлу; ключ включает
задачу, имя плагина, путь, SHA-256 и signature параметров/версии. При restart
кэш используется только после повторной проверки содержимого. Неуспешный файл
не кешируется. Если файл менялся, используйте стабильный снимок.

PluginProgress хранит статус, счётчики и текущий файл. Engine сохраняет периодические
контрольные точки оркестрации каждые N минут. Они не откатывают более новые успешные
пофайловые транзакции. Ошибка текущего файла при аварии может привести к повторному
разбору этого файла; атомарная публикация результата предотвращает дублирование
предметных сущностей. Supervisor задаёт timeout и прекращает worker process group;
CPU-bound native parser может потребовать принудительного завершения. Внутри
worker внешние backend-процессы остаются в его группе для общей уборки.

Для Memory live-выборки всегда свежие, PID starttime проверяется заново. Успешные
диагностические samples сохраняются; checkpoint не используется как ложное
актуальное состояние процесса. Импорт snapshot помечается отдельно.

## Знания и отчёты

Raw records и файлы сохраняются в SQLite и в analysis-result Artifact Manager.
ELF/Imports/CFG/Ghidra связываются через Modules, Functions, Libraries, file snapshots
и SHA-256 content identities. Memory связывает process maps и библиотеки.
Events журналов сохраняются полностью в evidence; высокие severity порождают
InterestingLocations с причиной ручной проверки. Review статусы не меняются
автоматически. Повторная доставка job идемпотентна.

Для CFG/Callgraph/Ghidra Engine сохраняет отдельные graph-json и graph-html blobs.
В HTML — SVG обзор, таблица рёбер и полный собранный JSON, без внешних скриптов.
Dashboard показывает задачу/плагин, статус, длительность, обработанные файлы,
ошибки, статистику, диагностические предупреждения, артефакты и worker logs.
Это offline snapshot; повторная команда обновляет его. Логи worker ограничены
64 KiB на попытку; timeline сохраняет факт запуска, завершения, ошибки и отмены.

Архив v3 включает PluginFileCache/PluginProgress. Импортируются также архивы v1/v2;
старый runtime не обязан понимать новый архив. Архив переносит память/результаты,
логи и checkpoints, а исходный target переносится отдельно и привязывается через
research open --root. Ghidra path и live PID машинозависимы: для новой машины
подготовьте новый план. Общий лимит portable archive унаследован: 512 MiB,
превышение приводит к явной ошибке. Анализаторы не изменяют этот контракт v0.2.

## Обнаружение KESL на Linux

```bash
# Каталог вывода должен ещё не существовать.
sudo .venv/bin/python -m core.discovery --package kesl --output "$PWD/kesl-snapshot" --snapshot
.venv/bin/python -m core.prepare_kesl kesl-snapshot --output config/discovered --headless /actual/path/support/analyzeHeadless
research create KESL
research open KESL --root "$PWD/kesl-snapshot/target"
research --config config/discovered/kesl.yaml start --plan config/discovered/kesl-plan.yaml --prepare
research --config config/discovered/kesl.yaml resume
```

sudo нужен лишь если реальная установка закрыта для пользователя. Инвентаризация
получает пути от dpkg-query -L, затем find/readlink/ps/ss; стандартное расположение
KESL не предполагается. Снимок ограничен 4 GiB (изменяется --max-bytes). SQLite
копируется backup API, занятые базы с timeout отражаются в discovery warnings.
Сборщик передаёт созданный каталог исходному SUDO_UID; сами приложения и сервисы
не меняются. В discovery.json — пути, размеры, категории, версия пакета, PID,
команды процессов, сокеты, SHA-256 снимков и все ошибки. Нет чтения /proc/PID/mem.

## Проверка

```bash
pytest -q
GHIDRA_HEADLESS=/actual/path/support/analyzeHeadless pytest tests/test_plugins.py -q
ruff check .
ruff format --check .
mypy .
```

Ghidra runtime test компилирует поставляемый Java post-script. Linux тесты читают
только диагностические данные собственного процесса и компилируют безопасную C
фикстуру; целевой продукт не исполняется. Многочасовой soak-test не заявляется.

Официальные интерфейсы: [Ghidra HeadlessScript](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessScript.html),
[BasicBlockModel](https://ghidra.re/ghidra_docs/api/ghidra/program/model/block/BasicBlockModel.html),
[Capstone Python API](https://www.capstone-engine.org/lang_python.html).

