# Changelog

## 0.3.0 — Research Engine

- Центральный ResearchManager поверх существующих проектов и плагинов.
- DAG задач, приоритеты, retry/backoff, таймауты, stop/cancel/resume.
- Отдельные Python worker-процессы, heartbeat, recovery, периодические checkpoints.
- Прогресс, timeline, результаты/логи/отчёты в Artifacts и Knowledge Engine.
- Новые CLI-команды и отдельный dashboard Research Engine.
- Формат архива v2 включает engine-состояние; импорт v1/v0.2 сохранён.
- Совместимость старых модулей, очереди и CLI проверяется общим набором тестов.

## 0.2.0 — Project Knowledge System

- ProjectManager: UUID, отдельные базы/очереди/вложения, активный проект и локальный root.
- KnowledgeEngine и GraphEngine: инвентарь, гипотезы, результаты, заметки, состояния,
  история и проверяемые связи.
- SQLite: 13 запрошенных предметных таблиц и служебные таблицы нормализации/ingest.
- CLI: create/open/list/export/import/dashboard/knowledge/note/graph/attach/sync,
  --workspace/--project/--legacy, project-status.
- Статический анализ дополнен объявлениями функций; результаты запусков переносятся
  в память идемпотентно. API Store/Scheduler/Plugin и схема очереди v0.1 сохранены.
- Переносимые архивы с согласованным снимком, SHA-256, FK validation и вложениями.
- Документация, dashboard и регрессионные тесты.

## 0.1.0

Первоначальная локальная платформа: очередь, индексация/AST, динамические команды,
корреляция, review history и HTML/Markdown/JSON отчёты.
