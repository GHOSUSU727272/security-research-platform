# SQLite Analyzer

SQLite открывается mode=ro с query_only=ON и trusted_schema=OFF. Извлекаются sqlite_schema (tables, indexes, triggers, views), table_xinfo, foreign_key_list и index_xinfo, user_version, application_id и page_count.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  sqlite:
    max_records: 10000
    instruction_budget: 1000000
```

Приложенческие таблицы и views не запрашиваются, триггеры не запускаются, расширения не загружаются. Виртуальные таблицы инвентаризируются по схеме без инициализации модуля. Для live WAL-баз используйте consistent backup: core.discovery делает sqlite3 backup с таймаутом. Неподдерживаемая/зашифрованная база даёт диагностическую ошибку.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

