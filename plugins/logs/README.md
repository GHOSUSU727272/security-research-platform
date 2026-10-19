# Logs Analyzer

Поддерживаются RFC3164/RFC5424 syslog, text logs, journal JSON/JSONL, текстовый journal export. Бинарные .journal читаются стандартным journalctl --file --output=json. Исходные поля и позиция события сохраняются, severity нормализуется.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  logs:
    max_records: 10000
    encoding: utf-8
    timeout: 120
    max_output_bytes: 33554432
```

Для текстового journal export можно задать format: journal-export. Binary fields внутри journal export требуют преобразования journalctl в JSON; ошибка не маскируется. Для нестандартных имён используйте include. Events находятся в SQLite evidence; high-severity события создают InterestingLocations для ручной проверки. Severity не подтверждает уязвимость.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

