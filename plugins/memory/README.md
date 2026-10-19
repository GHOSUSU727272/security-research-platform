# Memory Diagnostics

Читаются только maps, status, statm и smaps_rollup явно выбранных Linux PID. До и после выборки проверяется /proc/PID/stat starttime, чтобы выявить PID reuse. Доступные данные сохраняются даже при недоступности части файлов.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  memory:
    authorized: true
    pids: [1234]
    max_file_bytes: 16777216
```

Замените пример PID реально выбранным. Нет /proc/PID/mem, ptrace, дампа памяти или автоматического повышения прав. Live-данные после restart собираются заново; успешные samples сохраняются как checkpoints. snapshots: [process-diagnostics.json] разрешает импорт ранее собранного диагностического экспорта внутри root, с явной отметкой, что это не live-состояние. Ссылки mapped libraries коррелируют с Imports.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

