# Ghidra Headless

Запускается установленный официальный support/analyzeHeadless с disposable project, -import и поставляемым Java postScript ResearchExport.java. Экспорт включает функции/сигнатуры, call references, BasicBlockModel CFG, external libraries, язык/базу образа и признак timeout анализа.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  ghidra:
    headless_path: /usr/share/ghidra/support/analyzeHeadless
    backend_timeout: 600
    max_records: 100000
    max_log_bytes: 4194304
    max_heap_mb: 768
```

Укажите фактически установленный headless_path: пример не является автоматическим поиском. Ghidra/JDK устанавливаются отдельно. Backend не запускает GUI; stdout/stderr, ошибки компиляции скрипта и отсутствие JSON диагностируются. Плагин не подменяет отсутствующий backend пустым результатом. Для дополнительных loaders задайте extensions: [.exe]. Ghidra runtime проверен на 12.1.3.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.
