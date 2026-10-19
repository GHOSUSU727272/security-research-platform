# Config Analyzer

Независимое чтение YAML, JSON, XML, INI и TOML. Typed parameters содержат JSON-pointer-подобные пути, типы и значения; сохраняются контейнеры и обнаруженные YAML alias cycles. Для XML запрещены entities.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  config:
    max_records: 10000
    max_depth: 64
    redact_secrets: true
    xml_fragments: false
```

format позволяет задать формат extensionless файла. По умолчанию password/passwd/secret/token/private-key/api-key редактируются по пути параметра и имени XML элемента; custom secret_pattern расширяет правила. Это эвристическое скрытие полей, не гарантия удаления всех секретов; строки и исходные файлы обрабатываются отдельно. INI interpolation отключена.

Для нестандартных файлов KESL с несколькими корневыми элементами включайте
`xml_fragments: true`. Синтетический корень `__research_fragment__` отмечает этот
режим в извлечённой структуре; XML entities остаются запрещены.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.
