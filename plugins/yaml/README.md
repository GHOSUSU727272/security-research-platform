# YAML Analyzer

Самостоятельно зарегистрированный YAML анализатор использует тот же безопасный извлекатель структуры, что Config Analyzer. Поддерживаются несколько документов, scalar types, sequences, mappings и циклические aliases; Python objects не конструируются.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  yaml:
    max_records: 10000
    max_depth: 64
    redact_secrets: true
```

По умолчанию отбираются .yaml/.yml; для другого имени задайте format: yaml и files/include. parameters включают индекс YAML-документа. Для одинакового файла config и yaml имеют разную provenance, но Knowledge связывает их с одной file/content identity.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

