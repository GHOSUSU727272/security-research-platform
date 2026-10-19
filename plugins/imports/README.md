# Imports Analyzer

Из ELF динамической таблицы извлекаются DT_NEEDED, SONAME, RPATH/RUNPATH, undefined imports и global/weak exports из .dynsym. Версии символов связываются с GNU version requirements/definitions.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  imports:
    max_records: 100000
```

Это декларации зависимости и ABI-версии, а не утверждение об установленной версии пакета. ldd и целевой dynamic loader не запускаются. Плагин самостоятельно читает ELF, не требует запуска elf_analyzer. Libraries и Functions сопоставляются через общий Knowledge adapter.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

