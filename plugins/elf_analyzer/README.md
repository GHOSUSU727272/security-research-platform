# ELF Analyzer

pyelftools разбирает ELF header, program headers, sections, symbol tables, dynamic tags, relocations, notes и GNU Build ID. Требования и определения GNU symbol versions включаются в evidence. Бинарник и загрузчик не исполняются.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  elf_analyzer:
    max_records: 100000
```

records[].analysis содержит header, segments, sections, symbols, dynamic, relocations, notes, build_ids, needed, version_requirements и version_definitions. Запись сохраняется в SQLite PluginFileCache и Artifacts Knowledge Engine. Повреждённый ELF даёт отдельную ошибку файла. Предел max_records действует на коллекции; truncated показывает неполноту.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

