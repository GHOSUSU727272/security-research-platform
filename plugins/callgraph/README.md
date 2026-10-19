# Call Graph

Для ELF используется Capstone: прямые вызовы и неразрешённые indirect calls; для Python — AST без импорта и исполнения. Symbol table помогает назвать функции; для stripped-бинарников сохраняются адресные обозначения.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  callgraph:
    max_instructions: 100000
    max_records: 100000
```

Research Engine публикует JSON и автономный HTML/SVG через Artifact Manager. Python рёбра синтаксические: aliases, dynamic dispatch и исполнимость не доказываются. Поддержка ELF машин: x86, x86-64, AArch64. Другие машины дают явную ошибку с рекомендацией Ghidra. JSON сохраняет всю собранную информацию; обзор SVG ограничен 200 узлами/1000 рёбрами.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

