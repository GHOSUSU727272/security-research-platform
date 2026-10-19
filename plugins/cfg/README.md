# Control Flow Graph

Capstone строит блоки исполнимых ELF sections и branch/fallthrough edges; возвращает инструкции каждого блока, адреса, переходы и вызовы. Возвраты заканчивают блок. Indirect targets остаются unresolved.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  cfg:
    max_instructions: 100000
```

Поддерживаются x86/x86-64/AArch64. Линейная дизассембляция может включать embedded data; не восстановленные границы не объявляются доказанными функциями. Для прочих архитектур используйте ghidra, который также экспортирует CFG. В Engine публикуются JSON и HTML. Ограничение инструкций явно помечает truncated.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.

