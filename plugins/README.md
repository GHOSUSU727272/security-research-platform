# Рабочие плагины анализа

Все 11 плагинов автоматически зарегистрированы через Plugin.run(Context).
Настройки YAML, checkpoints, отмена через Research Engine, логи и Knowledge Engine
поддерживаются каждым анализатором. Документация каждого — README.md в его каталоге.

| Плагин | Документация |
|---|---|
| ELF | [elf_analyzer](elf_analyzer/README.md) |
| Strings | [strings](strings/README.md) |
| Imports | [imports](imports/README.md) |
| Callgraph | [callgraph](callgraph/README.md) |
| CFG | [cfg](cfg/README.md) |
| Logs | [logs](logs/README.md) |
| Config | [config](config/README.md) |
| YAML | [yaml](yaml/README.md) |
| SQLite | [sqlite](sqlite/README.md) |
| Memory | [memory](memory/README.md) |
| Ghidra | [ghidra](ghidra/README.md) |

Общее руководство: [анализаторы](../docs/analyzers.md).
Имена plugins.yaml, plugins.config, plugins.sqlite не заменяют внешние библиотеки
и прежние модули. Не добавляйте каталог plugins в PYTHONPATH напрямую.
