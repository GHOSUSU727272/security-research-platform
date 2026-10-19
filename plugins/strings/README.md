# Strings Analyzer

Извлекаются ASCII, UTF-8 и UTF-16LE/BE, включая оба смещения выравнивания UTF-16. Для каждой строки сохраняются исходное смещение в байтах, текст, кодировка и несколько категорий: URL, IP, путь, Unix socket, filename, environment, log_message, library.

## Настройка

В YAML платформы:

```yaml
plugin_options:
  strings:
    min_length: 4
    max_length: 4096
    max_records: 10000
    encodings: [ascii, utf-8, utf-16-le, utf-16-be]
```

Классификация эвристическая: строка /run/ считается кандидатом Unix socket, а не подтверждением наличия сокета. Unicode в произвольных бинарных данных может дать шум. ASCII и UTF-8 могут представлять одни байты; кодировка сохраняет происхождение наблюдения. Длинные последовательности разбиваются по max_length. Результат strings включает точные offsets; никакие URL не открываются.

Чтение потоковое блоками 64 KiB: UTF-последовательности на границе блоков
сохраняются incremental decoder. Бюджет записей распределён между кодировками
и выравниваниями, чтобы ASCII не вытеснял все Unicode-наблюдения.

Общие параметры, отмена, checkpoints, регистрация и CLI описаны в
[руководстве анализаторов](../../docs/analyzers.md). Реализация: [analyzer.py](analyzer.py).
Собственные проверки: [tests/test_plugins.py](../../tests/test_plugins.py); для Linux и Ghidra есть реальные runtime-тесты.
