# Расширение

Рабочие встроенные анализаторы перечислены в
[plugins/README.md](../plugins/README.md); source/dynamic и установленные entry-point
плагины сохраняют прежний интерфейс.

Плагин — класс с docstring и методом:

```python
from core.models import Context


class ExamplePlugin:
    """Collect additional evidence without modifying the target."""

    async def run(self, context: Context) -> dict[str, object]:
        """Return JSON-serializable evidence and review candidates."""
        return {"findings": [], "warnings": [], "truncated": False}
```

Зарегистрируйте его в pyproject.toml собственного пакета:

```toml
[project.entry-points."research_platform.plugins"]
example = "my_package.plugin:ExamplePlugin"
```

Установите пакет в тот же venv, затем `research scan --plugin example`.
Плагины являются доверенным локальным кодом. Загрузка entry points выполняет
их импорт; автоматической загрузки кода из исследуемого проекта нет.

Каждая находка: rule, path, line, reason, priority (1–3; меньше — важнее).
В reason объясняйте наблюдение, а не утверждайте неподтверждённую уязвимость.
Соблюдайте отмену asyncio, периодически отдавайте управление, ограничивайте память.
Для тяжёлых вычислений нужен отдельный процесс с принудительным завершением.
Возвращайте полные результаты; транзакцию и статус задачи сохраняет scheduler.
Плагин может быть повторён после сбоя: побочные эффекты должны быть идемпотентны.

Для пофайлового анализа наследуйте `plugins.common.FileAnalyzer`: обход, cache,
отмена и прогресс уже реализованы. Другие плагины используют
`database.checkpoints.CheckpointClient(context, context.task_id, plugin_name)`:
`await client.request("progress", status="running", progress=json.dumps(counters))`,
`request("put", path=..., digest=..., signature=..., result=json.dumps(detail))`
и `request("get", path=..., digest=..., signature=...)` (строка JSON или None).
Освобождайте client.close() в finally. Ошибку PersistenceError нужно передавать
Research Engine, а не превращать в предупреждение разбора файла.

В worker-процессе клиент использует очередь единственного writer supervisor.
Не открывайте `context.checkpoint_db` для прямой записи и не сохраняйте временные
checkpoint_endpoint/checkpoint_token. Эти поля выдаёт ProcessExecutor на попытку;
старые Context без них используют локальный backend. Схема, подтверждение commit
и поведение при сбоях описаны в [SQLite writer](sqlite-writer.md).
