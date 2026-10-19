"""Read-only configuration parsing with bounded structure extraction and redaction."""

import configparser
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml
from defusedxml import ElementTree

from plugins.common import FileAnalyzer, json_value, positive


def parse_config(path: Path, format_name: str, xml_fragments: bool = False) -> Any:
    """Parse supported formats without object construction, XML entities or INI interpolation."""
    text = path.read_text(encoding="utf-8-sig")
    if format_name in ("yaml", "yml"):
        return list(yaml.safe_load_all(text))
    if format_name == "json":
        return json.loads(text)
    if format_name == "toml":
        return tomllib.loads(text)
    if format_name in ("ini", "conf", "cfg"):
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = lambda optionstr: optionstr  # type: ignore[method-assign]
        parser.read_string(text)
        return {
            "DEFAULT": dict(parser.defaults()),
            **{section: dict(parser[section]) for section in parser.sections()},
        }
    if format_name == "xml":
        try:
            root = ElementTree.fromstring(text)
        except ElementTree.ParseError:
            if not xml_fragments:
                raise
            fragment = re.sub(r"^\s*<\?xml[^?]*\?>", "", text, count=1)
            root = ElementTree.fromstring(
                "<__research_fragment__>" + fragment + "</__research_fragment__>"
            )

        def element(node: Any) -> dict[str, Any]:
            """Preserve XML attributes, text and repeated children without flattening loss."""
            return {
                "tag": node.tag,
                "attributes": node.attrib,
                "text": node.text,
                "tail": node.tail,
                "children": [element(child) for child in node],
            }

        return element(root)
    raise ValueError(f"Unsupported configuration format: {format_name}")


class ConfigAnalyzer(FileAnalyzer):
    """Extract typed configuration parameters and nesting without exposing secret values by default."""

    name = "config"
    version = "2"
    formats = {"yaml", "yml", "json", "xml", "ini", "toml", "conf", "cfg"}

    def accepts(self, path: Path, options: dict[str, Any]) -> bool:
        """Use file suffix or an explicit per-run format for extensionless configuration."""
        return (
            bool(options.get("format"))
            or path.suffix.lower().lstrip(".") in self.formats
        )

    async def analyze(self, path: Path, options: dict[str, Any]) -> dict[str, Any]:
        """Walk a parsed document with cycle/depth protection and exact parameter paths."""
        format_name = str(options.get("format", path.suffix.lower().lstrip(".")))
        fragments = options.get("xml_fragments", False)
        if type(fragments) is not bool:
            raise ValueError("xml_fragments must be boolean")
        parsed = parse_config(path, format_name, fragments)
        limit = positive(options, "max_records", 10000)
        max_depth = positive(options, "max_depth", 64)
        redact = options.get("redact_secrets", True)
        if type(redact) is not bool:
            raise ValueError("redact_secrets must be boolean")
        sensitive = re.compile(
            str(
                options.get(
                    "secret_pattern",
                    "password|passwd|secret|token|private.?key|api.?key",
                )
            ),
            re.I,
        )
        parameters: list[dict[str, Any]] = []
        truncated = False

        def visit(value: Any, location: str, depth: int, ancestors: set[int]) -> None:
            """Record scalars and container types while safely handling YAML alias cycles."""
            nonlocal truncated
            if len(parameters) >= limit or depth > max_depth:
                truncated = True
                return
            entry: dict[str, Any] = {"path": location, "type": type(value).__name__}
            parameters.append(entry)
            if redact and (
                sensitive.search(location)
                or isinstance(value, dict)
                and sensitive.search(str(value.get("tag", "")))
            ):
                entry["value"], entry["redacted"] = "[REDACTED]", True
            elif isinstance(value, (dict, list)):
                if id(value) in ancestors:
                    entry["cycle"] = True
                    return
                branch = ancestors | {id(value)}
                for key, child in (
                    value.items() if isinstance(value, dict) else enumerate(value)
                ):
                    visit(
                        child,
                        location + "/" + str(key).replace("~", "~0").replace("/", "~1"),
                        depth + 1,
                        branch,
                    )
            else:
                entry["value"] = json_value(value)

        visit(parsed, "", 0, set())
        return {"format": format_name, "parameters": parameters, "truncated": truncated}
