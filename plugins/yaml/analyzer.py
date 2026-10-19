"""Independent safe YAML document analysis using the shared configuration parser."""

from plugins.config.analyzer import ConfigAnalyzer


class YAMLAnalyzer(ConfigAnalyzer):
    """Extract YAML parameters, document structure, types and alias cycles."""

    name = "yaml"
    formats = {"yaml", "yml"}
