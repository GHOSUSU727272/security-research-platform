"""Portable per-file checkpoints and live counters for independent analyzers."""

import sqlite3

PLUGIN_TABLES = ("PluginFileCache", "PluginProgress")


def initialize_plugins(db: sqlite3.Connection) -> None:
    """Install additive tables, preserving every previous schema contract."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS PluginFileCache(
            namespace TEXT NOT NULL, plugin TEXT NOT NULL, path TEXT NOT NULL,
            digest TEXT NOT NULL, signature TEXT NOT NULL, result TEXT NOT NULL,
            updated REAL NOT NULL, PRIMARY KEY(namespace,plugin,path)
        );
        CREATE TABLE IF NOT EXISTS PluginProgress(
            namespace TEXT NOT NULL, plugin TEXT NOT NULL, status TEXT NOT NULL,
            updated REAL NOT NULL, progress TEXT NOT NULL,
            PRIMARY KEY(namespace,plugin)
        );
    """)
