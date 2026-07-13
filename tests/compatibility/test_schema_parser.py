from pathlib import Path

import pytest

from tests.compatibility.schema_parity import SchemaIndex, parse_mysql_constraints


def _schema(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "schema.sql"
    path.write_text(f"CREATE TABLE `Demo` ({body});", encoding="utf-8")
    return path


def test_prefix_index_columns_are_parsed_without_truncation(tmp_path):
    path = _schema(
        tmp_path,
        "`id` int NOT NULL, `name` varchar(255), KEY `idx_Demo_name` (`name`(191))",
    )

    indexes, _ = parse_mysql_constraints(path)

    assert SchemaIndex("idx_Demo_name", ("name",)) in indexes["Demo"]


def test_fulltext_indexes_fail_loudly_until_supported(tmp_path):
    path = _schema(
        tmp_path,
        "`id` int NOT NULL, `notes` text, FULLTEXT KEY `idx_Demo_notes` (`notes`)",
    )

    with pytest.raises(ValueError, match="FULLTEXT"):
        parse_mysql_constraints(path)
