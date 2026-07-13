"""Small deterministic parser for the sysPass MySQL schema snapshot.

This intentionally parses only the CREATE TABLE shape used by upstream
sysPass. It is not intended to be a general-purpose SQL parser.
"""

from dataclasses import dataclass
from pathlib import Path
import re


_CREATE_TABLE_RE = re.compile(
    r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?`?([A-Za-z][A-Za-z0-9_]*)`?\s*\(",
    re.IGNORECASE,
)
_COLUMN_RE = re.compile(
    r"^\s*`?([A-Za-z][A-Za-z0-9_]*)`?\s+"
    r"([A-Za-z]+)(?:\(([^)]*)\))?\s*(.*?)(?:,)?\s*$",
    re.IGNORECASE,
)
_NON_COLUMN_PREFIXES = {
    "constraint",
    "foreign",
    "fulltext",
    "index",
    "key",
    "primary",
    "unique",
}


@dataclass(frozen=True)
class SchemaColumn:
    name: str
    sql_type: str
    length: str | None
    nullable: bool
    unsigned: bool
    default: str | None
    autoincrement: bool


@dataclass(frozen=True, order=True)
class SchemaIndex:
    name: str | None
    columns: tuple[str, ...]
    unique: bool = False
    primary: bool = False


@dataclass(frozen=True, order=True)
class SchemaForeignKey:
    name: str | None
    columns: tuple[str, ...]
    referred_table: str
    referred_columns: tuple[str, ...]
    on_delete: str | None = None
    on_update: str | None = None


def _normalized_default(suffix: str) -> str | None:
    match = re.search(
        r"\bdefault\s+((?:'[^']*')|(?:\"[^\"]*\")|(?:[^\s,]+))",
        suffix,
        re.IGNORECASE,
    )
    if not match:
        return None
    value = match.group(1).strip("'\"").lower()
    return None if value == "null" else value


def _parenthesized_body(sql: str, start: int) -> str:
    depth = 1
    quote: str | None = None
    escaped = False
    for index in range(start, len(sql)):
        char = sql[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return sql[start:index]
    raise ValueError("unterminated CREATE TABLE statement")


def _split_clauses(body: str) -> list[str]:
    clauses: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    for index, char in enumerate(body):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in {"'", '"', "`"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            clauses.append(body[start:index].strip())
            start = index + 1
    tail = body[start:].strip()
    if tail:
        clauses.append(tail)
    return clauses


def _column_names(value: str) -> tuple[str, ...]:
    names = re.findall(r"`?([A-Za-z][A-Za-z0-9_]*)`?(?:\(\d+\))?", value)
    if not names:
        raise ValueError(f"unable to parse indexed columns: {value!r}")
    return tuple(names)


def parse_mysql_constraints(
    path: Path,
) -> tuple[dict[str, set[SchemaIndex]], dict[str, set[SchemaForeignKey]]]:
    sql = path.read_text(encoding="utf-8")
    indexes: dict[str, set[SchemaIndex]] = {}
    foreign_keys: dict[str, set[SchemaForeignKey]] = {}
    for match in _CREATE_TABLE_RE.finditer(sql):
        table_name = match.group(1)
        if table_name in {"account_data_v", "account_search_v"}:
            continue
        body = _parenthesized_body(sql, match.end())
        table_indexes: set[SchemaIndex] = set()
        table_foreign_keys: set[SchemaForeignKey] = set()
        for clause in _split_clauses(body):
            if re.match(r"fulltext\s+(?:key|index)\b", clause, re.I):
                raise ValueError(f"FULLTEXT index requires explicit parser support: {clause}")
            primary = re.match(r"primary\s+key\s*\((.*)\)\s*$", clause, re.I | re.S)
            if primary:
                table_indexes.add(SchemaIndex("PRIMARY", _column_names(primary.group(1)), primary=True))
                continue
            index = re.match(
                r"(unique\s+)?(?:key|index)\s+`?([^`\s]+)`?\s*\((.*)\)\s*$",
                clause,
                re.I | re.S,
            )
            if index:
                table_indexes.add(
                    SchemaIndex(index.group(2), _column_names(index.group(3)), unique=bool(index.group(1)))
                )
                continue
            foreign_key = re.match(
                r"(?:constraint\s+`?([^`\s]+)`?\s+)?foreign\s+key\s*\(([^)]+)\)"
                r"\s+references\s+`?([^`\s(]+)`?\s*\(([^)]+)\)(.*)",
                clause,
                re.I | re.S,
            )
            if foreign_key:
                tail = foreign_key.group(5)
                on_delete = re.search(r"on\s+delete\s+(cascade|restrict|set\s+null|no\s+action)", tail, re.I)
                on_update = re.search(r"on\s+update\s+(cascade|restrict|set\s+null|no\s+action)", tail, re.I)
                table_foreign_keys.add(
                    SchemaForeignKey(
                        name=foreign_key.group(1),
                        columns=_column_names(foreign_key.group(2)),
                        referred_table=foreign_key.group(3),
                        referred_columns=_column_names(foreign_key.group(4)),
                        on_delete=on_delete.group(1).lower() if on_delete else None,
                        on_update=on_update.group(1).lower() if on_update else None,
                    )
                )
        indexes[table_name] = table_indexes
        foreign_keys[table_name] = table_foreign_keys
    return indexes, foreign_keys


def parse_mysql_tables(path: Path) -> dict[str, dict[str, SchemaColumn]]:
    sql = path.read_text(encoding="utf-8")
    tables: dict[str, dict[str, SchemaColumn]] = {}
    for match in _CREATE_TABLE_RE.finditer(sql):
        table_name = match.group(1)
        if table_name in {"account_data_v", "account_search_v"}:
            continue
        body = _parenthesized_body(sql, match.end())
        columns: dict[str, SchemaColumn] = {}
        for line in body.splitlines():
            quoted_identifier = line.lstrip().startswith("`")
            column_match = _COLUMN_RE.match(line)
            if not column_match:
                continue
            name, sql_type, length, suffix = column_match.groups()
            if not quoted_identifier and (
                name.lower() in _NON_COLUMN_PREFIXES
                or name.lower() in {"on", "references"}
            ):
                continue
            columns[name] = SchemaColumn(
                name=name,
                sql_type=sql_type.lower(),
                length=length,
                nullable=re.search(r"\bnot\s+null\b", suffix, re.IGNORECASE) is None,
                unsigned=re.search(r"\bunsigned\b", suffix, re.IGNORECASE) is not None,
                default=_normalized_default(suffix),
                autoincrement=re.search(r"\bauto_increment\b", suffix, re.IGNORECASE) is not None,
            )
        tables[table_name] = columns
    return tables


def normalized_sql(path: Path) -> str:
    """Normalize line endings only; semantic whitespace remains significant."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")
