from sqlalchemy import create_engine
from sqlalchemy import event
from sqlalchemy.orm import Session, declarative_base, sessionmaker
from sqlalchemy.types import LargeBinary as SA_LargeBinary, TypeDecorator
from sqlalchemy import Integer, SmallInteger
from sqlalchemy.dialects import mysql
from app.core.config import settings
import re


class FlexibleBinary(TypeDecorator):
    """Store strings and bytes in a binary-compatible column without breaking inserts."""

    impl = SA_LargeBinary
    cache_ok = True

    def __init__(self, length=None, *, mysql_type=None):
        super().__init__(length=length)
        self.mysql_type = mysql_type

    def load_dialect_impl(self, dialect):
        if dialect.name == "mysql" and self.mysql_type is not None:
            return dialect.type_descriptor(self.mysql_type)
        return super().load_dialect_impl(dialect)

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value)
        return bytes(str(value).encode("utf-8"))

    def process_result_value(self, value, dialect):
        return value if value is None else bytes(value)


def mysql_integer(*, width: int = 10, unsigned: bool = True):
    return Integer().with_variant(
        mysql.INTEGER(display_width=width, unsigned=unsigned), "mysql"
    )


def mysql_mediumint(*, width: int = 8, unsigned: bool = True):
    return Integer().with_variant(
        mysql.MEDIUMINT(display_width=width, unsigned=unsigned), "mysql"
    )


def mysql_smallint(*, width: int = 5, unsigned: bool = True):
    return SmallInteger().with_variant(
        mysql.SMALLINT(display_width=width, unsigned=unsigned), "mysql"
    )


def mysql_tinyint(*, width: int = 1, unsigned: bool = True):
    return SmallInteger().with_variant(
        mysql.TINYINT(display_width=width, unsigned=unsigned), "mysql"
    )

engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True) if settings.DATABASE_URL else None

SCHEMA_STATEMENT_RE = re.compile(
    r"^\s*(?:"
    r"create|alter|drop|truncate|rename|"
    r"grant|revoke"
    r")\b",
    re.IGNORECASE,
)


class SchemaMutationError(RuntimeError):
    """Raised when Python tries to mutate the PHP-owned sysPass schema."""


class GuardedSession(Session):
    pass


def _schema_guard_enabled() -> bool:
    return bool(settings.SQLALCHEMY_SCHEMA_GUARD)


if engine is not None:
    @event.listens_for(engine, "before_cursor_execute")
    def prevent_schema_mutations(conn, cursor, statement, parameters, context, executemany):
        if not _schema_guard_enabled():
            return

        if SCHEMA_STATEMENT_RE.match(statement):
            raise SchemaMutationError(
                "SQLAlchemy schema-guard mode is enabled; refusing database schema change."
            )


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=GuardedSession)

Base = declarative_base()

PHP_MYSQL_TABLE_OPTIONS = {
    "engine": "InnoDB",
    "charset": "utf8",
    "collate": "utf8_unicode_ci",
}


def apply_php_mysql_table_options(metadata=Base.metadata) -> None:
    """Apply upstream PHP storage options to mapped physical tables."""
    for table in metadata.tables.values():
        if table.info.get("is_view"):
            continue
        mysql_options = table.dialect_options["mysql"]
        for key, value in PHP_MYSQL_TABLE_OPTIONS.items():
            mysql_options[key] = value

def get_db():
    if engine is None:
        raise RuntimeError("DATABASE_URL is not configured.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
