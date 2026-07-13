"""Load SQLAlchemy model modules for registry side effects."""

from app.models.account import *  # noqa: F401,F403
from app.models.account_sharing import *  # noqa: F401,F403
from app.models.custom_field import *  # noqa: F401,F403

from app.db.base import apply_php_mysql_table_options

apply_php_mysql_table_options()
