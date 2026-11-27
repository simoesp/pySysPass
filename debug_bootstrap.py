#!/usr/bin/env python
"""Debug MySQL bootstrap."""
from sqlalchemy import create_engine, text
from app.db.bootstrap import bootstrap_database

engine = create_engine('mysql+pymysql://root:root@127.0.0.1:3306/')
import secrets
db_name = f'pysyspass_test_{secrets.token_hex(4)}'
with engine.connect() as conn:
    conn.execute(text(f'CREATE DATABASE `{db_name}`'))
engine2 = create_engine(f'mysql+pymysql://root:root@127.0.0.1:3306/{db_name}')
bootstrap_database(engine2)
print('Bootstrap done')

from sqlalchemy import inspect
insp = inspect(engine2)
print('Tables:', insp.get_table_names())
print('Views:', insp.get_view_names())