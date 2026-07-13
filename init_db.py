#!/usr/bin/env python3
"""
Initialize sysPass Python database with PHP-compatible schema.
This creates all tables exactly as they exist in the PHP version.
"""
import sys
from app.db.bootstrap import bootstrap_database

def init_database():
    """Initialize database with PHP-compatible schema."""
    try:
        initialized = bootstrap_database()
        if initialized:
            print("Database initialized successfully with PHP-compatible schema.")
        else:
            print("Database already contains the required sysPass schema.")
        return True
    except Exception as exc:
        print(f"Error initializing database: {exc}")
        return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
