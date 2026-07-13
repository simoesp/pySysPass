# PHP compatibility fixtures

`php_syspass_3211_crypto.json` contains synthetic test data authored by a real
sysPass PHP 3.2.11 installation. The account ciphertext was produced through
PHP's `account/saveCreate` endpoint, not by pySysPass.

The passwords and salt in this fixture are intentionally public test constants.
They must never be reused outside this disposable compatibility fixture. The
fixture is deliberately minimized instead of storing a full database dump, so
CI tests the cryptographic and profile wire formats without carrying unrelated
database state or requiring MySQL.

`php_syspass_3211_acl.json` records the ACL-relevant rows from a synthetic
100-account corpus plus the account IDs returned by PHP's paginated web search
for all ten fixture users. It deliberately omits passwords, encrypted account
payloads, custom-field values, and unrelated database columns. The offline test
reconstructs those rows in SQLite and compares `AccountService._access_filter`
against PHP's recorded result for every user.
