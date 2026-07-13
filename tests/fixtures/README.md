# PHP compatibility fixtures

`php_syspass_3211_acl.json` records the ACL-relevant rows from a synthetic
100-account corpus plus the account IDs returned by PHP's paginated web search
for all ten fixture users. It deliberately omits passwords, encrypted account
payloads, custom-field values, and unrelated database columns. The offline test
reconstructs those rows in SQLite and compares `AccountService._access_filter`
against PHP's recorded result for every user.
