# PHP public-link snapshot reader

Native sysPass public links store a PHP-serialized `SP\Core\Crypt\Vault` in
`PublicLink.data`. That Vault holds Defuse ciphertext and a password-protected
key. Its password is the hexadecimal SHA-1 of the configured `passwordSalt`
concatenated with the stored link hash, as implemented by PHP `PublicLinkKey`.
The decrypted plaintext is a serialized `SP\DataModel\AccountExtData` snapshot.

The Python reader uses a bounded data-only parser. It permits only the native
Vault/account classes and supported primitive/array values; it never creates
PHP objects or executes serialization hooks. Bad framing, references, unknown
classes, duplicate properties, oversized/deep payloads, wrong salts/hashes,
modified ciphertext and mismatched account IDs are rejected without consuming
a view. Defuse authentication is checked before reading account fields.

## Access behavior

`GET /api/v1/public-links/{hash}/access` now recognizes native PHP Vaults. It
returns the authenticated snapshot's account metadata, `password`, and
`category_name`/`client_name`. PHP's link query selects names rather than IDs,
so absent category/client IDs are returned as null rather than invented IDs.
PHP/PDO numeric string IDs and UTF-8 field values are supported.

As in PHP `AccountController::viewLinkAction`, this is the frozen snapshot:
later account edits are not reflected. A snapshot can still be served when
the live account row is absent. Expiry and the atomic view limit gate still
apply. Successful native reads update the link counters and, when the account
exists, its view/decryption counters. Possession of the public link grants
access to the snapshot password, as it does in PHP.

Native Vaults report `has_password=false`: their encrypted data is not a
separate access password. Legacy Python links retain their existing access
password checks and metadata-only responses; their `password` response value
is null. No database columns or encrypted payloads are rewritten.

## Fixture provenance and regeneration

`tests/fixtures/php_public_link_vault.json` contains synthetic data authored
by the upstream `AccountExtData`, `PublicLinkKey`, and `Vault::saveData` classes
with Defuse 2.4.0. It is not a fixture captured through a live PHP UI. Its
source commit is recorded in the JSON. The generator first verifies the
result with PHP's native Vault reader.

With the two upstream checkouts available, regenerate it using PHP with OpenSSL:

```bash
php scripts/generate-php-public-link-fixture.php /path/to/sysPass /path/to/php-encryption \
  > tests/fixtures/php_public_link_vault.json
```

Use sysPass commit `9d0e169d2163897238877fb65130db47fe1ddcfa` and Defuse
`f53396c2d34225064647a05ca76c1da9d99e5828` (v2.4.0). Random Defuse keys and Vault
timestamps intentionally change on regeneration. The committed fixture runs
in pytest without requiring PHP or a database service.

## Remaining interoperability work

This implements native reads only. Python link creation still uses the legacy
format; native Vault writing and verification through PHP's link-creation/UI
flows remain open. Existing native links require the matching PHP password
salt in runtime configuration. Missing/wrong salts fail closed; no fallback
key or empty salt is used.
