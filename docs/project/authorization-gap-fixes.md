# Authorization and PHP bootstrap fixes

The fixes on `fix/authorization-and-php-gaps` close four confirmed gaps:

- JWT-authenticated routes reload the PHP user row, reject disabled/deleted
  users, and honor current application/account admin flags.
- File and public-link routes enforce PHP profile gates and account ACLs.
  Nested file/link IDs must belong to the account in the URL. File writes
  require edit access; read-only shares retain download access.
- Public-link reads atomically enforce expiry and view limits and increment
  both PHP view counters. New links use `publinks_max_views`.
- Bootstrap creates the two canonical PHP account views. Alembic revision
  `002` repairs missing views without overwriting existing views or tables.

## Upgrade notes

Run `alembic upgrade head` with an online connection to the target database.
Revision `002` requires inspection of existing objects. A physical table named
`account_data_v` or `account_search_v` stops repair and needs investigation.
Downgrading to `001` preserves PHP-owned views; downgrading to `base` removes
views along with the rest of the canonical schema.

PHP treats `maxCountViews=0` as exhausted. Earlier Python-created zero-limit
links now stop serving and must be recreated with a positive configured limit.
Existing links and encrypted payloads are not rewritten.

## Validation

- Full pytest suite: 272 passed, 2 skipped (external PHP fixtures unavailable
  at the paths expected by those tests).
- Ruff and `git diff --check`: passed.
- Disposable MySQL 8: 27 physical tables and both views; bootstrap idempotence;
  repair of one missing view; upgrade from `001` preserving an existing view;
  full downgrade and fresh upgrade to `head`.
- Graphify AST graph refreshed. SQL extraction was unavailable because its
  optional parser was not installed; SQL was validated directly on MySQL.

## Remaining work

PHP stores a serialized Vault in `PublicLink.data`; the existing Python helper
uses that column for a link password. Full public-link format interoperability
is not established by these fixes and needs PHP-authored fixtures before a
format migration is attempted.

Real-browser login/sharing coverage and external PHP fixture coverage remain
separate work.

## Frontend build follow-up

Docker now copies both package manifests before `npm ci --legacy-peer-deps`.
Its context excludes host dependencies, compiled assets, test coverage, logs,
and local environment files. CI installs the same lockfile, runs frontend lint,
unit tests and a production build, and builds the actual frontend container.
Node 22.23.2 is recorded in `frontend/.nvmrc` and matches the Docker image;
installation instructions use that version and the lockfile install command.

Validation: clean install without lockfile changes; 22 frontend tests passed;
ESLint reported zero errors and 524 existing warnings; Vite production build
and Docker build passed. These checks do not replace real-browser tests.
