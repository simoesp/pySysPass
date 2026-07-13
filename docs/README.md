# pySysPass Documentation

This directory organizes the project documentation by topic so the main repository README can stay focused on orientation and setup.

## Documentation Map

### Getting Started

- [../README.md](../README.md): project overview, warnings, quick start, and development basics
- [installation.md](installation.md): step-by-step installation, first-run setup, and verification
- [api/reference.md](api/reference.md): API reference and endpoint catalog

### Security

- [security/policy.md](security/policy.md): security model, key handling, and reporting guidance
- [security/scanning.md](security/scanning.md): local and CI-based security scanning workflow

### Development and Project Status

- [project/feature-completion.md](project/feature-completion.md): implemented feature notes and historical delivery summary
- [project/php-compatibility-checklist.md](project/php-compatibility-checklist.md): compatibility goals and parity checklist against sysPass PHP

## Notes

- `AGENTS.md` remains at the repository root because it is used as a tooling instruction file rather than reader-facing project documentation.
- The repository root is intentionally kept minimal. Reader-facing project documentation lives in this `docs/` tree, with `README.md` serving as the main entry point.
