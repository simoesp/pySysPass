.PHONY: codeql-install codeql codeql-clean

codeql-install:
	./scripts/codeql-local.sh install

codeql:
	./scripts/codeql-local.sh analyze

codeql-clean:
	./scripts/codeql-local.sh clean
