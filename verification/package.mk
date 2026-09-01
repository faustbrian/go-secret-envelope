.PHONY: docs safety

docs:
	./scripts/check-docs.sh

safety:
	./scripts/check-safety.sh
