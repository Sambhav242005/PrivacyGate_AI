.PHONY: lint test

lint:
	@echo "lint: skeleton only, nothing to check yet"

test:
	@echo "test: skeleton only, nothing to run yet"

.PHONY: up down keygen
up:
	docker compose up -d

down:
	docker compose down

keygen:
	python infra/scripts/keygen.py
