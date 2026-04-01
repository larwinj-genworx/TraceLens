.PHONY: run dev lint test docker-up docker-down

run:
	uvicorn src.main:app --host 0.0.0.0 --port 8080

dev:
	uvicorn src.main:app --host 0.0.0.0 --port 8080 --reload

lint:
	python -m compileall -q src

test:
	python -m compileall -q src

docker-up:
	docker compose up --build

docker-down:
	docker compose down -v
