SHELL := /bin/bash

.PHONY: setup sast sca dast up down re-build re-clean secure vuln test

setup:
	@echo "Installing node deps for apps..."
	cd apps/vulnerable-webapp && npm install
	cd apps/secure-webapp && npm install
	@echo "Done."

sast:
	@echo "Running Semgrep..."
	semgrep --config tooling/configs/semgrep.yml --error --json --output analysis/sast/semgrep.json || true
	@echo "Running ESLint on Node apps..."
	cd apps/vulnerable-webapp && npx eslint .
	cd apps/secure-webapp && npx eslint .
	@echo "SAST complete."

sca:
	@echo "Running Trivy filesystem scan..."
	trivy fs --scanners vuln,secret,misconfig --format sarif --output analysis/sca/trivy-fs.sarif .
	@echo "SCA complete."

dast:
	@echo "Starting vulnerable app for DAST..."
	docker compose up -d vulnerable-webapp
	@echo "Waiting for app to be ready..."
	sleep 5
	@echo "Running ZAP Baseline..."
	docker run --rm --network host -v $$(pwd)/tooling/configs:/zap/wrk/:rw -v $$(pwd)/analysis/dast:/zap/reports:rw -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://localhost:3000 -r /zap/reports/zap-baseline.html -J /zap/reports/zap-baseline.json -c /zap/wrk/zap-baseline.conf || true
	@echo "Stopping app..."
	docker compose down

up:
	docker compose up -d

down:
	docker compose down

re-build:
	@echo "Building reverse engineering challenge..."
	cd apps/reverse-engineering/challenge-src && make
	@echo "Built artifacts in apps/reverse-engineering/challenge-src/bin"

re-clean:
	cd apps/reverse-engineering/challenge-src && make clean

secure:
	cd apps/secure-webapp && npm start

vuln:
	cd apps/vulnerable-webapp && npm start

test:
	cd apps/vulnerable-webapp && npm test
	cd apps/secure-webapp && npm test

lint:
	cd apps/vulnerable-webapp && npx eslint .
	cd apps/secure-webapp && npx eslint .

format:
	cd apps/vulnerable-webapp && npx prettier --write .
	cd apps/secure-webapp && npx prettier --write .
