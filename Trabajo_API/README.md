# Secure Programming Starter Kit (FastAPI + Docker + JWT)

This repository is a **teaching starter** for the course practice:
**"Building a secure API: from threat to defense"**.

## Quick start (local)

```bash
python3 -m venv .venv && source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env  # update secrets
mkdir database # generate databases folder
uvicorn app.main:app --reload
```

Visit: http://127.0.0.1:8000/docs

## Quick start (Docker)

```bash
docker build -t secure-api:dev .
docker run --rm -p 8000:8000 --env-file .env secure-api:dev
```

Or with docker-compose:

```bash
docker compose up --build
```

## Security highlights included

- Input validation with Pydantic models.
- **JWT authentication** (password hashing with `passlib[bcrypt]`).
- Role-based access (user/admin) in dependencies.
- Error handling with safe responses (no stack traces leaked).
- Basic logging.
- SQLite DB using SQLModel (swap for Postgres in prod).

## DevSecOps & scanning

- **SAST**: Bandit, Semgrep (OWASP Top 10 pack), pip-audit.
- **DAST**: OWASP ZAP Baseline scan (Docker).
- **Supply chain**: SBOM via `pip-tools`/`pipdeptree` (optional), Trivy for Docker image.

### Run scans

```bash
# Static analysis
bash scripts/scan_bandit.sh
bash scripts/scan_semgrep.sh
bash scripts/scan_pip_audit.sh

# ZAP baseline (requires Docker)
bash scripts/scan_zap_baseline.sh http://host.docker.internal:8000

# Trivy (requires Docker)
bash scripts/scan_trivy_fs.sh
bash scripts/scan_trivy_image.sh secure-api:dev
```

## Project tasks (suggested)

1. Threat model (STRIDE / OWASP) — see `docs/informe_template.md`.
2. Implement endpoints securely (auth, CRUD, roles).
3. Add request validation and secure error handling.
4. Add logging, rate limiting (bonus), and security headers.
5. Automate scans in CI (`.github/workflows/security.yml` provided).
6. Containerize and (optionally) deploy to cloud.
7. Document evidence and defend decisions.

## Educational notes

This template is intentionally **minimal but realistic** for teaching goals. Replace the SQLite DB
with Postgres + Alembic for production-like scenarios, and integrate a proper secrets manager.


Contenido

```
secure-prog-starter/
├─ app/                         # Código FastAPI
│  ├─ core/security.py          # JWT, hashing, auth deps
│  ├─ models/                   # SQLModel User/Message + esquemas Pydantic
│  └─ routers/                  # /auth, /users (admin), /messages (propietario)
├─ docs/
│  ├─ informe_template.md       # Plantilla informe técnico
│  ├─ checklist_owasp_cwe.md    # Checklist + evidencias
│  ├─ rubric.csv / rubric.xlsx  # Rúbrica (editable)
│  └─ support_channel_template.md
├─ scripts/                     # Scanners
│  ├─ scan_bandit.sh
│  ├─ scan_semgrep.sh
│  ├─ scan_pip_audit.sh
│  ├─ scan_zap_baseline.sh
│  └─ scan_trivy_{fs,image}.sh
├─ .github/workflows/security.yml  # CI de seguridad
├─ Dockerfile
├─ docker-compose.yml
├─ requirements.txt
├─ .env.example
└─ README.md
```