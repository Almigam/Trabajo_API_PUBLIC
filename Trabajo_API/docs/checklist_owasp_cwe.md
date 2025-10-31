# Checklist de verificación (OWASP Top 10 + CWE)

Marque (✔) cuando el control esté **implementado y verificado**. Añada evidencias (ruta a archivo, captura, commit).

## A01: Broken Access Control
- [ ] Autorización en backend para cada endpoint (no confiar en frontend) — Evidencia:
- [ ] Comprobación de ownership por objeto (IDOR evitado) — Evidencia:
- [ ] Separación de roles (RBAC/ABAC) — Evidencia:

## A02: Cryptographic Failures
- [ ] Hash de contraseñas con bcrypt/Argon2 (sal aleatoria) — Evidencia:
- [ ] TLS en tránsito (si aplica) — Evidencia:
- [ ] Gestión de secretos fuera de código (.env, vault) — Evidencia:

## A03: Injection
- [ ] ORM / consultas parametrizadas — Evidencia:
- [ ] Validación estricta de entradas (tipos/regex/longitud) — Evidencia:

## A04: Insecure Design
- [ ] Modelo de amenazas realizado — Evidencia:
- [ ] Controles de defensa en profundidad — Evidencia:

## A05: Security Misconfiguration
- [ ] Dockerfile seguro (no root, imagen slim, puertos mínimos) — Evidencia:
- [ ] Headers de seguridad (CSP, etc. si aplica) — Evidencia:
- [ ] Errores sin filtrar detalles internos — Evidencia:

## A06: Vulnerable and Outdated Components
- [ ] pip-audit / osv-scanner sin findings críticos — Evidencia:
- [ ] Dependabot/Renovate (bonus) — Evidencia:

## A07: Identification & Authentication Failures
- [ ] MFA (bonus) — Evidencia:
- [ ] JWT con expiración y firma correcta — Evidencia:

## A08: Software & Data Integrity Failures
- [ ] SBOM generado (bonus) — Evidencia:
- [ ] Firmas/verificación de artefactos (bonus) — Evidencia:

## A09: Security Logging & Monitoring Failures
- [ ] Logging de eventos clave (login/error/acciones críticas) — Evidencia:
- [ ] No se loguean secretos ni datos sensibles — Evidencia:

## A10: SSRF
- [ ] Validación y allowlist de URLs externas (si aplica) — Evidencia:

---

## Mapeo CWE (ejemplos)
- CWE-79 (XSS), CWE-89 (SQLi), CWE-200 (Exposure of Sensitive Info), CWE-287 (Auth Incorrecta), CWE-798 (Credenciales hardcodeadas)
