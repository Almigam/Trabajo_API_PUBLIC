# Informe técnico del proyecto

## 1. Introducción
- Objetivos del proyecto
- Alcance y funcionalidades

## 2. Arquitectura y tecnologías
- Diagrama de componentes / flujo
- Decisiones de diseño seguro (Security by Design)

## 3. Modelo de amenazas
- Metodología: STRIDE / OWASP
- Principales amenazas identificadas y riesgo

## 4. Controles implementados
- Validación de entradas
- Autenticación y autorización (roles)
- Gestión de sesiones / tokens
- Cifrado: contraseñas / TLS (si aplica)
- Gestión de errores y logging
- Seguridad en dependencias / SBOM
- Despliegue seguro (Docker, cloud)

## 5. Pruebas y evidencias
- SAST (Bandit, Semgrep) — hallazgos y mitigaciones
- DAST (ZAP) — hallazgos y mitigaciones
- Dependencias (pip-audit, Trivy) — hallazgos y mitigaciones
- Capturas y enlaces a los informes en `/reports`

## 6. Lecciones aprendidas
- Retos técnicos y decisiones clave
- Qué mejorar en siguiente iteración

## 7. Bibliografía
- OWASP Top 10, ASVS, CWE, etc.
