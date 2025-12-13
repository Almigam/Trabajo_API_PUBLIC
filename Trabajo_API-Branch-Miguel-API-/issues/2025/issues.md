# Lista de issues para el proyecto de Programación Segura

Cada issue corresponde a una tarea a implementar por los alumnos, con su objetivo, criterio de aceptación y referencia a OWASP/CWE.

---

## 1. Realizar modelo de amenazas inicial
**Objetivo:** Identificar posibles amenazas y vectores de ataque en la API base.  
**Criterio de aceptación:** Documento en `/docs/threat_model.md` con análisis usando STRIDE u OWASP, incluyendo al menos 5 amenazas priorizadas.  
**Referencias:** OWASP ASVS, OWASP Top 10 (A04).

---

## 2. Mejorar validación de entradas
**Objetivo:** Implementar validación estricta de parámetros en todas las rutas (longitud, formato, tipos).  
**Criterio de aceptación:** No se aceptan datos inválidos, se devuelven errores HTTP adecuados y se incluyen tests.  
**Referencias:** OWASP Top 10 (A03), CWE-20.

---

## 3. Implementar control de acceso granular (RBAC)
**Objetivo:** Separar permisos para usuarios y administradores; verificar ownership en todas las operaciones.  
**Criterio de aceptación:** Los usuarios no pueden ver/editar datos ajenos. Tests que lo validen.  
**Referencias:** OWASP Top 10 (A01), CWE-284.

---

## 4. Mejorar autenticación
**Objetivo:** Añadir expiración corta a tokens JWT y endpoint seguro de refresh.  
(Bonus) Implementar MFA o verificación por correo.  
**Criterio de aceptación:** Tokens antiguos expiran correctamente; MFA funciona si se implementa.  
**Referencias:** OWASP Top 10 (A07), CWE-287.

---

## 5. Cifrado de contraseñas con Argon2
**Objetivo:** Cambiar el algoritmo de hash a `argon2` con sal aleatoria.  
**Criterio de aceptación:** Todas las contraseñas existentes en pruebas se migran; nuevas usan Argon2.  
**Referencias:** OWASP Top 10 (A02), CWE-916.

---

## 6. Gestión segura de errores y logging
**Objetivo:** Responder con mensajes genéricos al cliente y registrar eventos críticos sin datos sensibles.  
**Criterio de aceptación:** Ningún stack trace ni dato sensible en respuestas; logs seguros presentes.  
**Referencias:** OWASP Top 10 (A09), CWE-209.

---

## 7. Añadir cabeceras HTTP de seguridad
**Objetivo:** Configurar en FastAPI cabeceras como CSP, X-Frame-Options, X-Content-Type-Options.  
**Criterio de aceptación:** Verificable con [Mozilla Observatory](https://observatory.mozilla.org/).  
**Referencias:** OWASP Top 10 (A05), CWE-693.

---

## 8. Implementar rate limiting
**Objetivo:** Evitar fuerza bruta o abuso de endpoints mediante limitación de peticiones por IP.  
**Criterio de aceptación:** Requests por encima del límite reciben respuesta 429.  
**Referencias:** OWASP API Top 10 (API4), CWE-307.

---

## 9. Seguridad en la cadena de suministro
**Objetivo:** Ejecutar `pip-audit`, `semgrep`, `bandit` y `trivy` y corregir vulnerabilidades críticas.  
**Criterio de aceptación:** Informes en `/reports` y dependencias actualizadas sin findings críticos.  
**Referencias:** OWASP Top 10 (A06), CWE-1104.

---

## 10. Dockerfile y despliegue seguro
**Objetivo:** Revisar Dockerfile para minimizar superficie de ataque (usuario no root, imagen slim, etc.).  
**Criterio de aceptación:** `trivy image` sin findings críticos; contenedor no corre como root.  
**Referencias:** OWASP Top 10 (A05), CIS Benchmarks.

---

## 11. Documentar controles implementados
**Objetivo:** Completar `docs/informe_template.md` con todos los cambios y evidencias.  
**Criterio de aceptación:** Documento final claro, con capturas y trazabilidad a commits.  
**Referencias:** OWASP SAMM, ISO/IEC 27034.

---

## 12. Defensa del proyecto
**Objetivo:** Preparar presentación explicando amenazas detectadas, mitigaciones y evidencias.  
**Criterio de aceptación:** Defensa de máximo 10 minutos.  
**Referencias:** Comunicación técnica, defensa en profundidad.
