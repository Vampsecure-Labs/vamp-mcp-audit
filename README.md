# vamp-mcp-audit

**VampSecure Labs · Security Research Division**

Auditor de seguridad profesional para servidores MCP (Model Context Protocol) y configuraciones de agentes IA. Detecta vulnerabilidades en servidores MCP mediante 5 fases de auditoría especializadas.

---

## Instalación

```bash
pip install -r requirements.txt
```

**Requisitos:** Python 3.11+

---

## Uso

```bash
# Auditoría básica con output en consola
python vamp_mcp_audit.py --target http://localhost:3000

# Con informes JSON y HTML
python vamp_mcp_audit.py --target https://mcp.example.com --json report.json --html report.html

# Con timeout personalizado y output detallado
python vamp_mcp_audit.py --target http://127.0.0.1:8080 --timeout 15 --verbose
```

### Argumentos

| Argumento       | Descripción                                              |
|----------------|----------------------------------------------------------|
| `--target URL`  | URL del servidor MCP a auditar (obligatorio)             |
| `--json FILE`   | Exportar informe completo en JSON                        |
| `--html FILE`   | Exportar informe visual dark-theme en HTML               |
| `--scope FILE`  | Fichero JSON de restricciones de scope (opcional)        |
| `--timeout N`   | Timeout HTTP en segundos (por defecto: 10)               |
| `--verbose`     | Output de depuración detallado                           |

---

## Fases de auditoría

| Fase | Nombre                          | Detecta                                                    |
|------|---------------------------------|------------------------------------------------------------|
| 1    | Reconocimiento MCP              | Capacidades, tools, recursos, autenticación                |
| 2    | Tool Poisoning Detection        | Prompt injection en descriptions, schema poisoning         |
| 3    | Privilege & Permissions Audit   | Filesystem, shell, red, secretos, path traversal           |
| 4    | Transport Security              | TLS, CORS, SSE sin auth, inyección STDIO (CVSS 9.8)        |
| 5    | Agentic Risk Assessment         | OWASP Agentic AI Top 10 2026, risk score global            |

---

## Exit codes

| Código | Significado                          |
|--------|--------------------------------------|
| `0`    | Sin hallazgos CRITICAL o HIGH        |
| `1`    | Al menos un hallazgo CRITICAL o HIGH |
| `2`    | Error de ejecución o interrupción    |

---

## Formatos de informe

- **Consola:** Rich con paneles por fase, tabla resumen de hallazgos y risk score OWASP
- **JSON:** Estructura completa con todos los campos de cada hallazgo, inventario de tools y resumen de riesgo
- **HTML:** Informe dark-theme standalone con badges de severidad y filtro interactivo por nivel de riesgo

---

## Referencias

- [MCP Specification 2024-11-05](https://modelcontextprotocol.io)
- [OWASP Agentic AI Top 10 2026](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- OX Security — MCP STDIO Injection, abril 2026 (CVSS 9.8)

---

© VampSecure Studios — VampSecure Labs Security Research Division  
Uso exclusivo en auditorías autorizadas. El uso no autorizado es ilegal.
