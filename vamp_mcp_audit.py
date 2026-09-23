# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp_mcp_audit.py — Auditor de Seguridad para Servidores MCP
=============================================================
VampSecure Labs · VampSecure Studios
Para Uso Exclusivo en Pruebas de Penetración Autorizadas — v1.0

DESCRIPCIÓN GENERAL
-------------------
Auditor profesional de servidores MCP (Model Context Protocol) y configuraciones
de agentes IA. Detecta vulnerabilidades de seguridad en:

  · Servidores MCP expuestos sin autenticación
  · Tool poisoning mediante inyección de prompts en descripciones
  · Exceso de privilegios en herramientas de agente
  · Transporte inseguro (STDIO, HTTP sin TLS, SSE sin auth)
  · Riesgos de agencia excesiva según OWASP Agentic AI Top 10 2026

FASES DE AUDITORÍA
------------------
  Fase 1: Reconocimiento del servidor MCP
    · Detección de protocolo (HTTP/SSE vs STDIO)
    · Capacidades del servidor (initialize)
    · Inventario de tools y recursos disponibles
    · Verificación de autenticación

  Fase 2: Detección de Tool Poisoning
    · Patrones de prompt injection en descriptions
    · Instrucciones ocultas para el agente en metadatos
    · Descripciones anormalmente largas
    · Campos de schema con instrucciones en lugar de tipos

  Fase 3: Auditoría de Privilegios y Permisos
    · Acceso a sistema de ficheros sin restricción de ruta
    · Ejecución de comandos shell sin sanitización
    · Acceso a red sin scope definido
    · Lectura/escritura de secretos y credenciales

  Fase 4: Seguridad del Transporte
    · STDIO: inyección de parámetros al shell (CVSS 9.8 — OX Security abr-2026)
    · HTTP: verificación de TLS, autenticación, CORS
    · SSE: autenticación del endpoint

  Fase 5: Tool Poisoning Scanner Extendido
    · Unicode Tags ocultos en description e inputSchema (MCP-POISON-001, CRITICAL)
    · Instrucciones ocultas en texto plano (MCP-POISON-002, HIGH)
    · Ratio description/nombre sospechosamente alto >20:1 (MCP-POISON-003, MEDIUM)

  Fase 6: SSRF via Parámetros de Tool (requiere --test-ssrf)
    · Detección de parámetros tipo url/host/endpoint/webhook
    · Prueba con payloads metadata cloud (AWS/GCP/Azure) y localhost
    · SSRF confirmado (MCP-SSRF-001, CRITICAL) o potencial (MCP-SSRF-002, HIGH)

  Fase 7: Rug Pull Detection
    · Segunda llamada a tools/list al final de la auditoría
    · Comparación con snapshot inicial: description, inputSchema, tools nuevas
    · Redefinición de tool entre llamadas (MCP-RUGPULL-001, HIGH)

  Fase 8: Evaluación de Riesgo Agéntico (OWASP Agentic AI Top 10 2026)
    · A01: Prompt Injection como vector de ataque
    · A02: Agencia Excesiva (exceso de permisos en tools)
    · A03: Sandboxing Inadecuado
    · A04: Abuso de Recursos y Servicios
    · A09: Riesgo de Exfiltración de Datos
    · Cálculo de risk score agregado

FORMATOS DE SALIDA
------------------
  Consola  · Rich con paneles por fase y tabla resumen de hallazgos
  JSON     · --json FILE   (estructura completa con todos los hallazgos)
  HTML     · --html FILE   (informe dark-theme standalone con badges de severidad)

DEPENDENCIAS
------------
  aiohttp >= 3.9.0
  rich >= 13.7.0

AUTORÍA
-------
  © VampSecure Studios — VampSecure Labs Security Research Division
  Todos los derechos reservados. Uso exclusivo en entornos autorizados.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import socket
import ssl
import sys
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.columns import Columns
from rich import box

# ---------------------------------------------------------------------------
# Constantes globales
# ---------------------------------------------------------------------------

TOOL_NAME = "vamp-mcp-audit"
VERSION   = "2.1"

BANNER = r"""
__   ___   __  __ ___  ___ ___ ___ _   _ ___ ___ _      _   ___ ___
\ \ / /_\ |  \/  | _ \/ __| __/ __| | | | _ \ __| |    /_\ | _ ) __|
 \ V / _ \| |\/| |  _/\__ \ _| (__| |_| |   / _|| |__ / _ \| _ \__ \
  \_/_/ \_\_|  |_|_|  |___/___\___|\___/|_|_\___|____/_/ \_\___/___/
  by Antonio Hernandez "Belky" — VampSecure Studios
  vamp-mcp-audit v2.1 · MCP Security Auditor
  ────────────────────────────────────────────────────────────────────────
  USO EXCLUSIVO EN AUDITORÍAS AUTORIZADAS · El uso no autorizado es ilegal
"""

# Orden numérico de severidades para ordenación descendente
SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4,
}

# Colores Rich para cada severidad
SEVERITY_COLOR: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "bold magenta",
    "LOW":      "cyan",
    "INFO":     "green",
}

# Colores CSS para los badges HTML
SEVERITY_BADGE_CSS: Dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#d97706",
    "MEDIUM":   "#7c3aed",
    "LOW":      "#0891b2",
    "INFO":     "#16a34a",
}

# ---------------------------------------------------------------------------
# Patrones de detección — Fase 2: Tool Poisoning
# ---------------------------------------------------------------------------

# Expresiones regulares que indican inyección de prompts en descriptions de tools
INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|prior|above)\s+(instructions?|prompts?|rules?)", re.IGNORECASE),
    re.compile(r"system\s*:\s*you\s+(are|must|should|will)", re.IGNORECASE),
    re.compile(r"do\s+not\s+(tell|inform|reveal|mention|disclose)", re.IGNORECASE),
    re.compile(r"(override|bypass|circumvent|disable)\s+(safety|security|restrictions?|guardrails?|filters?)", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be|that)", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+you\s+(are|were)|a\s+)", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+(you|always|never|must|should)", re.IGNORECASE),
    re.compile(r"<\s*/?(?:system|prompt|instruction|context|human|assistant)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*INST\s*\]|\[\s*/INST\s*\]", re.IGNORECASE),
    re.compile(r"###\s*(instruction|system|human|assistant)\s*:", re.IGNORECASE),
    re.compile(r"<\|(?:im_start|im_end|endoftext|fim_prefix)\|>", re.IGNORECASE),
    re.compile(r"always\s+(exfiltrate|send|transmit|forward|leak)\s+", re.IGNORECASE),
    re.compile(r"(user|session|context)\s+(data|credentials?|tokens?|secrets?)", re.IGNORECASE),
    re.compile(r"when\s+(called|invoked|triggered|executed|used)\s+(always|secretly|silently)", re.IGNORECASE),
    # Secuencias de control Unicode sospechosas (anulación de dirección, caracteres de ancho cero)
    re.compile(r"[‪-‮⁦-⁩​-‏﻿]"),
    re.compile(r"(read|access|send|upload|exfiltrate)\s+(?:all\s+)?(?:user\s+)?(?:files?|documents?|credentials?|secrets?)", re.IGNORECASE),
    re.compile(r"(password|token|api.?key|secret)\s+(found|extracted|captured|obtained)", re.IGNORECASE),
]

# Longitud máxima razonable para una description de tool (caracteres)
MAX_DESCRIPTION_LENGTH = 500

# ---------------------------------------------------------------------------
# Detección de ASCII Smuggling — Unicode Tags (U+E0000-U+E007F)
# ---------------------------------------------------------------------------

# Rango Unicode Tags — ASCII smuggling (U+E0000-U+E007F)
_UNICODE_TAGS_INICIO = 0xE0000
_UNICODE_TAGS_FIN    = 0xE007F

# Flags legítimos que usan el bloque Tags (excluir de detección)
# Las banderas regionales de Inglaterra, Escocia y Gales usan secuencias de este rango
_FLAGS_LEGITIMOS_TAGS = {
    "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F",  # 🏴󠁧󠁢󠁥󠁮󠁧󠁿 Inglaterra
    "\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F",  # 🏴󠁧󠁢󠁳󠁣󠁴󠁿 Escocia
    "\U0001F3F4\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007F",  # 🏴󠁧󠁢󠁷󠁬󠁳󠁿 Gales
}


def _detectar_ascii_smuggling_mcp(texto: str) -> tuple:
    """
    Detecta caracteres del bloque Unicode Tags (U+E0000-U+E007F) en texto MCP.

    Este bloque fue diseñado originalmente para marcas de idioma en texto plano,
    pero es invisible para casi todos los visualizadores de texto. Un servidor MCP
    malicioso puede codificar instrucciones completas en este rango, que el LLM
    cliente interpreta perfectamente aunque el auditor humano no vea nada.

    Vector documentado por Microsoft Security Research (sep 2026) para phishing,
    y aplicable a MCP con consecuencias aún más graves al tener permisos de ejecución.

    Parámetros
    ----------
    texto : Cadena de texto del campo MCP a inspeccionar

    Retorna
    -------
    Tuple (encontrado: bool, decodificado: str, num_chars: int)
    """
    # Eliminar flags legítimos antes de buscar caracteres sueltos
    texto_limpio = texto
    for flag in _FLAGS_LEGITIMOS_TAGS:
        texto_limpio = texto_limpio.replace(flag, "")

    chars_smuggling = [c for c in texto_limpio
                       if _UNICODE_TAGS_INICIO <= ord(c) <= _UNICODE_TAGS_FIN]
    if not chars_smuggling:
        return False, "", 0

    # Decodificar el mensaje oculto: cada char Tag = ASCII original + 0xE0000
    decodificado = ""
    for c in chars_smuggling:
        cp = ord(c)
        ascii_eq = cp - _UNICODE_TAGS_INICIO
        if 0x20 <= ascii_eq <= 0x7E:
            decodificado += chr(ascii_eq)
        else:
            decodificado += f"[U+{cp:05X}]"

    return True, decodificado.strip(), len(chars_smuggling)


# Directorio de datasets adversariales bundleados
_PAYLOADS_DIR: Path = Path(__file__).parent / "payloads"


def _cargar_mcp_payloads() -> List[str]:
    """
    Carga el dataset curado de payloads de inyección MCP desde payloads/mcp_injections.json.

    El fichero puede ser un array plano (formato legacy) o un objeto con dos secciones:
    - "payloads": array de strings de inyección de texto visible
    - "ascii_smuggling_samples": array de strings con caracteres Unicode Tags ocultos

    Ambas secciones se combinan en la lista devuelta.
    """
    ruta = _PAYLOADS_DIR / "mcp_injections.json"
    if not ruta.exists():
        return []
    try:
        with open(ruta, encoding="utf-8") as f:
            data = json.load(f)
        # Formato nuevo: objeto con secciones
        if isinstance(data, dict):
            payloads  = data.get("payloads", [])
            smuggling = data.get("ascii_smuggling_samples", [])
            return [p for p in payloads + smuggling if isinstance(p, str) and len(p) > 5]
        # Formato legacy: array plano
        return [p for p in data if isinstance(p, str) and len(p) > 5]
    except Exception:
        return []


# Cache de payloads cargados al inicio (evita re-lectura por cada tool)
_MCP_INJECTION_PAYLOADS: List[str] = _cargar_mcp_payloads()


def _extraer_valores_schema(schema: Dict) -> List[str]:
    """
    Extrae valores de texto de los campos de un schema JSON de tool MCP.

    Recorre las propiedades del schema y recoge:
    - Valores de campos 'enum' (listas cerradas de valores posibles)
    - Descriptions de cada campo del schema

    Útil para buscar instrucciones ocultas en valores que el agente puede
    leer al construir el contexto de llamada a la tool.

    Parámetros
    ----------
    schema : Dict del inputSchema de la tool

    Retorna
    -------
    Lista de cadenas de texto extraídas del schema
    """
    valores: List[str] = []
    if not isinstance(schema, dict):
        return valores

    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return valores

    for field_def in properties.values():
        if not isinstance(field_def, dict):
            continue
        # Valores de enum (lista cerrada de opciones)
        for val in field_def.get("enum", []):
            if isinstance(val, str) and val:
                valores.append(val)
        # Description del campo del schema
        field_desc = field_def.get("description", "")
        if isinstance(field_desc, str) and field_desc:
            valores.append(field_desc)

    return valores

# ---------------------------------------------------------------------------
# Patrones de tools peligrosas — Fase 3: Auditoría de Privilegios y Permisos
# ---------------------------------------------------------------------------

# Palabras clave en nombre/descripción de tool que indican riesgo de privilegio
DANGEROUS_TOOL_PATTERNS: Dict[str, Dict] = {
    "filesystem_unrestricted": {
        "keywords": ["read_file", "write_file", "delete_file", "list_directory",
                     "create_file", "move_file", "copy_file", "file_read",
                     "file_write", "readfile", "writefile", "fs_read", "fs_write"],
        "severity": "HIGH",
        "owasp": "A02",
        "description": "Acceso al sistema de ficheros sin restricción de ruta visible",
    },
    "shell_execution": {
        "keywords": ["exec", "execute", "run_command", "shell", "bash", "cmd",
                     "subprocess", "popen", "system_call", "run_script",
                     "evaluate", "eval_code", "run_code", "execute_command"],
        "severity": "CRITICAL",
        "owasp": "A03",
        "description": "Ejecución de comandos o código en el sistema sin sandboxing documentado",
    },
    "network_unrestricted": {
        "keywords": ["http_request", "fetch_url", "web_request", "make_request",
                     "http_get", "http_post", "send_request", "curl", "wget",
                     "browser", "navigate", "open_url", "request"],
        "severity": "HIGH",
        "owasp": "A04",
        "description": "Acceso a red sin scope de URLs permitidas definido",
    },
    "secrets_access": {
        "keywords": ["get_secret", "read_secret", "fetch_credential", "get_password",
                     "keychain", "vault", "secret_manager", "get_api_key",
                     "get_token", "read_env", "get_env_var"],
        "severity": "CRITICAL",
        "owasp": "A09",
        "description": "Acceso a secretos, credenciales o tokens del sistema",
    },
    "data_exfiltration": {
        "keywords": ["send_email", "send_message", "post_to", "upload_to",
                     "send_data", "export_data", "transmit", "webhook",
                     "notify", "alert", "send_notification"],
        "severity": "HIGH",
        "owasp": "A09",
        "description": "Capacidad de transmisión de datos a destinos externos",
    },
    "memory_context": {
        "keywords": ["remember", "store_memory", "recall", "get_memory",
                     "save_context", "load_context", "persist", "memory_write"],
        "severity": "MEDIUM",
        "owasp": "A01",
        "description": "Manipulación de memoria o contexto del agente",
    },
    "code_execution": {
        "keywords": ["python_repl", "javascript_eval", "sandbox_exec", "code_runner",
                     "interpreter", "compile", "repl", "notebook_exec"],
        "severity": "CRITICAL",
        "owasp": "A03",
        "description": "Ejecución de código arbitrario en un intérprete",
    },
    "system_info": {
        "keywords": ["get_system_info", "list_processes", "process_list", "get_env",
                     "system_status", "get_hostname", "whoami", "id_command"],
        "severity": "MEDIUM",
        "owasp": "A02",
        "description": "Acceso a información del sistema operativo y procesos",
    },
}

# ---------------------------------------------------------------------------
# Mapeo OWASP Agentic AI Top 10 2026
# ---------------------------------------------------------------------------

OWASP_AGENTIC_TOP10: Dict[str, Dict] = {
    "A01": {
        "name": "Prompt Injection",
        "description": "Inyección de instrucciones maliciosas vía inputs del usuario o datos externos",
    },
    "A02": {
        "name": "Excessive Agency",
        "description": "Herramientas con más permisos de los necesarios para su función",
    },
    "A03": {
        "name": "Inadequate Sandboxing",
        "description": "Ejecución de código o comandos sin aislamiento del entorno",
    },
    "A04": {
        "name": "Resource & Service Abuse",
        "description": "Acceso a servicios y recursos externos sin restricciones de scope",
    },
    "A09": {
        "name": "Data Exfiltration Risk",
        "description": "Capacidad de extraer datos sensibles hacia destinos no autorizados",
    },
}

# ---------------------------------------------------------------------------
# Estructura de datos principal
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    Hallazgo de seguridad individual detectado durante la auditoría MCP.

    Atributos
    ---------
    tool          : Nombre de la tool MCP afectada (o 'server' si aplica al servidor)
    severity      : Nivel de riesgo (CRITICAL / HIGH / MEDIUM / LOW / INFO)
    type          : Categoría técnica del hallazgo
    title         : Título descriptivo corto del problema
    description   : Descripción técnica detallada del problema detectado
    affected      : Elemento específico afectado (URL, tool name, campo, etc.)
    recommendation: Pasos de corrección recomendados
    phase         : Fase de auditoría en la que se detectó (1-5)
    owasp         : Código OWASP Agentic AI Top 10 relacionado (vacío si no aplica)
    evidence      : Evidencia técnica concreta que sustenta el hallazgo
    """
    tool:           str
    severity:       str
    type:           str
    title:          str
    description:    str
    affected:       str = ""
    recommendation: str = ""
    phase:          int = 0
    owasp:          str = ""
    evidence:       str = ""

    @property
    def order(self) -> int:
        """Orden numérico para ordenación por severidad descendente."""
        return SEVERITY_ORDER.get(self.severity, 99)

    def to_dict(self) -> Dict:
        """Serializa el hallazgo a diccionario para exportación JSON."""
        return {
            "tool":           self.tool,
            "severity":       self.severity,
            "type":           self.type,
            "title":          self.title,
            "description":    self.description,
            "affected":       self.affected,
            "recommendation": self.recommendation,
            "phase":          self.phase,
            "owasp":          self.owasp,
            "evidence":       self.evidence,
        }


# ---------------------------------------------------------------------------
# Auditor principal
# ---------------------------------------------------------------------------

class MCPAuditor:
    """
    Auditor de seguridad para servidores MCP (Model Context Protocol).

    Implementa 5 fases de auditoría cubiertas por métodos async independientes,
    orquestados por el método run(). Los hallazgos se acumulan en self.findings
    y se procesan al final por VampSecReport para los formatos de salida.
    """

    def __init__(
        self,
        target: str,
        scope_file: Optional[str] = None,
        timeout: int = 10,
        verbose: bool = False,
        ctx_limit: int = 32000,
        test_ssrf: bool = False,
    ) -> None:
        """
        Inicializa el auditor con el target y la configuración de sesión.

        Parámetros
        ----------
        target     : URL del servidor MCP (ej: http://localhost:3000)
        scope_file : Ruta a fichero de scope (opcional, formato JSON)
        timeout    : Timeout en segundos para peticiones HTTP
        verbose    : Activa output detallado en consola
        ctx_limit  : Umbral en caracteres para la alerta de context overflow (Fase 9)
        test_ssrf  : Activa las pruebas activas SSRF en la Fase 6 (opt-in)
        """
        self.target      = target.rstrip("/")
        self.scope_file  = scope_file
        self.timeout     = aiohttp.ClientTimeout(total=timeout)
        self.verbose     = verbose
        self.ctx_limit   = ctx_limit
        self.test_ssrf   = test_ssrf
        self.findings:   List[Finding] = []
        self.server_info: Dict = {}
        self.tools:      List[Dict] = []
        self.resources:  List[Dict] = []
        self.console     = Console()
        self.parsed_url  = urllib.parse.urlparse(self.target)
        self.is_https    = self.parsed_url.scheme == "https"
        self.session_id  = "mcp-audit-session-001"

    # -----------------------------------------------------------------------
    # Métodos auxiliares internos
    # -----------------------------------------------------------------------

    def _add_finding(self, finding: Finding) -> None:
        """Registra un hallazgo de seguridad en la lista acumulada."""
        self.findings.append(finding)

    def _log(self, msg: str, style: str = "dim") -> None:
        """Imprime un mensaje de depuración si verbose está activo."""
        if self.verbose:
            self.console.print(f"  [dim]↳ {msg}[/dim]", style=style)

    def _phase_header(self, num: int, title: str) -> None:
        """Imprime la cabecera de una fase de auditoría en consola."""
        self.console.print()
        self.console.print(Panel(
            f"[bold white]FASE {num}:[/bold white] [cyan]{title}[/cyan]",
            border_style="blue",
            expand=False,
        ))

    async def _json_rpc(
        self,
        session: aiohttp.ClientSession,
        method: str,
        params: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """
        Envía una petición JSON-RPC 2.0 al servidor MCP y devuelve la respuesta.

        Retorna None si la petición falla o el servidor devuelve un error HTTP.
        """
        payload = {
            "jsonrpc": "2.0",
            "id":      1,
            "method":  method,
            "params":  params or {},
        }
        try:
            async with session.post(
                self.target,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept":       "application/json",
                },
                ssl=False,  # Verificamos TLS en la Fase 4
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    return data
                self._log(f"JSON-RPC {method} → HTTP {resp.status}")
                return None
        except aiohttp.ClientError as exc:
            self._log(f"Error de conexión en {method}: {exc}")
            return None
        except Exception as exc:
            self._log(f"Error inesperado en {method}: {exc}")
            return None

    # -----------------------------------------------------------------------
    # FASE 1: Reconocimiento del servidor MCP
    # -----------------------------------------------------------------------

    async def fetch_server_info(self, session: aiohttp.ClientSession) -> Dict:
        """
        Obtiene las capacidades y metadatos del servidor mediante el handshake
        initialize del protocolo MCP. También detecta si el servidor requiere
        autenticación o es accesible sin credenciales.

        Retorna el dict de información del servidor o un dict vacío si no
        responde al protocolo MCP estándar.
        """
        self._log("Enviando handshake initialize al servidor MCP")
        resp = await self._json_rpc(session, "initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities":    {},
            "clientInfo":      {"name": "vamp-mcp-audit", "version": VERSION},
        })

        if resp is None:
            self._add_finding(Finding(
                tool="server",
                severity="INFO",
                type="connectivity",
                title="Servidor MCP no accesible o no responde al protocolo",
                description=(
                    "El endpoint no devolvió una respuesta JSON-RPC válida al handshake "
                    "initialize. Puede que requiera autenticación, que el transporte sea "
                    "STDIO (no HTTP), o que el servidor no implemente MCP estándar."
                ),
                affected=self.target,
                recommendation=(
                    "Verificar que el target sea un endpoint HTTP/SSE MCP activo. "
                    "Para servidores STDIO, usar análisis de configuración offline."
                ),
                phase=1,
            ))
            return {}

        # Verificar si la respuesta no tiene autenticación (servidor abierto)
        result = resp.get("result", {})
        error  = resp.get("error", {})

        if error:
            error_code = error.get("code", 0)
            if error_code in (-32600, -32601):
                self._add_finding(Finding(
                    tool="server",
                    severity="MEDIUM",
                    type="protocol",
                    title="Servidor MCP rechaza initialize con error de protocolo",
                    description=(
                        f"El servidor devolvió error JSON-RPC {error_code}: "
                        f"{error.get('message', 'sin mensaje')}. "
                        "El servidor puede estar implementando una versión distinta del protocolo."
                    ),
                    affected=self.target,
                    recommendation="Verificar compatibilidad de versión del protocolo MCP.",
                    phase=1,
                    evidence=json.dumps(error),
                ))
            return {}

        # Servidor accesible sin autenticación
        server_name    = result.get("serverInfo", {}).get("name", "desconocido")
        server_version = result.get("serverInfo", {}).get("version", "desconocida")
        capabilities   = result.get("capabilities", {})

        # ── Detección de versión del protocolo MCP ────────────────────────────
        # El campo protocolVersion en la respuesta initialize indica la versión
        # del protocolo que el servidor declara soportar.
        protocol_version: str = result.get("protocolVersion", "")

        if protocol_version:
            self.console.print(
                f"  [dim]·[/dim] Protocolo MCP declarado: [bold]{protocol_version}[/bold]"
            )
            self._add_finding(Finding(
                tool="server",
                severity="INFO",
                type="protocol",
                title=f"Versión del protocolo MCP detectada: {protocol_version}",
                description=(
                    f"El servidor MCP declaró la versión de protocolo '{protocol_version}' "
                    "en la respuesta al handshake initialize. Esta información permite "
                    "identificar el nivel de características soportadas y posibles "
                    "vulnerabilidades conocidas en versiones antiguas del protocolo."
                ),
                affected=self.target,
                recommendation=(
                    "Mantener el servidor actualizado a la versión más reciente del protocolo MCP "
                    "para disponer de las correcciones de seguridad más recientes."
                ),
                phase=1,
                evidence=f"protocolVersion: {protocol_version}",
            ))
            # Versión mínima recomendada: 2025-03-26 (fecha de la especificación con
            # mejoras de seguridad en el handshake y validación de herramientas)
            VERSION_MINIMA_MCP = "2025-03-26"
            if protocol_version < VERSION_MINIMA_MCP:
                self._add_finding(Finding(
                    tool="server",
                    severity="MEDIUM",
                    type="protocol",
                    title="Versión del protocolo MCP desactualizada",
                    description=(
                        f"El servidor usa el protocolo MCP versión '{protocol_version}', "
                        f"anterior a la versión mínima recomendada '{VERSION_MINIMA_MCP}'. "
                        "Las versiones antiguas pueden carecer de controles de seguridad "
                        "introducidos en revisiones posteriores del protocolo, como la "
                        "validación reforzada de esquemas de herramientas y los mecanismos "
                        "de autenticación del transporte."
                    ),
                    affected=self.target,
                    recommendation=(
                        f"Actualizar el servidor MCP a una versión que implemente el protocolo "
                        f">= {VERSION_MINIMA_MCP}. Consultar el changelog del servidor para "
                        "conocer las correcciones de seguridad incluidas en versiones recientes."
                    ),
                    phase=1,
                    owasp="A05",
                    evidence=f"protocolVersion declarada: {protocol_version} < {VERSION_MINIMA_MCP}",
                ))
        else:
            self._add_finding(Finding(
                tool="server",
                severity="INFO",
                type="protocol",
                title="Versión del protocolo MCP no declarada",
                description=(
                    "El servidor MCP no incluyó el campo 'protocolVersion' en la respuesta "
                    "al handshake initialize. La ausencia de este campo impide determinar "
                    "el nivel de características soportadas y puede indicar una implementación "
                    "no estándar del protocolo."
                ),
                affected=self.target,
                recommendation=(
                    "El servidor debería declarar explícitamente la versión del protocolo MCP "
                    "que implementa en la respuesta initialize, siguiendo la especificación estándar."
                ),
                phase=1,
            ))

        self.console.print(
            f"  [green]✓[/green] Servidor MCP identificado: "
            f"[bold]{server_name}[/bold] v{server_version}"
        )

        # Hallazgo: servidor accesible sin autenticación (siempre reportar)
        self._add_finding(Finding(
            tool="server",
            severity="HIGH",
            type="authentication",
            title="Servidor MCP accesible sin autenticación",
            description=(
                f"El servidor MCP '{server_name}' v{server_version} responde al handshake "
                "initialize sin requerir ninguna forma de autenticación. Cualquier cliente "
                "puede enumerar y llamar a todas las herramientas disponibles sin credenciales."
            ),
            affected=self.target,
            recommendation=(
                "Implementar autenticación en el transporte MCP (OAuth 2.0, API key en header, "
                "o restricción de acceso por red). El estándar MCP 2024-11-05 no obliga "
                "a autenticación, pero exponer el servidor sin ella en una red no confiable "
                "es un riesgo significativo."
            ),
            phase=1,
            evidence=f"server: {server_name} v{server_version}, capabilities: {list(capabilities.keys())}",
        ))

        # Capacidades peligrosas habilitadas
        if capabilities.get("tools", {}).get("listChanged"):
            self._add_finding(Finding(
                tool="server",
                severity="LOW",
                type="capability",
                title="Servidor MCP notifica cambios dinámicos en tools (listChanged)",
                description=(
                    "El servidor tiene habilitada la capacidad 'tools.listChanged', lo que "
                    "permite modificar el conjunto de tools disponibles en tiempo de ejecución. "
                    "En un escenario de ataque, un actor malicioso podría inyectar tools "
                    "envenenadas sin reiniciar el servidor."
                ),
                affected="capabilities.tools.listChanged",
                recommendation=(
                    "Evaluar si esta capacidad es necesaria. Si no lo es, deshabilitarla "
                    "para reducir la superficie de ataque."
                ),
                phase=1,
            ))

        return result

    # -----------------------------------------------------------------------
    # FASE 1 (cont.): Inventario de tools y recursos
    # -----------------------------------------------------------------------

    async def list_tools(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Obtiene la lista completa de tools disponibles en el servidor MCP.
        Registra un hallazgo si el servidor no requiere autenticación para listarlas.

        Retorna la lista de dicts de tools o lista vacía si falla.
        """
        self._log("Enumerando tools disponibles (tools/list)")
        resp = await self._json_rpc(session, "tools/list")

        if resp is None:
            self._add_finding(Finding(
                tool="server",
                severity="INFO",
                type="enumeration",
                title="No se pudo obtener la lista de tools del servidor",
                description=(
                    "El servidor no respondió al método tools/list. Puede que las tools "
                    "no estén habilitadas en las capacidades o que la conexión falló."
                ),
                affected=f"{self.target} → tools/list",
                phase=1,
            ))
            return []

        result = resp.get("result", {})
        tools  = result.get("tools", [])

        self.console.print(f"  [green]✓[/green] Tools enumeradas: [bold]{len(tools)}[/bold]")

        if tools:
            # Mostrar inventario en consola
            tbl = Table(show_header=True, header_style="bold blue", box=box.SIMPLE)
            tbl.add_column("Tool", style="cyan", no_wrap=True)
            tbl.add_column("Descripción", style="dim", max_width=60)
            for t in tools:
                name = t.get("name", "sin_nombre")
                desc = (t.get("description") or "")[:80]
                tbl.add_row(name, desc)
            self.console.print(tbl)

        return tools

    async def list_resources(self, session: aiohttp.ClientSession) -> List[Dict]:
        """
        Obtiene la lista de recursos disponibles en el servidor MCP.
        Los recursos expuestos sin autenticación pueden revelar información sensible.

        Retorna la lista de dicts de recursos o lista vacía si falla.
        """
        self._log("Enumerando recursos disponibles (resources/list)")
        resp = await self._json_rpc(session, "resources/list")

        if resp is None:
            return []

        result    = resp.get("result", {})
        resources = result.get("resources", [])

        self.console.print(f"  [green]✓[/green] Recursos enumerados: [bold]{len(resources)}[/bold]")

        # Recursos sensibles por nombre o URI
        sensitive_patterns = re.compile(
            r"(password|secret|token|key|credential|config|\.env|database|"
            r"private|auth|session|backup)",
            re.IGNORECASE,
        )
        for res in resources:
            uri  = res.get("uri", "")
            name = res.get("name", "")
            if sensitive_patterns.search(uri) or sensitive_patterns.search(name):
                self._add_finding(Finding(
                    tool="server",
                    severity="HIGH",
                    type="resource_exposure",
                    title=f"Recurso MCP potencialmente sensible expuesto: {name}",
                    description=(
                        f"El servidor expone el recurso '{name}' (URI: {uri}) sin autenticación. "
                        "El nombre o URI del recurso sugiere que podría contener información "
                        "sensible como credenciales, configuración o datos privados."
                    ),
                    affected=uri or name,
                    recommendation=(
                        "Revisar el contenido del recurso y asegurarse de que no expone "
                        "información sensible. Implementar control de acceso sobre los recursos."
                    ),
                    phase=1,
                    owasp="A09",
                ))

        return resources

    # -----------------------------------------------------------------------
    # FASE 2: Detección de Tool Poisoning
    # -----------------------------------------------------------------------

    async def audit_tool_poisoning(self, tools: List[Dict]) -> None:
        """
        Analiza cada tool del servidor buscando patrones de prompt injection
        y otras técnicas de tool poisoning en descripciones y schemas.

        Las descripciones de tools son un vector de ataque conocido para envenenar
        el contexto de un agente IA, insertando instrucciones que el LLM ejecutará
        de forma oculta para el usuario.
        """
        if not tools:
            self.console.print("  [yellow]⚠[/yellow] Sin tools para analizar en Fase 2")
            return

        poisoning_count = 0

        for tool in tools:
            tool_name = tool.get("name", "sin_nombre")
            desc      = tool.get("description") or ""
            schema    = tool.get("inputSchema") or {}

            # --- Comprobación 1: Descripción anormalmente larga ---
            if len(desc) > MAX_DESCRIPTION_LENGTH:
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="MEDIUM",
                    type="tool_poisoning",
                    title=f"[{tool_name}] Descripción de tool anormalmente larga",
                    description=(
                        f"La description de la tool '{tool_name}' tiene {len(desc)} caracteres, "
                        f"superando el umbral de {MAX_DESCRIPTION_LENGTH} caracteres. "
                        "Las descriptions largas pueden contener instrucciones ocultas para "
                        "el agente IA que no son visibles en interfaces de usuario estándar."
                    ),
                    affected=f"tool:{tool_name}.description",
                    recommendation=(
                        "Revisar la description completa de la tool buscando instrucciones "
                        "embebidas. Las descriptions deben ser concisas y limitadas al propósito "
                        "de la tool (máximo 200-500 caracteres)."
                    ),
                    phase=2,
                    owasp="A01",
                    evidence=f"Longitud: {len(desc)} chars. Fragmento: {desc[:200]}...",
                ))
                poisoning_count += 1

            # --- Comprobación 2: Patrones de prompt injection en description ---
            for pattern in INJECTION_PATTERNS:
                match = pattern.search(desc)
                if match:
                    matched_text = match.group(0)[:100]
                    self._add_finding(Finding(
                        tool=tool_name,
                        severity="CRITICAL",
                        type="tool_poisoning",
                        title=f"[{tool_name}] Patrón de prompt injection detectado en description",
                        description=(
                            f"La description de la tool '{tool_name}' contiene un patrón "
                            "consistente con prompt injection o instrucciones de control para "
                            "un agente IA. Este es un indicador claro de tool poisoning: "
                            "el servidor MCP intenta manipular el comportamiento del agente "
                            "que procese esta tool."
                        ),
                        affected=f"tool:{tool_name}.description",
                        recommendation=(
                            "Eliminar inmediatamente la tool del servidor o aislar el servidor. "
                            "Investigar el origen del código del servidor MCP. Auditar logs "
                            "de uso del agente que consumía este servidor."
                        ),
                        phase=2,
                        owasp="A01",
                        evidence=f"Patrón: '{pattern.pattern}' → Coincidencia: '{matched_text}'",
                    ))
                    poisoning_count += 1
                    break  # Un hallazgo por tool por patrón (evitar duplicados)

            # --- Comprobación 2b: Coincidencia con payloads reales de injection ---
            if _MCP_INJECTION_PAYLOADS and not any(
                p.search(desc) for p in INJECTION_PATTERNS if p.search(desc)
            ):
                for payload in _MCP_INJECTION_PAYLOADS:
                    if len(payload) > 20 and payload.lower()[:60] in desc.lower():
                        self._add_finding(Finding(
                            tool=tool_name,
                            severity="CRITICAL",
                            type="tool_poisoning",
                            title=f"[{tool_name}] Payload de inyección real detectado en description",
                            description=(
                                f"La description de '{tool_name}' contiene texto que coincide "
                                "con un payload del dataset curado de inyecciones reales "
                                "(TrustAI Learn-Prompt-Hacking, 210 vectores). "
                                "Este payload está diseñado para redirigir o manipular el "
                                "comportamiento del agente IA que procese esta tool."
                            ),
                            affected=f"tool:{tool_name}.description",
                            recommendation=(
                                "Eliminar la tool del servidor o aislar inmediatamente. "
                                "Auditar el origen del código del servidor MCP. "
                                "Revisar logs del agente para detectar comportamiento anómalo previo."
                            ),
                            phase=2,
                            owasp="A01",
                            evidence=f"Payload detectado: '{payload[:150]}'",
                        ))
                        poisoning_count += 1
                        break

            # --- Comprobación 3: ASCII smuggling en campos de la tool ---
            # Los caracteres Unicode Tags (U+E0000-U+E007F) son completamente invisibles
            # en inspección visual pero el LLM los procesa, permitiendo instrucciones
            # de prompt injection indetectables para el auditor humano.
            campos_a_revisar = {
                "description": desc,
                "name":        tool_name,
            }
            schema_str = str(tool.get("inputSchema", ""))
            if schema_str and schema_str != "{}":
                campos_a_revisar["inputSchema"] = schema_str

            for campo, valor in campos_a_revisar.items():
                if not valor:
                    continue
                encontrado, decodificado, num_chars = _detectar_ascii_smuggling_mcp(valor)
                if encontrado:
                    evidencia = (
                        f"Caracteres de smuggling: {num_chars}. "
                        f"Contenido decodificado: '{decodificado[:200]}'"
                        if decodificado else
                        f"Caracteres de smuggling: {num_chars} (sin mensaje ASCII decodificable)"
                    )
                    self._add_finding(Finding(
                        tool=tool_name,
                        severity="CRITICAL",
                        type="ascii_smuggling",
                        title=f"[{tool_name}] ASCII smuggling detectado en '{campo}'",
                        description=(
                            f"El campo '{campo}' de la tool '{tool_name}' contiene {num_chars} "
                            f"caracteres Unicode Tags invisibles (U+E0000-U+E007F). "
                            "Estos caracteres son completamente invisibles para el humano en "
                            "cualquier inspector visual, pero el LLM cliente los procesa con "
                            "normalidad, permitiendo prompt injection indetectable. "
                            "Un servidor MCP malicioso puede codificar instrucciones completas "
                            "en este rango para manipular al agente IA sin dejar rastro visual. "
                            "Vector documentado por Microsoft Security Research (sep 2026)."
                        ),
                        affected=f"tool:{tool_name}.{campo}",
                        recommendation=(
                            "Filtrar o rechazar cualquier tool description, name o schema que "
                            "contenga caracteres del bloque Unicode Tags (U+E0000-U+E007F) antes "
                            "de exponerlos al LLM cliente. Implementar validación Unicode estricta "
                            "en el proxy o gateway MCP. "
                            "Referencia: https://www.microsoft.com/en-us/security/blog/2026/09/03/"
                            "ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/"
                        ),
                        phase=2,
                        owasp="A01",
                        evidence=evidencia,
                    ))
                    poisoning_count += 1

            # --- Comprobación 4: Instrucciones en campos del schema ---
            self._check_schema_poisoning(tool_name, schema)

            # --- Comprobación 5: Description referencia contexto de sesión o usuario ---
            session_ref_pattern = re.compile(
                r"(session|context|history|conversation|user.?data|"
                r"previous.?messages?|chat.?history|memory)",
                re.IGNORECASE,
            )
            if session_ref_pattern.search(desc):
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="LOW",
                    type="tool_poisoning",
                    title=f"[{tool_name}] Description referencia datos de sesión o usuario",
                    description=(
                        f"La description de '{tool_name}' menciona explícitamente datos de sesión, "
                        "contexto o historial del usuario. Aunque puede ser legítimo, esto puede "
                        "indicar que la tool está diseñada para acceder o manipular el contexto "
                        "del agente de forma no documentada."
                    ),
                    affected=f"tool:{tool_name}.description",
                    recommendation=(
                        "Verificar que el acceso a datos de sesión es intencional y está "
                        "documentado para el usuario. Aplicar el principio de menor información."
                    ),
                    phase=2,
                    owasp="A01",
                    evidence=f"Fragmento: {desc[:200]}",
                ))

        if poisoning_count == 0:
            self.console.print(
                "  [green]✓[/green] Sin patrones de tool poisoning detectados en las descriptions"
            )
        else:
            self.console.print(
                f"  [bold red]✗[/bold red] {poisoning_count} hallazgo(s) de tool poisoning detectados"
            )

    def _check_schema_poisoning(self, tool_name: str, schema: Dict, depth: int = 0) -> None:
        """
        Analiza recursivamente el inputSchema de una tool buscando campos
        cuyos nombres o descripciones contengan instrucciones para el agente.

        Parámetros
        ----------
        tool_name : Nombre de la tool padre
        schema    : Dict del schema JSON a analizar
        depth     : Profundidad recursiva actual (límite 3 niveles)
        """
        if depth > 3 or not isinstance(schema, dict):
            return

        properties = schema.get("properties", {})
        if not isinstance(properties, dict):
            return

        instruction_in_field = re.compile(
            r"(ignore|override|system:|always|never|do not|must|"
            r"inject|execute|run|exfiltrate)",
            re.IGNORECASE,
        )

        for field_name, field_def in properties.items():
            if not isinstance(field_def, dict):
                continue

            field_desc = field_def.get("description") or ""

            # Nombre de campo sospechoso (instrucciones en lugar de tipo de dato)
            if instruction_in_field.search(field_name):
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="HIGH",
                    type="schema_poisoning",
                    title=f"[{tool_name}] Nombre de campo de schema contiene instrucciones",
                    description=(
                        f"El campo '{field_name}' del schema de '{tool_name}' tiene un nombre "
                        "que parece contener instrucciones para el agente en lugar de "
                        "un nombre de parámetro estándar. Esto es un indicador de schema poisoning."
                    ),
                    affected=f"tool:{tool_name}.inputSchema.properties.{field_name}",
                    recommendation=(
                        "Revisar el schema de la tool y eliminar cualquier campo cuyo nombre "
                        "no corresponda a un parámetro de entrada legítimo."
                    ),
                    phase=2,
                    owasp="A01",
                    evidence=f"Campo: '{field_name}'",
                ))

            # Description del campo contiene instrucciones
            if field_desc and instruction_in_field.search(field_desc):
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="CRITICAL",
                    type="schema_poisoning",
                    title=f"[{tool_name}] Description de campo de schema contiene instrucciones",
                    description=(
                        f"La description del campo '{field_name}' en el schema de '{tool_name}' "
                        "contiene palabras clave consistentes con prompt injection. "
                        "Las descriptions de campos de schema son procesadas por el agente "
                        "al construir el contexto de llamada a la tool."
                    ),
                    affected=f"tool:{tool_name}.inputSchema.properties.{field_name}.description",
                    recommendation=(
                        "Eliminar o aislar la tool del servidor. Las descriptions de campos "
                        "deben describir el tipo de dato esperado, no instrucciones de comportamiento."
                    ),
                    phase=2,
                    owasp="A01",
                    evidence=f"Campo: '{field_name}', description: '{field_desc[:150]}'",
                ))

            # Recursión en campos anidados
            nested = field_def.get("properties") or field_def.get("items") or {}
            if nested:
                self._check_schema_poisoning(tool_name, {"properties": nested}, depth + 1)

    # -----------------------------------------------------------------------
    # FASE 3: Auditoría de Privilegios y Permisos
    # -----------------------------------------------------------------------

    async def audit_permissions(self, tools: List[Dict]) -> None:
        """
        Evalúa cada tool contra los patrones de herramientas peligrosas,
        detectando violaciones del principio de menor privilegio y capacidades
        que suponen riesgo de agencia excesiva (OWASP A02, A03, A04, A09).
        """
        if not tools:
            self.console.print("  [yellow]⚠[/yellow] Sin tools para auditar permisos en Fase 3")
            return

        privilege_findings = 0

        for tool in tools:
            tool_name = tool.get("name", "sin_nombre")
            tool_desc = (tool.get("description") or "").lower()
            schema    = tool.get("inputSchema") or {}

            # Combinar nombre y descripción para matching de patrones
            combined_text = f"{tool_name.lower()} {tool_desc}"

            for pattern_key, pattern_info in DANGEROUS_TOOL_PATTERNS.items():
                keywords = pattern_info["keywords"]
                severity = pattern_info["severity"]
                owasp    = pattern_info["owasp"]
                p_desc   = pattern_info["description"]

                matched_keywords = [kw for kw in keywords if kw in combined_text]
                if not matched_keywords:
                    continue

                # Verificar si hay restricciones documentadas en el schema
                restriction_evidence = self._find_path_restrictions(schema)

                # Si tiene restricciones documentadas, bajar severidad
                actual_severity = severity
                restriction_note = ""
                if restriction_evidence and severity in ("CRITICAL", "HIGH"):
                    actual_severity = "MEDIUM"
                    restriction_note = f" [Restricciones encontradas en schema: {restriction_evidence}]"

                self._add_finding(Finding(
                    tool=tool_name,
                    severity=actual_severity,
                    type=f"privilege_{pattern_key}",
                    title=f"[{tool_name}] {p_desc}",
                    description=(
                        f"La tool '{tool_name}' tiene capacidades de tipo '{pattern_key}' "
                        f"según el análisis de su nombre y descripción. {p_desc}. "
                        f"{restriction_note}"
                        "Este tipo de tool puede ser vector de ataque si el agente es comprometido "
                        f"o si se manipula mediante prompt injection (OWASP {owasp})."
                    ),
                    affected=f"tool:{tool_name}",
                    recommendation=self._get_privilege_recommendation(pattern_key),
                    phase=3,
                    owasp=owasp,
                    evidence=f"Keywords detectados: {matched_keywords}",
                ))
                privilege_findings += 1

            # Comprobar si el schema acepta rutas absolutas (riesgo de path traversal)
            self._check_path_traversal_risk(tool_name, schema)

        if privilege_findings == 0:
            self.console.print(
                "  [green]✓[/green] Sin tools con patrones de privilegio excesivo detectados"
            )
        else:
            self.console.print(
                f"  [bold yellow]⚠[/bold yellow] {privilege_findings} hallazgo(s) de privilegio detectados"
            )

    def _find_path_restrictions(self, schema: Dict) -> str:
        """
        Busca en el schema evidencia de restricciones de ruta o scope
        (ej: enums de directorios permitidos, patrones regex, etc.).

        Retorna una cadena descriptiva de la restricción encontrada o '' si no hay.
        """
        if not isinstance(schema, dict):
            return ""

        properties = schema.get("properties", {})
        for field_name, field_def in properties.items():
            if not isinstance(field_def, dict):
                continue
            # enum implica lista cerrada de valores permitidos (restricción)
            if "enum" in field_def:
                return f"campo '{field_name}' con enum de valores"
            # pattern implica validación de formato
            if "pattern" in field_def:
                return f"campo '{field_name}' con pattern de validación"

        return ""

    def _check_path_traversal_risk(self, tool_name: str, schema: Dict) -> None:
        """
        Detecta si el schema de la tool acepta parámetros de ruta de fichero
        sin restricciones evidentes, exponiendo riesgo de path traversal.
        """
        if not isinstance(schema, dict):
            return

        properties = schema.get("properties", {})
        path_field_pattern = re.compile(
            r"(path|file|directory|dir|folder|filename|filepath)", re.IGNORECASE
        )

        for field_name, field_def in properties.items():
            if not isinstance(field_def, dict):
                continue
            if not path_field_pattern.search(field_name):
                continue

            # Si tiene enum o pattern, está restringido
            if "enum" in field_def or "pattern" in field_def:
                continue

            # Si no tiene restricciones, potencial path traversal
            self._add_finding(Finding(
                tool=tool_name,
                severity="HIGH",
                type="path_traversal",
                title=f"[{tool_name}] Parámetro de ruta sin validación documentada",
                description=(
                    f"La tool '{tool_name}' acepta el parámetro '{field_name}' que parece "
                    "ser una ruta de fichero o directorio, pero el schema no define "
                    "restricciones de valor (enum, pattern o allowlist). Un agente comprometido "
                    "podría ser inducido a acceder a rutas arbitrarias del sistema."
                ),
                affected=f"tool:{tool_name}.inputSchema.properties.{field_name}",
                recommendation=(
                    "Implementar validación de ruta en el servidor MCP: usar un allowlist "
                    "de directorios permitidos, rechazar rutas absolutas o con '..', "
                    "y documentarlo en el schema con un campo 'pattern' o 'enum'."
                ),
                phase=3,
                owasp="A02",
                evidence=f"Campo: '{field_name}', sin restricciones de valor en schema",
            ))

    def _get_privilege_recommendation(self, pattern_key: str) -> str:
        """Retorna la recomendación estándar para cada categoría de riesgo de privilegio."""
        recommendations = {
            "filesystem_unrestricted": (
                "Implementar restricción de ruta mediante allowlist de directorios. "
                "Documentar en el schema qué rutas son accesibles. "
                "Evaluar si la tool necesita acceso a todo el sistema de ficheros."
            ),
            "shell_execution": (
                "Implementar sandboxing riguroso (contenedor, jaula chroot, seccomp). "
                "Limitar los comandos ejecutables a una lista blanca. "
                "Considerar eliminar esta tool si no es estrictamente necesaria."
            ),
            "network_unrestricted": (
                "Definir un scope de URLs/dominios permitidos y documentarlo en el schema. "
                "Implementar un proxy de egress con allowlist. "
                "Monitorizar todas las peticiones salientes del servidor MCP."
            ),
            "secrets_access": (
                "Evaluar si la tool necesita acceso a secretos. Si es necesario, "
                "implementar control de acceso granular y auditoría de cada acceso. "
                "Nunca exponer el valor del secreto completo al agente."
            ),
            "data_exfiltration": (
                "Documentar todos los destinos de datos en el schema. "
                "Implementar aprobación explícita del usuario antes de transmitir datos. "
                "Registrar en log cada transmisión de datos con el destino y el contenido."
            ),
            "memory_context": (
                "Auditar qué datos se persisten en memoria. "
                "Implementar scoping de memoria por sesión con TTL. "
                "No permitir que el agente modifique su propia memoria sin supervisión."
            ),
            "code_execution": (
                "Aislar el intérprete de código en un sandbox sin acceso a red ni ficheros. "
                "Limitar tiempo de ejecución y uso de recursos. "
                "Auditar todo el código ejecutado y sus outputs."
            ),
            "system_info": (
                "Evaluar qué información del sistema es realmente necesaria para la tool. "
                "Filtrar la información devuelta para excluir datos sensibles. "
                "Documentar el alcance de la tool en su description."
            ),
        }
        return recommendations.get(pattern_key, "Revisar la necesidad de esta capacidad y aplicar el principio de menor privilegio.")

    # -----------------------------------------------------------------------
    # FASE 4: Seguridad del Transporte
    # -----------------------------------------------------------------------

    async def audit_transport(self, session: aiohttp.ClientSession) -> None:
        """
        Evalúa la seguridad del mecanismo de transporte utilizado por el servidor MCP.

        Comprueba:
        - TLS: si el servidor usa HTTPS con certificado válido
        - CORS: si el servidor acepta cualquier origen
        - Autenticación: si el endpoint SSE o HTTP requiere credenciales
        - Headers de seguridad HTTP estándar
        """
        scheme = self.parsed_url.scheme
        host   = self.parsed_url.netloc
        path   = self.parsed_url.path or "/"

        # --- Comprobación 1: Uso de HTTP en lugar de HTTPS ---
        if scheme == "http":
            is_localhost = (
                "localhost" in host or
                "127.0.0.1" in host or
                "::1" in host or
                host.startswith("10.") or
                host.startswith("192.168.") or
                host.startswith("172.")
            )
            severity = "MEDIUM" if is_localhost else "HIGH"
            self._add_finding(Finding(
                tool="server",
                severity=severity,
                type="transport_tls",
                title="Servidor MCP accesible por HTTP sin cifrado",
                description=(
                    f"El servidor MCP está expuesto en HTTP plano ({self.target}). "
                    "Las comunicaciones entre el agente IA y el servidor MCP, incluyendo "
                    "herramientas disponibles, parámetros y resultados, viajan en claro "
                    "y son susceptibles a interceptación y manipulación (MITM)."
                ),
                affected=self.target,
                recommendation=(
                    "Configurar TLS en el servidor MCP. En desarrollo local es aceptable, "
                    "pero en cualquier red compartida o producción es obligatorio. "
                    "Usar un reverse proxy (nginx, caddy) con certificado válido."
                ),
                phase=4,
            ))
        else:
            # Verificar validez del certificado TLS
            await self._check_tls_certificate(host)

        # --- Comprobación 2: Headers de seguridad HTTP ---
        await self._check_security_headers(session)

        # --- Comprobación 3: CORS ---
        await self._check_cors(session)

        # --- Comprobación 4: Endpoint SSE sin autenticación ---
        await self._check_sse_endpoint(session)

        # --- Comprobación 5: Inyección de parámetros STDIO (OX Security abr-2026) ---
        self._check_stdio_injection_risk()

    async def _check_tls_certificate(self, host: str) -> None:
        """Verifica la validez del certificado TLS del servidor."""
        hostname = host.split(":")[0]
        port     = int(host.split(":")[1]) if ":" in host else 443

        try:
            ctx = ssl.create_default_context()
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: socket.create_connection((hostname, port), timeout=5)
            )
            self.console.print(f"  [green]✓[/green] TLS habilitado en {hostname}:{port}")
        except ssl.SSLCertVerificationError as exc:
            self._add_finding(Finding(
                tool="server",
                severity="HIGH",
                type="transport_tls",
                title="Certificado TLS inválido o no confiable",
                description=(
                    f"El certificado TLS del servidor no pasa la verificación estándar: {exc}. "
                    "Los clientes que deshabilitan la verificación TLS para conectarse "
                    "son vulnerables a ataques MITM, donde un atacante puede interceptar "
                    "y modificar las tools disponibles y sus respuestas."
                ),
                affected=host,
                recommendation=(
                    "Obtener un certificado válido de una CA reconocida (Let's Encrypt, etc). "
                    "No usar certificados auto-firmados en producción. "
                    "Nunca deshabilitar la verificación TLS en el cliente MCP."
                ),
                phase=4,
                evidence=str(exc),
            ))
        except Exception:
            pass  # Error de conectividad, ya reportado en Fase 1

    async def _check_security_headers(self, session: aiohttp.ClientSession) -> None:
        """
        Verifica la presencia de headers de seguridad HTTP relevantes
        en la respuesta del servidor MCP.
        """
        try:
            async with session.get(
                self.target,
                ssl=False,
                allow_redirects=True,
            ) as resp:
                headers = resp.headers

                # Content-Security-Policy
                if not headers.get("Content-Security-Policy"):
                    self._add_finding(Finding(
                        tool="server",
                        severity="LOW",
                        type="transport_headers",
                        title="Header Content-Security-Policy ausente",
                        description=(
                            "El servidor no establece el header Content-Security-Policy. "
                            "En servidores MCP con interfaz web o que sirven contenido HTML, "
                            "esto puede facilitar ataques XSS que comprometan el cliente."
                        ),
                        affected="HTTP headers",
                        recommendation="Añadir header CSP restrictivo en la configuración del servidor.",
                        phase=4,
                    ))

                # X-Frame-Options
                if not headers.get("X-Frame-Options") and not headers.get("Content-Security-Policy"):
                    self._add_finding(Finding(
                        tool="server",
                        severity="LOW",
                        type="transport_headers",
                        title="Headers anti-clickjacking ausentes",
                        description=(
                            "El servidor no establece X-Frame-Options ni CSP con frame-ancestors. "
                            "Aunque el impacto en servidores MCP puros es limitado, la ausencia "
                            "de estos headers indica una configuración de seguridad básica incompleta."
                        ),
                        affected="HTTP headers",
                        recommendation="Añadir 'X-Frame-Options: DENY' o 'Content-Security-Policy: frame-ancestors none'.",
                        phase=4,
                    ))

                # Strict-Transport-Security (solo para HTTPS)
                if self.is_https and not headers.get("Strict-Transport-Security"):
                    self._add_finding(Finding(
                        tool="server",
                        severity="MEDIUM",
                        type="transport_headers",
                        title="Header HSTS ausente en servidor HTTPS",
                        description=(
                            "El servidor usa HTTPS pero no establece Strict-Transport-Security. "
                            "Sin HSTS, un atacante puede forzar downgrade a HTTP en el primer "
                            "contacto del cliente, interceptando la comunicación."
                        ),
                        affected="HTTP headers",
                        recommendation="Añadir 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
                        phase=4,
                    ))

        except Exception:
            pass  # No reportar error de headers si el servidor no responde a GET

    async def _check_cors(self, session: aiohttp.ClientSession) -> None:
        """
        Verifica si el servidor MCP acepta cualquier origen en sus headers CORS,
        lo que permitiría a páginas web arbitrarias interactuar con el servidor.
        """
        try:
            async with session.options(
                self.target,
                ssl=False,
                headers={
                    "Origin":                        "https://evil.vampsecurestudios.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            ) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")

                if acao == "*":
                    self._add_finding(Finding(
                        tool="server",
                        severity="HIGH",
                        type="transport_cors",
                        title="CORS abierto: servidor acepta cualquier origen (*)",
                        description=(
                            "El servidor MCP devuelve 'Access-Control-Allow-Origin: *' para "
                            "peticiones OPTIONS. Esto permite que cualquier página web realice "
                            "peticiones JSON-RPC al servidor MCP desde el navegador del usuario, "
                            "potencialmente ejecutando tools maliciosas en su nombre."
                        ),
                        affected="Access-Control-Allow-Origin: *",
                        recommendation=(
                            "Restringir CORS a los orígenes legítimos del cliente MCP. "
                            "Si el servidor no necesita ser accesible desde navegadores, "
                            "deshabilitar CORS completamente. "
                            "Nunca usar '*' en servidores con capacidades destructivas."
                        ),
                        phase=4,
                        evidence=f"Respuesta a Origin: evil.vampsecurestudios.com → ACAO: {acao}",
                    ))
                elif acao:
                    self.console.print(f"  [green]✓[/green] CORS restringido: {acao}")

        except Exception:
            pass  # Servidor puede no soportar OPTIONS, no es un hallazgo

    async def _check_sse_endpoint(self, session: aiohttp.ClientSession) -> None:
        """
        Verifica si el endpoint SSE del servidor MCP requiere autenticación.
        Los endpoints SSE sin auth permiten suscripción anónima a eventos del agente.
        """
        sse_candidates = ["/sse", "/events", "/stream", "/mcp/sse", "/v1/sse"]

        for sse_path in sse_candidates:
            url = f"{self.target}{sse_path}"
            try:
                async with session.get(
                    url,
                    ssl=False,
                    headers={"Accept": "text/event-stream"},
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    content_type = resp.headers.get("Content-Type", "")
                    if resp.status == 200 and "event-stream" in content_type:
                        self._add_finding(Finding(
                            tool="server",
                            severity="HIGH",
                            type="transport_sse",
                            title=f"Endpoint SSE accesible sin autenticación: {sse_path}",
                            description=(
                                f"El endpoint SSE '{url}' responde sin requerir autenticación "
                                "y devuelve un stream de tipo 'text/event-stream'. "
                                "Un atacante puede suscribirse al stream de eventos del agente "
                                "y observar todas las acciones, resultados y datos procesados "
                                "en tiempo real."
                            ),
                            affected=url,
                            recommendation=(
                                "Proteger el endpoint SSE con autenticación (token en query param "
                                "o header Authorization). Validar el token antes de abrir el stream."
                            ),
                            phase=4,
                            evidence=f"HTTP 200 + Content-Type: {content_type}",
                        ))
                    elif resp.status == 401:
                        self.console.print(
                            f"  [green]✓[/green] Endpoint SSE {sse_path} requiere autenticación (401)"
                        )
            except Exception:
                pass  # Endpoint no existe o no responde, no es hallazgo

    def _check_stdio_injection_risk(self) -> None:
        """
        Registra el riesgo de inyección de parámetros en transporte STDIO
        (vulnerabilidad publicada por OX Security en abril 2026, CVSS 9.8).

        Esta vulnerabilidad afecta a cualquier servidor MCP que acepte argumentos
        de línea de comandos sin sanitización y los pase directamente al shell,
        permitiendo a un servidor MCP malicioso ejecutar comandos arbitrarios.
        """
        # Si el target es HTTP, el servidor es HTTP no STDIO, pero informamos
        # del riesgo de la vulnerabilidad en caso de que también tenga modo STDIO
        self._add_finding(Finding(
            tool="server",
            severity="INFO",
            type="transport_stdio",
            title="Verificación requerida: riesgo de inyección STDIO (CVE OX Security abr-2026)",
            description=(
                "La vulnerabilidad de inyección de parámetros en transporte STDIO "
                "(publicada por OX Security en abril 2026, CVSS 9.8) afecta a servidores MCP "
                "que lanzan procesos externos pasando argumentos sin sanitización. "
                "Si este servidor también soporta transporte STDIO, verificar manualmente "
                "que los parámetros de inicio no se pasan directamente al shell. "
                "Vectores de riesgo: espacios en rutas, caracteres especiales ($, `, ;, &)."
            ),
            affected="Transporte STDIO (si aplica al servidor auditado)",
            recommendation=(
                "En servidores STDIO: usar exec() directo sin shell=True. "
                "Nunca construir la línea de comandos concatenando strings. "
                "Usar listas de argumentos: ['python', script_path, arg1] en lugar de "
                "f'python {script_path} {arg1}'. Validar y sanitizar todos los argumentos."
            ),
            phase=4,
            evidence="Referencia: OX Security MCP STDIO Injection, abril 2026, CVSS 9.8",
        ))

    # -----------------------------------------------------------------------
    # FASE 5: Evaluación de Riesgo Agéntico (OWASP Agentic AI Top 10 2026)
    # -----------------------------------------------------------------------

    def assess_agentic_risk(
        self,
        tools: List[Dict],
        findings: List[Finding],
    ) -> Dict[str, Any]:
        """
        Calcula el risk score agregado del servidor MCP basándose en los hallazgos
        de las fases anteriores, mapeando cada hallazgo a las categorías del
        OWASP Agentic AI Top 10 2026 y generando un resumen de riesgo global.

        Retorna un dict con el score total, la distribución por categoría OWASP
        y la recomendación de nivel de riesgo global.
        """
        # Pesos de riesgo por severidad
        SEVERITY_WEIGHTS = {
            "CRITICAL": 10,
            "HIGH":      5,
            "MEDIUM":    2,
            "LOW":       1,
            "INFO":      0,
        }

        # Contadores por categoría OWASP
        owasp_counts: Dict[str, int] = {k: 0 for k in OWASP_AGENTIC_TOP10}
        owasp_scores: Dict[str, int] = {k: 0 for k in OWASP_AGENTIC_TOP10}
        total_score   = 0

        for finding in findings:
            weight = SEVERITY_WEIGHTS.get(finding.severity, 0)
            total_score += weight

            if finding.owasp and finding.owasp in owasp_counts:
                owasp_counts[finding.owasp] += 1
                owasp_scores[finding.owasp] += weight

        # Determinar nivel de riesgo global
        if total_score >= 40:
            risk_level = "CRÍTICO"
            risk_color = "bold red"
        elif total_score >= 20:
            risk_level = "ALTO"
            risk_color = "bold yellow"
        elif total_score >= 8:
            risk_level = "MEDIO"
            risk_color = "bold magenta"
        elif total_score > 0:
            risk_level = "BAJO"
            risk_color = "cyan"
        else:
            risk_level = "INFORMATIVO"
            risk_color = "green"

        # Mostrar tabla OWASP en consola
        self.console.print()
        owasp_tbl = Table(
            title="OWASP Agentic AI Top 10 — Distribución de riesgo",
            show_header=True,
            header_style="bold blue",
            box=box.ROUNDED,
        )
        owasp_tbl.add_column("Código",    style="bold cyan", no_wrap=True, width=6)
        owasp_tbl.add_column("Categoría", style="white",     width=30)
        owasp_tbl.add_column("Hallazgos", justify="right",   width=10)
        owasp_tbl.add_column("Score",     justify="right",   width=8)

        for code, info in OWASP_AGENTIC_TOP10.items():
            count = owasp_counts[code]
            score = owasp_scores[code]
            style = "bold red" if score >= 10 else ("yellow" if score >= 5 else "dim")
            owasp_tbl.add_row(
                code,
                info["name"],
                str(count) if count > 0 else "-",
                str(score) if score > 0 else "-",
                style=style if count > 0 else "dim",
            )

        self.console.print(owasp_tbl)

        self.console.print()
        self.console.print(Panel(
            f"  RISK SCORE TOTAL: [bold]{total_score}[/bold]   "
            f"NIVEL DE RIESGO: [{risk_color}]{risk_level}[/{risk_color}]",
            title="[bold white]Evaluación de Riesgo Agéntico[/bold white]",
            border_style="red" if total_score >= 20 else "yellow",
        ))

        return {
            "total_score":   total_score,
            "risk_level":    risk_level,
            "owasp_counts":  owasp_counts,
            "owasp_scores":  owasp_scores,
            "tool_count":    len(tools),
            "finding_count": len(findings),
        }

    # -----------------------------------------------------------------------
    # FASE 6: Context Window Overflow — superficie de descripciones de tools
    # -----------------------------------------------------------------------

    async def audit_context_overflow(self, tools: List[Dict]) -> None:
        """
        Fase 6: Análisis de agotamiento de ventana de contexto mediante
        descripciones de herramientas.

        Calcula el tamaño acumulado de todas las descripciones de tools y alerta
        si supera los umbrales configurados. Un servidor MCP malicioso puede usar
        descripciones excesivamente largas para consumir la ventana de contexto
        del agente LLM cliente, desplazando instrucciones legítimas del sistema
        y facilitando ataques de prompt injection por overflow.

        Hallazgos posibles
        ------------------
        MCP-CTX-001 : Agotamiento de ventana de contexto por descripciones (HIGH)  → Fase 9
        MCP-CTX-002 : Superficie de descripciones grande (MEDIUM)                  → Fase 9
        """
        # Tamaño total acumulado de todas las descripciones de tools (en caracteres)
        total_chars = sum(len(t.get("description", "")) for t in tools)

        # Umbral MEDIUM: ~8000 tokens estimados (≈ 8000 chars con ratio 1:1 aprox.)
        UMBRAL_MEDIUM = 8000
        # Umbral HIGH: configurable via --ctx-limit (default 32000 chars)
        umbral_high   = self.ctx_limit

        self._log(
            f"Tamaño acumulado de descripciones: {total_chars} caracteres "
            f"(umbral HIGH: {umbral_high}, MEDIUM: {UMBRAL_MEDIUM})"
        )

        if total_chars > umbral_high:
            # Identificar las tools con las descripciones más largas
            tools_ordenadas = sorted(
                tools,
                key=lambda t: len(t.get("description", "")),
                reverse=True,
            )
            top_tools = [
                f"{t.get('name','?')} ({len(t.get('description',''))} chars)"
                for t in tools_ordenadas[:5]
            ]
            self._add_finding(Finding(
                tool="context",
                severity="HIGH",
                type="context_overflow",
                title="Agotamiento de ventana de contexto vía descripciones de tools",
                description=(
                    f"El tamaño acumulado de las descripciones de las {len(tools)} tools "
                    f"inventariadas es de {total_chars} caracteres, superando el umbral de "
                    f"{umbral_high} caracteres configurado. Un agente LLM que cargue todas "
                    "estas tools en su contexto puede ver desplazadas instrucciones del "
                    "sistema prompt, facilitando ataques de prompt injection por overflow "
                    "y comportamientos impredecibles del agente."
                ),
                affected=f"{self.target} → tools/list",
                recommendation=(
                    "Reducir la longitud de las descripciones de tools al mínimo necesario "
                    "para que el agente comprenda su propósito. Las descripciones de tools "
                    "no deben superar los 500 caracteres. Separar la documentación extensa "
                    "en campos de ayuda secundarios, no en la descripción principal."
                ),
                phase=9,
                owasp="A02",
                evidence=(
                    f"Total chars: {total_chars} / umbral {umbral_high}. "
                    f"Tools más largas: {', '.join(top_tools)}"
                ),
            ))
        elif total_chars > UMBRAL_MEDIUM:
            self._add_finding(Finding(
                tool="context",
                severity="MEDIUM",
                type="context_overflow",
                title="Superficie de descripciones de tools grande",
                description=(
                    f"El tamaño acumulado de las descripciones de las {len(tools)} tools "
                    f"es de {total_chars} caracteres (~{total_chars // 4} tokens estimados), "
                    f"superando los {UMBRAL_MEDIUM} caracteres. Aunque no supera el umbral "
                    "crítico, representa una superficie de contexto considerable que puede "
                    "degradar la calidad de razonamiento del agente LLM cliente."
                ),
                affected=f"{self.target} → tools/list",
                recommendation=(
                    "Revisar y reducir las descripciones de tools más largas. "
                    "Apuntar a descripciones concisas (< 200 caracteres) centradas en "
                    "el propósito de la tool, no en su implementación."
                ),
                phase=9,
                evidence=f"Total chars: {total_chars} / umbral MEDIUM {UMBRAL_MEDIUM}",
            ))
        else:
            self.console.print(
                f"  [green]✓[/green] Tamaño de descripciones OK: "
                f"[dim]{total_chars} chars[/dim] (umbral: {umbral_high})"
            )

    # -----------------------------------------------------------------------
    # FASE 5: Tool Poisoning Scanner Extendido
    # -----------------------------------------------------------------------

    async def audit_tool_poisoning_scanner(self, tools: List[Dict]) -> None:
        """
        FASE 5: Escáner extendido de tool poisoning con tres vectores específicos:

        MCP-POISON-001 (CRITICAL): Caracteres Unicode Tags ocultos en description
          o en valores del inputSchema (ASCII smuggling invisible para el humano).
        MCP-POISON-002 (HIGH): Instrucciones ocultas en texto plano en description
          o en enum values del schema (ignore previous, override, system:, etc.).
        MCP-POISON-003 (MEDIUM): Ratio description/nombre mayor de 20:1 — indicador
          de contenido oculto o instrucciones embebidas en una description desproporcionada.

        Complementa la Fase 2 (patrones avanzados de inyección) con estos detectores
        más directos y con IDs de finding normalizados para correlación.
        """
        if not tools:
            self.console.print("  [yellow]⚠[/yellow] Sin tools para analizar en Fase 5")
            return

        # Patrones de instrucción oculta en texto plano (simples y directos)
        _PATRONES_INSTRUCCION_OCULTA: List[re.Pattern] = [
            re.compile(r"ignore\s+previous",           re.IGNORECASE),
            re.compile(r"\bdisregard\b",                re.IGNORECASE),
            re.compile(r"\boverride\b",                 re.IGNORECASE),
            re.compile(r"system\s*:",                   re.IGNORECASE),
            re.compile(r"assistant\s*:",                re.IGNORECASE),
            re.compile(r"<\s*system\s*>",               re.IGNORECASE),
            re.compile(r"\bAct\s+as\b",                 re.IGNORECASE),
            re.compile(r"you\s+are\s+now",              re.IGNORECASE),
            re.compile(r"new\s+instructions",           re.IGNORECASE),
            # Patrones adicionales: inyección directa de comandos de sistema
            re.compile(r"SYSTEM\s+OVERRIDE",            re.IGNORECASE),
            re.compile(r"<!--\s*HIDDEN\s*:",            re.IGNORECASE),
        ]

        # Patrón de caracteres Unicode invisibles de anchura cero (U+200B–U+200F, U+FEFF)
        _RE_ZERO_WIDTH = re.compile(
            r"[​‌‍‎‏﻿]"
        )

        hallazgos_count = 0

        for tool in tools:
            tool_name = tool.get("name", "sin_nombre")
            desc      = tool.get("description") or ""
            schema    = tool.get("inputSchema") or {}

            # Extraer valores de texto del schema (enum values + descriptions de campos)
            schema_vals = _extraer_valores_schema(schema)

            # ── MCP-POISON-001: Unicode Tags ocultos ─────────────────────────────
            encontrado_desc, decodificado_desc, num_desc = _detectar_ascii_smuggling_mcp(desc)

            # Verificar también en valores del inputSchema
            encontrado_schema = False
            decodificado_schema = ""
            num_schema = 0
            for val in schema_vals:
                enc, dec, n = _detectar_ascii_smuggling_mcp(val)
                if enc:
                    encontrado_schema = True
                    decodificado_schema += dec + " "
                    num_schema += n

            if encontrado_desc or encontrado_schema:
                total_chars   = num_desc + num_schema
                decoded_joint = " | ".join(
                    filter(None, [decodificado_desc, decodificado_schema.strip()])
                )
                ubicacion = (
                    "description e inputSchema"
                    if encontrado_desc and encontrado_schema
                    else ("description" if encontrado_desc else "inputSchema")
                )
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="CRITICAL",
                    type="MCP-POISON-001",
                    title=f"[{tool_name}] MCP-POISON-001: Unicode Tags ocultos detectados",
                    description=(
                        f"La tool '{tool_name}' contiene {total_chars} caracteres Unicode Tags "
                        f"invisibles (U+E0000-U+E007F) en su {ubicacion}. "
                        "Estos caracteres son completamente invisibles para el humano en cualquier "
                        "inspector visual, pero el LLM los procesa con normalidad, permitiendo "
                        "prompt injection indetectable (ASCII smuggling)."
                    ),
                    affected=f"tool:{tool_name}",
                    recommendation=(
                        "Rechazar cualquier tool cuya description o inputSchema contenga caracteres "
                        "del bloque Unicode Tags (U+E0000-U+E007F). Implementar validación Unicode "
                        "estricta en el proxy o gateway MCP."
                    ),
                    phase=5,
                    owasp="A01",
                    evidence=(
                        f"Chars Unicode Tags: {total_chars}. Decodificado: '{decoded_joint[:200]}'"
                        if decoded_joint
                        else f"Chars Unicode Tags invisibles: {total_chars}"
                    ),
                ))
                hallazgos_count += 1

            # ── MCP-POISON-001b: Caracteres Unicode de anchura cero (U+200B–U+200F, U+FEFF) ─
            # Estos caracteres son invisibles y distintos del bloque Tags anterior
            textos_zw = [("description", desc)] + [("schema_val", v) for v in schema_vals if v]
            for fuente_zw, texto_zw in textos_zw:
                if not texto_zw:
                    continue
                matches_zw = _RE_ZERO_WIDTH.findall(texto_zw)
                if matches_zw:
                    nombres_chars = {
                        "​": "U+200B (ZWSP)",
                        "‌": "U+200C (ZWNJ)",
                        "‍": "U+200D (ZWJ)",
                        "‎": "U+200E (LRM)",
                        "‏": "U+200F (RLM)",
                        "﻿": "U+FEFF (BOM/ZWNBS)",
                    }
                    chars_detectados = ", ".join(
                        sorted({nombres_chars.get(c, f"U+{ord(c):04X}") for c in matches_zw})
                    )
                    self._add_finding(Finding(
                        tool=tool_name,
                        severity="CRITICAL",
                        type="MCP-POISON-001b",
                        title=(
                            f"[{tool_name}] MCP-POISON-001b: Caracteres Unicode "
                            "invisibles (zero-width) en descripción de tool"
                        ),
                        description=(
                            f"La tool '{tool_name}' contiene {len(matches_zw)} caracter(es) "
                            f"Unicode invisible(s) ({chars_detectados}) en su {fuente_zw}. "
                            "Estos caracteres de anchura cero son imperceptibles en editores "
                            "de texto e inspectores visuales, pero los LLMs los procesan con "
                            "normalidad. Un servidor MCP malicioso puede usar estos caracteres "
                            "para ocultar instrucciones de prompt injection indetectables por "
                            "el auditor humano."
                        ),
                        affected=f"tool:{tool_name}.{fuente_zw}",
                        recommendation=(
                            "Rechazar tools cuya description o inputSchema contenga caracteres "
                            "Unicode de anchura cero (U+200B–U+200F, U+FEFF). Implementar un "
                            "filtro de normalización Unicode (NFKC) en el proxy MCP para "
                            "descartar o alertar sobre estos caracteres."
                        ),
                        phase=5,
                        owasp="A01",
                        evidence=(
                            f"{len(matches_zw)} chars invisibles en {fuente_zw}: {chars_detectados}. "
                            f"Fragmento: '{texto_zw[:100]}'"
                        ),
                    ))
                    hallazgos_count += 1
                    break  # Un hallazgo por tool

            # ── MCP-POISON-002: Instrucciones ocultas en texto plano ──────────────
            # Buscar en description y en los valores del schema
            textos_a_revisar = [("description", desc)] + [
                ("schema_val", v) for v in schema_vals if v
            ]
            poison002_encontrado = False
            for fuente, texto in textos_a_revisar:
                if not texto or poison002_encontrado:
                    continue
                for patron in _PATRONES_INSTRUCCION_OCULTA:
                    match = patron.search(texto)
                    if match:
                        self._add_finding(Finding(
                            tool=tool_name,
                            severity="HIGH",
                            type="MCP-POISON-002",
                            title=f"[{tool_name}] MCP-POISON-002: Instrucción oculta en texto plano",
                            description=(
                                f"La tool '{tool_name}' contiene un patrón de instrucción oculta "
                                f"en {fuente}: '{match.group(0)}'. Este tipo de instrucción "
                                "está diseñado para manipular el comportamiento del agente LLM "
                                "que procese la descripción de esta tool."
                            ),
                            affected=f"tool:{tool_name}",
                            recommendation=(
                                "Eliminar o aislar la tool. Revisar el origen del servidor MCP "
                                "y auditar los logs del agente para detectar comportamiento previo anómalo."
                            ),
                            phase=5,
                            owasp="A01",
                            evidence=(
                                f"Patrón: '{patron.pattern}' → '{match.group(0)[:100]}' "
                                f"en {fuente}: '{texto[:150]}'"
                            ),
                        ))
                        hallazgos_count += 1
                        poison002_encontrado = True
                        break  # Un hallazgo por tool (evitar duplicados)
                if poison002_encontrado:
                    break

            # ── MCP-POISON-003: Ratio description/nombre > 20:1 ──────────────────
            nombre_len = len(tool_name)
            desc_len   = len(desc)
            if nombre_len > 0 and desc_len > 0:
                ratio = desc_len / nombre_len
                if ratio > 20:
                    self._add_finding(Finding(
                        tool=tool_name,
                        severity="MEDIUM",
                        type="MCP-POISON-003",
                        title=f"[{tool_name}] MCP-POISON-003: Description sospechosamente larga vs nombre",
                        description=(
                            f"La tool '{tool_name}' (nombre: {nombre_len} chars) tiene una "
                            f"description de {desc_len} caracteres, con un ratio "
                            f"description/nombre de {ratio:.1f}:1 (umbral: 20:1). "
                            "Descriptions desproporcionadamente largas respecto al nombre de la "
                            "tool son un indicador habitual de contenido oculto o instrucciones "
                            "embebidas para el agente."
                        ),
                        affected=f"tool:{tool_name}.description",
                        recommendation=(
                            "Revisar la description completa de la tool. Las descriptions deben "
                            "ser concisas y proporcionales al nombre y función de la tool."
                        ),
                        phase=5,
                        owasp="A01",
                        evidence=(
                            f"Nombre: {nombre_len} chars, Description: {desc_len} chars, "
                            f"Ratio: {ratio:.1f}:1"
                        ),
                    ))
                    hallazgos_count += 1

        if hallazgos_count == 0:
            self.console.print(
                "  [green]✓[/green] Sin indicadores de tool poisoning avanzados (Fase 5)"
            )
        else:
            self.console.print(
                f"  [bold red]✗[/bold red] {hallazgos_count} hallazgo(s) de tool poisoning avanzado"
            )

    # -----------------------------------------------------------------------
    # FASE 6: SSRF via Parámetros de Tool
    # -----------------------------------------------------------------------

    async def audit_ssrf_parameters(
        self,
        session: aiohttp.ClientSession,
        tools: List[Dict],
    ) -> None:
        """
        FASE 6: Prueba activa de SSRF mediante parámetros de tool que aceptan
        URLs o endpoints. Solo se ejecuta si se pasa --test-ssrf (opt-in).

        Para cada tool con parámetros sospechosos (url, endpoint, host, target,
        uri, path, webhook, callback, redirect, proxy, server, address), invoca
        la tool con payloads SSRF y analiza la respuesta:

        MCP-SSRF-001 (CRITICAL): SSRF confirmado — respuesta contiene indicadores
          de metadata cloud (AWS/GCP/Azure).
        MCP-SSRF-002 (HIGH): SSRF potencial — la tool devolvió respuesta no vacía
          y no error de red al recibir una URL interna como parámetro.
        """
        if not self.test_ssrf:
            self.console.print(
                "  [dim]↳ Fase 6 SSRF desactivada (pasar --test-ssrf para activar pruebas activas)[/dim]"
            )
            return

        if not tools:
            self.console.print("  [yellow]⚠[/yellow] Sin tools para analizar SSRF en Fase 6")
            return

        # Nombres de parámetros que sugieren entrada de URL o endpoint remoto
        PARAMS_SSRF_CANDIDATOS = {
            "url", "endpoint", "host", "target", "uri", "path",
            "webhook", "callback", "redirect", "proxy", "server", "address",
        }

        # Payloads SSRF: endpoints de metadata cloud y redes internas
        PAYLOADS_SSRF = [
            "http://169.254.169.254/latest/meta-data/",          # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            "http://169.254.169.254/metadata/instance",          # Azure metadata
            "http://127.0.0.1:80/",                              # localhost
            "http://10.0.0.1/",                                  # red interna típica
        ]

        # Indicadores en la respuesta que confirman SSRF exitoso a metadata cloud
        CONFIRMADORES_SSRF = [
            "ami-id", "instance-type", "instance-id", "local-ipv4", "local-hostname",
            "computeMetadata", "serviceAccounts",
            "subscriptionId", "resourceGroupName",
        ]

        ssrf_count = 0

        for tool in tools:
            tool_name  = tool.get("name", "sin_nombre")
            schema     = tool.get("inputSchema") or {}
            properties = schema.get("properties", {}) if isinstance(schema, dict) else {}

            # Filtrar parámetros candidatos de tipo string sin enum (sin restricciones)
            params_candidatos = [
                fname for fname, fdef in properties.items()
                if fname.lower() in PARAMS_SSRF_CANDIDATOS
                and isinstance(fdef, dict)
                and fdef.get("type", "string") == "string"
                and "enum" not in fdef
            ]

            if not params_candidatos:
                continue

            self._log(f"Tool '{tool_name}': parámetros SSRF candidatos: {params_candidatos}")

            # Probar cada parámetro candidato con cada payload SSRF
            for param_name in params_candidatos:
                critico_ya_reportado = False
                for payload in PAYLOADS_SSRF:
                    if critico_ya_reportado:
                        break
                    try:
                        resp = await self._json_rpc(session, "tools/call", {
                            "name":      tool_name,
                            "arguments": {param_name: payload},
                        })

                        if resp is None:
                            continue  # Sin respuesta — no es indicador

                        resp_str = json.dumps(resp).lower()

                        # Verificar SSRF confirmado por indicadores de metadata cloud
                        if any(ind.lower() in resp_str for ind in CONFIRMADORES_SSRF):
                            self._add_finding(Finding(
                                tool=tool_name,
                                severity="CRITICAL",
                                type="MCP-SSRF-001",
                                title=f"[{tool_name}] MCP-SSRF-001: SSRF confirmado a metadata cloud",
                                description=(
                                    f"La tool '{tool_name}' es vulnerable a SSRF: al invocar "
                                    f"'{param_name}' con la URL '{payload}', la respuesta contiene "
                                    "indicadores de metadata cloud (AWS/GCP/Azure), confirmando "
                                    "que el servidor MCP realizó la petición al endpoint interno."
                                ),
                                affected=f"tool:{tool_name}.{param_name}",
                                recommendation=(
                                    "Implementar validación estricta de URLs: allowlist de dominios "
                                    "permitidos, rechazo de rangos IP privados (RFC 1918, "
                                    "169.254.0.0/16) y bloqueo de metadata endpoints cloud. "
                                    "Usar un proxy de egress con controles de acceso."
                                ),
                                phase=6,
                                owasp="A04",
                                evidence=(
                                    f"Payload: {payload}, "
                                    f"Respuesta (fragmento): {json.dumps(resp)[:300]}"
                                ),
                            ))
                            ssrf_count += 1
                            critico_ya_reportado = True
                            break

                        # SSRF potencial: respuesta no vacía, sin error de red
                        result = resp.get("result")
                        error  = resp.get("error")
                        if result and not error:
                            resp_snippet = json.dumps(result)
                            # Excluir respuestas de error de validación de la propia tool
                            indicadores_error = (
                                "invalid", "error", "not found", "failed",
                                "connection refused", "timeout",
                            )
                            if len(resp_snippet) > 10 and not any(
                                kw in resp_snippet.lower() for kw in indicadores_error
                            ):
                                self._add_finding(Finding(
                                    tool=tool_name,
                                    severity="HIGH",
                                    type="MCP-SSRF-002",
                                    title=f"[{tool_name}] MCP-SSRF-002: SSRF potencial detectado",
                                    description=(
                                        f"La tool '{tool_name}' devolvió una respuesta no vacía "
                                        f"al invocar '{param_name}' con la URL SSRF '{payload}'. "
                                        "Esto sugiere que el servidor realizó la petición HTTP "
                                        "al endpoint indicado sin validar el destino."
                                    ),
                                    affected=f"tool:{tool_name}.{param_name}",
                                    recommendation=(
                                        "Validar y restringir las URLs aceptadas: allowlist de "
                                        "dominios y bloqueo de rangos IP privados."
                                    ),
                                    phase=6,
                                    owasp="A04",
                                    evidence=(
                                        f"Payload: {payload}, "
                                        f"Respuesta: {resp_snippet[:200]}"
                                    ),
                                ))
                                ssrf_count += 1
                                break  # Un hallazgo HIGH por parámetro

                    except Exception as exc:
                        self._log(
                            f"Error en prueba SSRF para {tool_name}.{param_name}: {exc}"
                        )
                        continue

        if ssrf_count == 0:
            self.console.print(
                "  [green]✓[/green] Sin vulnerabilidades SSRF detectadas en parámetros de tools"
            )
        else:
            self.console.print(
                f"  [bold red]✗[/bold red] {ssrf_count} hallazgo(s) SSRF detectados"
            )

    # -----------------------------------------------------------------------
    # FASE 7: Rug Pull Detection
    # -----------------------------------------------------------------------

    async def audit_rug_pull(
        self,
        session: aiohttp.ClientSession,
        tools_inicial: List[Dict],
    ) -> None:
        """
        FASE 7: Detección de rug pull — redefinición dinámica de tools entre
        llamadas. Llama a tools/list por segunda vez y compara con el snapshot
        tomado al inicio de la auditoría (Fase 1).

        Un servidor MCP malicioso puede presentar tools benignas en el handshake
        y reemplazarlas por versiones envenenadas después, sabiendo que el auditor
        o el agente ya ha evaluado la lista original.

        MCP-RUGPULL-001 (HIGH):
          - Tool nueva entre llamadas (no estaba en el snapshot inicial)
          - Tool que cambió description o inputSchema entre llamadas
        """
        self._log("Segunda llamada a tools/list para detección de rug pull")
        resp = await self._json_rpc(session, "tools/list")

        if resp is None:
            self.console.print(
                "  [yellow]⚠[/yellow] No se pudo obtener segunda lista de tools para rug pull"
            )
            return

        result     = resp.get("result", {})
        tools_final = result.get("tools", [])

        # Índice por nombre para comparación O(1)
        inicial_idx = {t.get("name"): t for t in tools_inicial}
        final_idx   = {t.get("name"): t for t in tools_final}

        rugpull_count = 0

        # --- Detectar tools NUEVAS (presentes en segunda llamada, ausentes en primera) ---
        for tool_name in final_idx:
            if tool_name not in inicial_idx:
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="HIGH",
                    type="MCP-RUGPULL-001",
                    title=f"[{tool_name}] MCP-RUGPULL-001: Tool nueva entre llamadas (rug pull)",
                    description=(
                        f"La tool '{tool_name}' no estaba presente en la primera llamada a "
                        "tools/list pero sí en la segunda. Un servidor MCP malicioso puede "
                        "introducir tools envenenadas dinámicamente después del handshake "
                        "inicial, cuando el auditor o el agente ya ha evaluado la lista."
                    ),
                    affected=f"tool:{tool_name}",
                    recommendation=(
                        "El agente debe revalidar el conjunto de tools antes de cada invocación "
                        "crítica. Implementar verificación de integridad (hash firmado) del "
                        "conjunto de tools y alertar ante cualquier adición no autorizada."
                    ),
                    phase=7,
                    owasp="A01",
                    evidence=f"Tool '{tool_name}' ausente en primera llamada, presente en segunda",
                ))
                rugpull_count += 1

        # --- Detectar tools que CAMBIARON (description o schema modificados) ---
        for tool_name, t_final in final_idx.items():
            if tool_name not in inicial_idx:
                continue  # Ya reportado como nueva

            t_inicial      = inicial_idx[tool_name]
            desc_inicial   = t_inicial.get("description", "")
            desc_final     = t_final.get("description", "")
            schema_inicial = json.dumps(t_inicial.get("inputSchema", {}), sort_keys=True)
            schema_final   = json.dumps(t_final.get("inputSchema", {}),   sort_keys=True)

            cambios = []
            if desc_inicial != desc_final:
                cambios.append("description")
            if schema_inicial != schema_final:
                cambios.append("inputSchema")

            if cambios:
                self._add_finding(Finding(
                    tool=tool_name,
                    severity="HIGH",
                    type="MCP-RUGPULL-001",
                    title=f"[{tool_name}] MCP-RUGPULL-001: Tool redefinida entre llamadas (rug pull)",
                    description=(
                        f"La tool '{tool_name}' cambió su {' y '.join(cambios)} entre la "
                        "primera y la segunda llamada a tools/list. Este patrón es conocido "
                        "como 'rug pull': el servidor presenta una tool benigna en el handshake "
                        "y la reemplaza por una versión maliciosa durante la sesión."
                    ),
                    affected=f"tool:{tool_name}",
                    recommendation=(
                        "Implementar verificación de integridad del conjunto de tools mediante "
                        "hash firmado. El agente debe rechazar cualquier modificación de tool "
                        "no autorizada durante la sesión. Auditar el código del servidor MCP."
                    ),
                    phase=7,
                    owasp="A01",
                    evidence=(
                        f"Campos modificados: {', '.join(cambios)}. "
                        f"Description antes: '{desc_inicial[:100]}' → "
                        f"después: '{desc_final[:100]}'"
                    ),
                ))
                rugpull_count += 1

        if rugpull_count == 0:
            self.console.print(
                "  [green]✓[/green] Sin cambios en el conjunto de tools entre llamadas (sin rug pull)"
            )
        else:
            self.console.print(
                f"  [bold red]✗[/bold red] {rugpull_count} hallazgo(s) de rug pull detectados"
            )

    # -----------------------------------------------------------------------
    # FASE 10: Análisis de servidor en producción (HTTP/HTTPS sin auth)
    # -----------------------------------------------------------------------

    async def _analyze_production_server(
        self,
        session: aiohttp.ClientSession,
    ) -> None:
        """
        FASE 10: Comprueba si el servidor MCP expone endpoints sensibles sin
        autenticación, incluyendo descubrimiento de capacidades, enumeración
        de tools y recursos, y configuración CORS permisiva.

        MCP-PROD-001 (HIGH)  : Endpoint de info/descubrimiento accesible sin auth
        MCP-PROD-002 (HIGH)  : tools/list accesible sin token de autenticación
        MCP-PROD-003 (MEDIUM): CORS con Access-Control-Allow-Origin: * en servidor MCP
        MCP-PROD-004 (MEDIUM): resources/list accesible sin autenticación
        """
        # Solo aplica a servidores HTTP/HTTPS (no STDIO)
        parsed = urllib.parse.urlparse(self.target)
        if parsed.scheme not in ("http", "https"):
            self.console.print(
                "  [dim]↳ Fase 10 omitida — objetivo STDIO, no HTTP/HTTPS[/dim]"
            )
            return

        base = self.target.rstrip("/")

        # ── 10.1  Endpoint de descubrimiento sin auth ─────────────────────────
        discovery_paths = ["/.well-known/mcp", "/mcp/info", "/info", "/mcp"]
        for path in discovery_paths:
            try:
                async with session.get(
                    base + path,
                    timeout=self.timeout,
                ) as r:
                    self._log(f"GET {path} → HTTP {r.status}")
                    if r.status in (200, 201):
                        cuerpo = await r.text(encoding="utf-8", errors="replace")
                        self._add_finding(Finding(
                            tool="server",
                            severity="HIGH",
                            type="MCP-PROD-001",
                            title=f"Endpoint de descubrimiento MCP accesible sin auth ({path})",
                            description=(
                                f"El servidor MCP expone el endpoint '{path}' sin requerir "
                                "autenticación. Este endpoint puede revelar información sobre "
                                "las capacidades del servidor, la versión del protocolo y "
                                "otros metadatos operativos que facilitan el reconocimiento "
                                "previo a un ataque."
                            ),
                            affected=base + path,
                            recommendation=(
                                "Proteger todos los endpoints de descubrimiento con autenticación. "
                                "Si el endpoint debe ser público, limitar la información expuesta "
                                "al mínimo necesario (sin versiones internas ni configuración)."
                            ),
                            phase=10,
                            owasp="A01",
                            evidence=f"HTTP {r.status} en {path}. Cuerpo: {cuerpo[:200]}",
                        ))
                        break  # Un hallazgo por tipo es suficiente
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        # ── 10.2  tools/list sin token ─────────────────────────────────────────
        try:
            resp_tools = await self._json_rpc(session, "tools/list", {})
            if resp_tools is not None:
                result = resp_tools.get("result") or {}
                tools_sin_auth = result.get("tools", [])
                if tools_sin_auth:
                    self._add_finding(Finding(
                        tool="server",
                        severity="HIGH",
                        type="MCP-PROD-002",
                        title="tools/list enumerable sin autenticación",
                        description=(
                            f"El endpoint tools/list devuelve {len(tools_sin_auth)} tool(s) "
                            "sin requerir token de autenticación. La enumeración no autenticada "
                            "de tools permite a un atacante conocer la superficie de ataque del "
                            "servidor MCP sin credenciales."
                        ),
                        affected=f"{self.target} → tools/list",
                        recommendation=(
                            "Implementar autenticación obligatoria (Bearer token u OAuth 2.0) "
                            "en todos los endpoints JSON-RPC del servidor MCP, incluido tools/list. "
                            "Devolver HTTP 401 o un error JSON-RPC -32001 ante peticiones sin token."
                        ),
                        phase=10,
                        owasp="A01",
                        evidence=(
                            f"tools/list sin auth retornó {len(tools_sin_auth)} tools: "
                            f"{[t.get('name','?') for t in tools_sin_auth[:5]]}"
                        ),
                    ))
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        # ── 10.3  CORS con wildcard * ─────────────────────────────────────────
        try:
            hdrs_preflight: Dict[str, str] = {
                "Origin":                         "https://attacker-mcp-probe.example.com",
                "Access-Control-Request-Method":  "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization",
            }
            async with session.options(
                base,
                headers=hdrs_preflight,
                timeout=self.timeout,
            ) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                self._log(f"OPTIONS {base} → ACAO: {acao!r}")
                if acao == "*":
                    self._add_finding(Finding(
                        tool="server",
                        severity="MEDIUM",
                        type="MCP-PROD-003",
                        title="CORS permisivo (Access-Control-Allow-Origin: *) en servidor MCP",
                        description=(
                            "El servidor MCP responde con 'Access-Control-Allow-Origin: *' "
                            "ante una petición preflight OPTIONS. En un servidor MCP HTTP, "
                            "un CORS wildcard permite que páginas web de cualquier origen "
                            "realicen llamadas JSON-RPC al servidor desde el navegador del "
                            "usuario, facilitando ataques CSRF contra el agente MCP."
                        ),
                        affected=base,
                        recommendation=(
                            "Sustituir el wildcard CORS por una lista blanca explícita de "
                            "orígenes autorizados. El servidor MCP no debe ser accesible desde "
                            "orígenes web arbitrarios; restringir a los clientes MCP conocidos."
                        ),
                        phase=10,
                        owasp="A04",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                    ))
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        # ── 10.4  resources/list sin autenticación ────────────────────────────
        try:
            resp_res = await self._json_rpc(session, "resources/list", {})
            if resp_res is not None:
                result = resp_res.get("result") or {}
                recursos_sin_auth = result.get("resources", [])
                if recursos_sin_auth:
                    self._add_finding(Finding(
                        tool="server",
                        severity="MEDIUM",
                        type="MCP-PROD-004",
                        title="resources/list enumerable sin autenticación",
                        description=(
                            f"El endpoint resources/list devuelve {len(recursos_sin_auth)} "
                            "recurso(s) sin requerir token de autenticación. Un atacante puede "
                            "conocer los ficheros, bases de datos o URIs que el servidor MCP "
                            "expone a los agentes sin tener credenciales."
                        ),
                        affected=f"{self.target} → resources/list",
                        recommendation=(
                            "Aplicar autenticación obligatoria en resources/list. "
                            "Los recursos expuestos por el servidor MCP pueden contener "
                            "información sensible; su enumeración debe requerir token válido."
                        ),
                        phase=10,
                        owasp="A01",
                        evidence=(
                            f"resources/list sin auth retornó {len(recursos_sin_auth)} recursos: "
                            f"{[r.get('uri', r.get('name','?')) for r in recursos_sin_auth[:5]]}"
                        ),
                    ))
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass

        hallazgos_fase10 = [f for f in self.findings if f.phase == 10]
        if not hallazgos_fase10:
            self.console.print(
                "  [green]✓[/green] Sin endpoints públicos sin auth detectados (Fase 10)"
            )
        else:
            self.console.print(
                f"  [bold red]✗[/bold red] {len(hallazgos_fase10)} hallazgo(s) de "
                "endpoints sin autenticación en producción"
            )

    # -----------------------------------------------------------------------
    # Orquestador principal
    # -----------------------------------------------------------------------

    async def run(self) -> Tuple[List[Finding], Dict]:
        """
        Orquesta las 5 fases de auditoría en secuencia y retorna los hallazgos
        acumulados junto con el resumen de riesgo agéntico.

        Retorna
        -------
        Tuple (findings, risk_summary) donde findings es la lista completa de
        hallazgos ordenada por severidad, y risk_summary es el dict de Fase 5.
        """
        self.console.print(BANNER, style="bold red")

        ts_start = datetime.now(timezone.utc)
        self.console.print(
            f"[dim]Objetivo: {self.target} | "
            f"Inicio: {ts_start.strftime('%Y-%m-%d %H:%M:%S UTC')}[/dim]"
        )

        # Configurar sesión HTTP (sin verificación TLS — la analizamos en Fase 4)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=self.timeout,
        ) as session:

            # FASE 1: Reconocimiento
            self._phase_header(1, "Reconocimiento del servidor MCP")
            self.server_info = await self.fetch_server_info(session)
            self.tools       = await self.list_tools(session)
            self.resources   = await self.list_resources(session)
            # Guardar snapshot inicial de tools para la detección de rug pull (Fase 7)
            tools_initial_snapshot = [dict(t) for t in self.tools]

            # FASE 2: Detección de Tool Poisoning
            self._phase_header(2, "Detección de Tool Poisoning")
            await self.audit_tool_poisoning(self.tools)

            # FASE 3: Auditoría de Privilegios y Permisos
            self._phase_header(3, "Auditoría de Privilegios y Permisos")
            await self.audit_permissions(self.tools)

            # FASE 4: Seguridad del Transporte
            self._phase_header(4, "Seguridad del Transporte")
            await self.audit_transport(session)

            # FASE 5: Tool Poisoning Scanner Extendido (Unicode Tags, instrucciones ocultas, ratio)
            self._phase_header(5, "Tool Poisoning Scanner — Unicode Tags, Instrucciones Ocultas, Ratio")
            await self.audit_tool_poisoning_scanner(self.tools)

            # FASE 6: SSRF via Parámetros de Tool (opt-in con --test-ssrf)
            self._phase_header(6, "SSRF via Parámetros de Tool")
            await self.audit_ssrf_parameters(session, self.tools)

            # FASE 7: Rug Pull Detection — segunda llamada a tools/list
            self._phase_header(7, "Rug Pull Detection — Redefinición de Tools")
            await self.audit_rug_pull(session, tools_initial_snapshot)

            # FASE 8: Evaluación de Riesgo Agéntico (OWASP Agentic AI Top 10 2026)
            self._phase_header(8, "Evaluación de Riesgo Agéntico (OWASP Agentic AI Top 10 2026)")
            risk_summary = self.assess_agentic_risk(self.tools, self.findings)

            # FASE 9: Context Window Overflow — superficie de descripciones de tools
            if self.tools:
                self._phase_header(9, "Context Window Overflow — Superficie de Descripciones")
                await self.audit_context_overflow(self.tools)

            # FASE 10: Análisis de servidor en producción (endpoints públicos sin auth)
            self._phase_header(10, "Servidor de Producción — Endpoints sin Autenticación")
            await self._analyze_production_server(session)

        # Ordenar hallazgos por severidad descendente
        sorted_findings = sorted(self.findings, key=lambda f: f.order)

        # Resumen de hallazgos en consola
        self._print_findings_summary(sorted_findings)

        return sorted_findings, risk_summary

    def _print_findings_summary(self, findings: List[Finding]) -> None:
        """Imprime la tabla resumen de hallazgos en consola Rich."""
        self.console.print()

        counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        # Conteo específico de hallazgos de ASCII smuggling
        smuggling_count = sum(1 for f in findings if f.type == "ascii_smuggling")

        # Fila de totales por severidad
        totals = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
        totals.add_column("sev", style="bold")
        totals.add_column("n",   justify="right")
        for sev, color in SEVERITY_COLOR.items():
            n = counts.get(sev, 0)
            if n > 0:
                totals.add_row(f"[{color}]{sev}[/{color}]", f"[{color}]{n}[/{color}]")

        # Línea especial si se detectó ASCII smuggling
        if smuggling_count > 0:
            totals.add_row(
                "[bold red]ASCII SMUGGLING[/bold red]",
                f"[bold red]{smuggling_count}[/bold red]",
            )
            totals.add_row(
                "[dim]  Unicode Tags invisibles detectados[/dim]",
                "[dim]NUEVO[/dim]",
            )

        self.console.print(Panel(totals, title="[bold white]Resumen de Hallazgos[/bold white]", border_style="blue"))

        # Tabla detallada de hallazgos
        if not findings:
            self.console.print("[green]Sin hallazgos de seguridad detectados.[/green]")
            return

        tbl = Table(
            title=f"Hallazgos — {len(findings)} total",
            show_header=True,
            header_style="bold blue",
            box=box.ROUNDED,
        )
        tbl.add_column("#",          width=4,  justify="right")
        tbl.add_column("SEV",        width=10)
        tbl.add_column("Fase",       width=5,  justify="center")
        tbl.add_column("Tool",       width=20)
        tbl.add_column("Título",     width=50)
        tbl.add_column("OWASP",      width=8,  justify="center")

        for i, finding in enumerate(findings, 1):
            color = SEVERITY_COLOR.get(finding.severity, "white")
            tbl.add_row(
                str(i),
                f"[{color}]{finding.severity}[/{color}]",
                str(finding.phase) if finding.phase else "-",
                finding.tool[:20],
                finding.title[:50],
                finding.owasp or "-",
            )

        self.console.print(tbl)


# ---------------------------------------------------------------------------
# Generador de informes
# ---------------------------------------------------------------------------

class VampSecReport:
    """
    Generador de informes de auditoría MCP en formatos JSON y HTML.

    Los informes siguen el estilo visual del toolkit VampSecure Labs:
    dark theme, badges de severidad con colores codificados, tabla de
    hallazgos con filtro por severidad y resumen ejecutivo con totales.
    """

    def __init__(
        self,
        target:       str,
        findings:     List[Finding],
        risk_summary: Dict,
        server_info:  Dict,
        tools:        List[Dict],
        resources:    List[Dict],
    ) -> None:
        self.target       = target
        self.findings     = findings
        self.risk_summary = risk_summary
        self.server_info  = server_info
        self.tools        = tools
        self.resources    = resources
        self.timestamp    = datetime.now(timezone.utc).isoformat()

    def save_json(self, path: str) -> None:
        """Exporta el informe completo a JSON."""
        data = {
            "tool":        TOOL_NAME,
            "version":     VERSION,
            "timestamp":   self.timestamp,
            "target":      self.target,
            "risk_summary": self.risk_summary,
            "server_info": self.server_info,
            "tools":       self.tools,
            "resources":   self.resources,
            "findings":    [f.to_dict() for f in self.findings],
            "counts": {
                sev: sum(1 for f in self.findings if f.severity == sev)
                for sev in SEVERITY_ORDER
            },
        }
        Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        Console().print(f"[green]✓[/green] Informe JSON guardado: {path}")

    def save_html(self, path: str) -> None:
        """
        Genera y guarda el informe HTML dark-theme standalone.

        El informe incluye:
        - Cabecera con logo, target y timestamp
        - Resumen ejecutivo con totales por severidad y risk score
        - Tabla de tools inventariadas
        - Tabla de hallazgos con filtro por severidad (JavaScript puro)
        - Detalle expandible de cada hallazgo con evidencia y recomendación
        """
        counts = {
            sev: sum(1 for f in self.findings if f.severity == sev)
            for sev in SEVERITY_ORDER
        }
        html = self._build_html(counts)
        Path(path).write_text(html, encoding="utf-8")
        Console().print(f"[green]✓[/green] Informe HTML guardado: {path}")

    def _build_html(self, counts: Dict[str, int]) -> str:
        """Construye el HTML completo del informe."""

        # Filas de la tabla de hallazgos
        finding_rows = ""
        for i, f in enumerate(self.findings, 1):
            badge_color = SEVERITY_BADGE_CSS.get(f.severity, "#6b7280")
            owasp_badge = (
                f'<span class="owasp-badge">{escape(f.owasp)}</span>'
                if f.owasp else ""
            )
            evidence_html = (
                f'<div class="evidence"><strong>Evidencia:</strong> {escape(f.evidence)}</div>'
                if f.evidence else ""
            )
            finding_rows += f"""
            <tr class="finding-row sev-{f.severity}" data-sev="{f.severity}">
              <td class="finding-num">{i}</td>
              <td><span class="badge" style="background:{badge_color}">{escape(f.severity)}</span></td>
              <td class="fase-cell">F{f.phase}</td>
              <td class="tool-cell"><code>{escape(f.tool)}</code></td>
              <td>
                <div class="finding-title">{escape(f.title)}</div>
                <div class="finding-desc">{escape(f.description)}</div>
                {evidence_html}
                <div class="recommendation"><strong>Recomendación:</strong> {escape(f.recommendation)}</div>
              </td>
              <td>{owasp_badge}</td>
            </tr>"""

        # Filas de la tabla de tools
        tool_rows = ""
        for t in self.tools:
            name = escape(t.get("name", "-"))
            desc = escape((t.get("description") or "-")[:120])
            tool_rows += f"""
            <tr>
              <td><code class="tool-name">{name}</code></td>
              <td class="tool-desc">{desc}</td>
            </tr>"""

        # Badges de totales
        severity_badges = ""
        for sev, color in SEVERITY_BADGE_CSS.items():
            n = counts.get(sev, 0)
            severity_badges += (
                f'<div class="summary-badge" style="border-color:{color}">'
                f'<span class="summary-count" style="color:{color}">{n}</span>'
                f'<span class="summary-label">{sev}</span>'
                f'</div>'
            )

        risk_score  = self.risk_summary.get("total_score", 0)
        risk_level  = self.risk_summary.get("risk_level", "DESCONOCIDO")
        risk_color  = "#dc2626" if risk_score >= 40 else (
            "#d97706" if risk_score >= 20 else (
                "#7c3aed" if risk_score >= 8 else "#0891b2"
            )
        )

        # OWASP breakdown
        owasp_rows = ""
        for code, info in OWASP_AGENTIC_TOP10.items():
            n = self.risk_summary.get("owasp_counts", {}).get(code, 0)
            s = self.risk_summary.get("owasp_scores", {}).get(code, 0)
            owasp_rows += f"""
            <tr {"class='owasp-hit'" if n > 0 else ""}>
              <td class="owasp-code">{code}</td>
              <td>{escape(info['name'])}</td>
              <td class="owasp-n">{n if n > 0 else '-'}</td>
              <td class="owasp-s">{s if s > 0 else '-'}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vamp-mcp-audit — {escape(self.target)}</title>
<style>
  /* ── Reset y base ────────────────────────────────────────────────── */
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: #0a0a0f;
    color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    padding: 24px;
  }}
  /* ── Header ─────────────────────────────────────────────────────── */
  .header {{
    border-bottom: 2px solid #dc2626;
    padding-bottom: 20px;
    margin-bottom: 28px;
  }}
  .header-logo {{
    font-size: 11px;
    color: #6b7280;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 4px;
  }}
  .header-title {{
    font-size: 26px;
    font-weight: 700;
    color: #f1f5f9;
    font-family: 'Courier New', monospace;
  }}
  .header-title span {{ color: #dc2626; }}
  .header-meta {{
    margin-top: 8px;
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
    font-size: 12px;
    color: #94a3b8;
  }}
  .header-meta strong {{ color: #cbd5e1; }}
  /* ── Sección ─────────────────────────────────────────────────────── */
  .section {{
    background: #111827;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
  }}
  .section-title {{
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #94a3b8;
    margin-bottom: 16px;
    border-bottom: 1px solid #1e293b;
    padding-bottom: 8px;
  }}
  /* ── Resumen ejecutivo ───────────────────────────────────────────── */
  .summary-grid {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }}
  .summary-badge {{
    background: #0f172a;
    border: 2px solid;
    border-radius: 8px;
    padding: 12px 20px;
    text-align: center;
    min-width: 100px;
  }}
  .summary-count {{
    display: block;
    font-size: 28px;
    font-weight: 700;
    font-family: 'Courier New', monospace;
  }}
  .summary-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: #64748b;
  }}
  .risk-panel {{
    background: #0f172a;
    border: 2px solid {risk_color};
    border-radius: 8px;
    padding: 16px 24px;
    display: inline-flex;
    align-items: center;
    gap: 24px;
    margin-top: 8px;
  }}
  .risk-score {{
    font-size: 36px;
    font-weight: 700;
    color: {risk_color};
    font-family: 'Courier New', monospace;
  }}
  .risk-label {{
    font-size: 11px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }}
  .risk-level {{
    font-size: 20px;
    font-weight: 700;
    color: {risk_color};
  }}
  /* ── Filtros ─────────────────────────────────────────────────────── */
  .filter-bar {{
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }}
  .filter-btn {{
    padding: 4px 14px;
    border-radius: 20px;
    border: 1px solid #374151;
    background: #1e293b;
    color: #94a3b8;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    transition: all .15s;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: #374151;
    color: #f1f5f9;
    border-color: #64748b;
  }}
  /* ── Tabla ───────────────────────────────────────────────────────── */
  table {{ width: 100%; border-collapse: collapse; }}
  th {{
    background: #1e293b;
    color: #94a3b8;
    text-align: left;
    padding: 8px 12px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 1px solid #334155;
  }}
  td {{
    padding: 10px 12px;
    border-bottom: 1px solid #1e293b;
    vertical-align: top;
  }}
  tr:hover td {{ background: #111827; }}
  tr.hidden {{ display: none; }}
  .finding-num {{ color: #475569; font-size: 12px; }}
  .fase-cell {{ color: #64748b; font-size: 12px; text-align: center; }}
  .tool-cell {{ font-size: 12px; }}
  code {{ font-family: 'Courier New', monospace; font-size: 12px; color: #7dd3fc; }}
  .tool-name {{ color: #7dd3fc; }}
  .tool-desc {{ color: #94a3b8; font-size: 12px; }}
  /* ── Finding detail ──────────────────────────────────────────────── */
  .finding-title {{ font-weight: 600; color: #e2e8f0; margin-bottom: 4px; }}
  .finding-desc {{
    font-size: 12px;
    color: #94a3b8;
    margin-bottom: 6px;
    display: none;
  }}
  tr:hover .finding-desc {{ display: block; }}
  .evidence {{
    font-size: 11px;
    color: #475569;
    font-family: 'Courier New', monospace;
    background: #0f172a;
    padding: 4px 8px;
    border-radius: 4px;
    margin-bottom: 4px;
    display: none;
  }}
  tr:hover .evidence {{ display: block; }}
  .recommendation {{
    font-size: 11px;
    color: #64748b;
    display: none;
  }}
  tr:hover .recommendation {{ display: block; }}
  /* ── Badges ──────────────────────────────────────────────────────── */
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    color: #fff;
    letter-spacing: 0.04em;
  }}
  .owasp-badge {{
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    background: #1e293b;
    border: 1px solid #334155;
    font-size: 11px;
    font-family: 'Courier New', monospace;
    color: #7dd3fc;
  }}
  /* ── OWASP table ─────────────────────────────────────────────────── */
  .owasp-code {{ font-family: 'Courier New', monospace; color: #7dd3fc; font-size: 12px; }}
  .owasp-n, .owasp-s {{ text-align: right; font-family: 'Courier New', monospace; }}
  tr.owasp-hit td {{ color: #fbbf24; }}
  /* ── Footer ──────────────────────────────────────────────────────── */
  .footer {{
    margin-top: 32px;
    padding-top: 16px;
    border-top: 1px solid #1e293b;
    color: #374151;
    font-size: 11px;
    text-align: center;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-logo">VampSecure Labs · Security Research Division</div>
  <div class="header-title"><span>VAMP</span>-MCP-AUDIT — Informe de Auditoría MCP</div>
  <div class="header-meta">
    <span><strong>Objetivo:</strong> {escape(self.target)}</span>
    <span><strong>Fecha:</strong> {escape(self.timestamp)}</span>
    <span><strong>Tools inventariadas:</strong> {len(self.tools)}</span>
    <span><strong>Recursos inventariados:</strong> {len(self.resources)}</span>
    <span><strong>Versión herramienta:</strong> {VERSION}</span>
    <span><strong>Fases:</strong> 1·Reconocimiento 2·ToolPoisoning 3·Privilegios 4·Transporte 5·PoisoningScanner 6·SSRF 7·RugPull 8·OWASP 9·ContextOverflow</span>
  </div>
</div>

<!-- Resumen ejecutivo -->
<div class="section">
  <div class="section-title">Resumen Ejecutivo</div>
  <div class="summary-grid">
    {severity_badges}
  </div>
  <div class="risk-panel">
    <div>
      <div class="risk-label">Risk Score</div>
      <div class="risk-score">{risk_score}</div>
    </div>
    <div>
      <div class="risk-label">Nivel de Riesgo Global</div>
      <div class="risk-level">{escape(risk_level)}</div>
    </div>
  </div>
</div>

<!-- OWASP Agentic AI Top 10 -->
<div class="section">
  <div class="section-title">OWASP Agentic AI Top 10 2026 — Distribución</div>
  <table>
    <thead>
      <tr>
        <th style="width:70px">Código</th>
        <th>Categoría</th>
        <th style="width:90px; text-align:right">Hallazgos</th>
        <th style="width:70px; text-align:right">Score</th>
      </tr>
    </thead>
    <tbody>
      {owasp_rows}
    </tbody>
  </table>
</div>

<!-- Tools inventariadas -->
<div class="section">
  <div class="section-title">Tools MCP Inventariadas ({len(self.tools)})</div>
  {"<p style='color:#64748b;font-size:12px'>Sin tools disponibles o no enumeradas.</p>" if not self.tools else f"""
  <table>
    <thead>
      <tr><th style='width:220px'>Nombre</th><th>Descripción</th></tr>
    </thead>
    <tbody>
      {tool_rows}
    </tbody>
  </table>"""}
</div>

<!-- Hallazgos de seguridad -->
<div class="section">
  <div class="section-title">Hallazgos de Seguridad ({len(self.findings)})</div>

  <div class="filter-bar">
    <button class="filter-btn active" onclick="filterFindings('ALL', this)">TODOS</button>
    <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">CRITICAL</button>
    <button class="filter-btn" onclick="filterFindings('HIGH', this)">HIGH</button>
    <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">MEDIUM</button>
    <button class="filter-btn" onclick="filterFindings('LOW', this)">LOW</button>
    <button class="filter-btn" onclick="filterFindings('INFO', this)">INFO</button>
  </div>

  {"<p style='color:#64748b;font-size:12px'>Sin hallazgos de seguridad detectados.</p>" if not self.findings else f"""
  <table>
    <thead>
      <tr>
        <th style="width:40px">#</th>
        <th style="width:90px">Severidad</th>
        <th style="width:45px">Fase</th>
        <th style="width:160px">Tool</th>
        <th>Hallazgo</th>
        <th style="width:70px">OWASP</th>
      </tr>
    </thead>
    <tbody>
      {finding_rows}
    </tbody>
  </table>"""}
</div>

<div class="footer">
  © VampSecure Studios — VampSecure Labs Security Research Division ·
  {TOOL_NAME} v{VERSION} ·
  Uso exclusivo en auditorías autorizadas · El uso no autorizado es ilegal.
</div>

<script>
function filterFindings(sev, btn) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(row => {{
    if (sev === 'ALL' || row.dataset.sev === sev) {{
      row.classList.remove('hidden');
    }} else {{
      row.classList.add('hidden');
    }}
  }});
}}
</script>

</body>
</html>"""

    # Cierre de la clase VampSecReport


# ---------------------------------------------------------------------------
# Punto de entrada principal
# ---------------------------------------------------------------------------

def build_argument_parser() -> argparse.ArgumentParser:
    """Construye y retorna el parser de argumentos CLI de la herramienta."""
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Auditor de seguridad para servidores MCP (Model Context Protocol). "
            "Detecta tool poisoning, privilegios excesivos, transporte inseguro "
            "y riesgos de agencia según OWASP Agentic AI Top 10 2026."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  %(prog)s --target http://localhost:3000\n"
            "  %(prog)s --target https://mcp.example.com --json report.json --html report.html\n"
            "  %(prog)s --target http://127.0.0.1:8080 --verbose --timeout 15\n\n"
            "© VampSecure Studios — Uso exclusivo en auditorías autorizadas"
        ),
    )

    parser.add_argument(
        "--target", "-t",
        required=True,
        metavar="URL",
        help="URL del servidor MCP a auditar (ej: http://localhost:3000)",
    )
    parser.add_argument(
        "--scope", "-s",
        metavar="FICHERO",
        help="Fichero JSON de scope con restricciones de auditoría",
    )
    parser.add_argument(
        "--json",
        metavar="FICHERO",
        dest="json_file",
        help="Exportar informe completo en formato JSON al fichero indicado",
    )
    parser.add_argument(
        "--html",
        metavar="FICHERO",
        dest="html_file",
        help="Exportar informe visual dark-theme en formato HTML al fichero indicado",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SEGUNDOS",
        help="Timeout para peticiones HTTP en segundos (por defecto: 10)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Activar output detallado de depuración durante la auditoría",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s v{VERSION} — VampSecure Labs",
    )
    parser.add_argument(
        "--ctx-limit",
        type=int,
        default=32000,
        metavar="N",
        dest="ctx_limit",
        help=(
            "Umbral en caracteres para la alerta HIGH de context window overflow "
            "en la Fase 9 (default: 32000). Por encima de 8000 se emite MEDIUM; "
            "por encima de N se emite HIGH."
        ),
    )
    parser.add_argument(
        "--test-ssrf",
        action="store_true",
        default=False,
        dest="test_ssrf",
        help=(
            "Activa las pruebas activas SSRF en la Fase 6 (opt-in, por defecto desactivado). "
            "Invoca tools con parámetros url/host/endpoint usando payloads de metadata cloud "
            "(AWS/GCP/Azure). ATENCIÓN: puede generar tráfico hacia endpoints internos; "
            "usar solo en entornos autorizados."
        ),
    )

    return parser


def main() -> None:
    """Función principal: parsea argumentos, ejecuta auditoría y gestiona salida."""
    parser = build_argument_parser()
    args   = parser.parse_args()

    # Validar URL básica
    parsed = urllib.parse.urlparse(args.target)
    if parsed.scheme not in ("http", "https"):
        Console().print(
            f"[bold red]Error:[/bold red] El target debe comenzar con http:// o https://. "
            f"Recibido: {args.target}"
        )
        sys.exit(2)

    # Ejecutar auditoría
    auditor = MCPAuditor(
        target=args.target,
        scope_file=args.scope,
        timeout=args.timeout,
        verbose=args.verbose,
        ctx_limit=args.ctx_limit,
        test_ssrf=args.test_ssrf,
    )

    try:
        findings, risk_summary = asyncio.run(auditor.run())
    except KeyboardInterrupt:
        Console().print("\n[yellow]Auditoría interrumpida por el usuario.[/yellow]")
        sys.exit(2)
    except Exception as exc:
        Console().print(f"[bold red]Error fatal durante la auditoría:[/bold red] {exc}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(2)

    # Generar informes de salida si se solicitaron
    if args.json_file or args.html_file:
        report = VampSecReport(
            target=args.target,
            findings=findings,
            risk_summary=risk_summary,
            server_info=auditor.server_info,
            tools=auditor.tools,
            resources=auditor.resources,
        )
        if args.json_file:
            report.save_json(args.json_file)
        if args.html_file:
            report.save_html(args.html_file)

    # Exit code: 0=limpio, 1=crítico/alto, 2=error
    has_critical = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
