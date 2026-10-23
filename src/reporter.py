"""Módulo de presentación y generación de reportes en Markdown.

Genera salidas legibles para humanos y comandos de actualización accionables,
así como prompts estructurados para asistir en casos donde no existan parches.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def render_patched_finding(item: Mapping[str, Any]) -> str:
    """Renderiza la sección de mitigación determinista cuando hay parche oficial."""
    return f"""### 🚨 Vulnerabilidad Detectada: {item['id']}
* **Componente:** `{item['package_name']}` (Ecosistema: {item['ecosystem']})
* **Versión instalada:** `{item['current_version']}`
* **Severidad:** {item['severity']}
* **Descripción:** {item['summary']}

**🛠️ Plan de Mitigación Inmediato:**
Existe una solución oficial confirmada. Actualizar `{item['package_name']}` a la versión **`{item['fixed_version']}`** o superior.
"""


def render_zero_day_finding(item: Mapping[str, Any], project_name: str) -> str:
    """Renderiza la alerta Zero-Day con el prompt pre-armado para asistir con IA."""
    return f"""### ⚠️ ALERTA ZERO-DAY (Sin parche disponible): {item['id']}
* **Componente:** `{item['package_name']}` (Ecosistema: {item['ecosystem']})
* **Versión instalada:** `{item['current_version']}`
* **Severidad:** {item['severity']}
* **Descripción:** {item['summary']}

**🤖 Asistencia de Mitigación con IA:**
No existe actualización oficial en este momento. Copia y pega el siguiente bloque en tu IA de confianza:

> Actúa como experto en DevSecOps. Se ha detectado la vulnerabilidad {item['id']} en el componente `{item['package_name']}` versión `{item['current_version']}` ({item['ecosystem']}), utilizado en el proyecto '{project_name}'.
> Detalle reportado: "{item['summary']}".
> Al no existir aún una versión parcheada disponible, propón 3 estrategias de contención temporal (a nivel de configuración, variables de entorno, reglas de red o aislamiento) para reducir el riesgo de explotación inmediata.
"""


def generate_markdown_report(
    findings: Sequence[Mapping[str, Any]],
    project_name: str,
) -> str:
    """Construye el documento Markdown consolidado con todos los hallazgos evaluados.

    Args:
        findings: Secuencia inmutable de hallazgos devueltos por el auditor.
        project_name: Nombre del proyecto bajo auditoría.

    Returns:
        str: Texto completo en formato Markdown listo para visualización o envío.
    """
    if not findings:
        return f"# Reporte de Auditoría: {project_name}\n\n✅ No se detectaron vulnerabilidades conocidas en las dependencias analizadas."

    header = [
        f"# Reporte de Auditoría de Seguridad: {project_name}",
        f"**Total de vulnerabilidades evaluadas:** {len(findings)}\n",
        "---",
    ]

    blocks = []
    for item in findings:
        if item.get("has_patch"):
            blocks.append(render_patched_finding(item))
        else:
            blocks.append(render_zero_day_finding(item, project_name))

    return "\n\n---\n\n".join(header + blocks)
