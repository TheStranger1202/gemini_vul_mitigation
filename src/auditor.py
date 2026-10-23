"""Módulo de lógica y clasificación de mitigaciones.

Evalúa el esquema OSV de cada vulnerabilidad para determinar la disponibilidad
de versiones parcheadas (fixed) o la ausencia de parches oficiales (Zero-Day).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


def extract_fixed_version(
    vuln_data: Mapping[str, Any], package_name: str
) -> str | None:
    """Inspecciona los eventos de rangos afectados en búsqueda de un parche ('fixed').

    Args:
        vuln_data: Estructura individual de una vulnerabilidad devuelta por OSV.
        package_name: Nombre del paquete auditado para filtrar bloques relevantes.

    Returns:
        str | None: Cadena con la versión mínima parchada si existe; de lo contrario None.
    """
    affected_blocks = vuln_data.get("affected", [])

    for block in affected_blocks:
        pkg_info = block.get("package", {})
        # Validar concordancia de paquete si la información está disponible
        if pkg_info and pkg_info.get("name") != package_name:
            continue

        ranges = block.get("ranges", [])
        for rng in ranges:
            events = rng.get("events", [])
            for event in events:
                if "fixed" in event:
                    return str(event["fixed"])

    return None


def extract_severity_score(vuln_data: Mapping[str, Any]) -> str:
    """Extrae la métrica o severidad declarada en el registro de la vulnerabilidad.

    Args:
        vuln_data: Registro de la vulnerabilidad.

    Returns:
        str: Puntuación o vector CVSS, o 'No especificada' si no está presente.
    """
    severities = vuln_data.get("severity", [])
    if isinstance(severities, list) and severities:
        first_sev = severities[0]
        if isinstance(first_sev, dict):
            return str(first_sev.get("score", "Severidad no especificada"))
    return "Severidad no especificada"


def process_vulnerability_record(
    vuln: Mapping[str, Any],
    dep: Mapping[str, str],
) -> dict[str, Any]:
    """Transforma una vulnerabilidad cruda en un registro de auditoría estandarizado.

    Args:
        vuln: Registro crudo de la vulnerabilidad en OSV.
        dep: Dependencia asociada del inventario local.

    Returns:
        dict[str, Any]: Objeto de veredicto con estado de parche y metadatos limpios.
    """
    vuln_id = str(vuln.get("id", "ID-DESCONOCIDO"))
    summary = str(vuln.get("summary", "Sin resumen disponible.")).strip()
    fixed_version = extract_fixed_version(vuln, dep["name"])
    severity = extract_severity_score(vuln)

    return {
        "id": vuln_id,
        "package_name": dep["name"],
        "ecosystem": dep["ecosystem"],
        "current_version": dep["version"],
        "summary": summary,
        "severity": severity,
        "has_patch": fixed_version is not None,
        "fixed_version": fixed_version,
    }


def evaluate_findings(
    scan_results: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Any], ...]:
    """Procesa de forma pura todos los hallazgos reportados por el escáner.

    Args:
        scan_results: Tupla generada por scanner.scan_inventory.

    Returns:
        tuple[dict[str, Any], ...]: Tupla inmutable con todos los veredictos clasificados.
    """
    findings = []

    for item in scan_results:
        dep = item["dependency"]
        for vuln in item["vulnerabilities"]:
            findings.append(process_vulnerability_record(vuln, dep))

    return tuple(findings)
