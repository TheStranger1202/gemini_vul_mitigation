"""Módulo de lógica y clasificación de mitigaciones.

Evalúa el esquema OSV de cada vulnerabilidad para determinar la disponibilidad
de versiones parcheadas (fixed) o la ausencia de parches oficiales (Zero-Day).
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence
from packaging.version import InvalidVersion, parse as parse_version


def parse_safe_version(version_str: str) -> Any:
    """Intenta parsear la versión de forma semántica; si falla, devuelve la cadena plana."""
    try:
        return parse_version(version_str)
    except InvalidVersion:
        return version_str


def select_best_fixed_version(
    candidates: Sequence[str], current_version: str
) -> str | None:
    """Función pura que selecciona la versión de parche más adecuada.

    Filtra candidatos descartando versiones inferiores a la versión instalada
    (evitando sugerir ramas obsoletas) y selecciona la versión mínima superior.

    Args:
        candidates: Lista de versiones declaradas en los eventos 'fixed'.
        current_version: Versión actualmente en uso en el inventario.

    Returns:
        str | None: Versión recomendada para actualización, o None si no hay candidatos válidos.
    """
    if not candidates:
        return None

    parsed_current = parse_safe_version(current_version)

    # Filtrar únicamente versiones estrictamente mayores a la actual
    strictly_higher: list[str] = []
    for cand in candidates:
        parsed_cand = parse_safe_version(cand)
        try:
            if parsed_cand > parsed_current:
                strictly_higher.append(cand)
        except TypeError:
            # Fallback en caso de comparar tipos incompatibles
            if str(parsed_cand) > str(parsed_current):
                strictly_higher.append(cand)

    if strictly_higher:
        # Ordenar funcionalmente para recomendar el menor salto de versión seguro
        try:
            return min(strictly_higher, key=parse_safe_version)
        except TypeError:
            return min(strictly_higher)

    # Si ninguna es mayor pero hay candidatos, retornar el último parche declarado
    return candidates[-1]


def extract_fixed_version(
    vuln_data: Mapping[str, Any], package_name: str, current_version: str
) -> str | None:
    """Inspecciona los eventos de rangos afectados en búsqueda de un parche ('fixed').

    Args:
        vuln_data: Estructura individual de una vulnerabilidad devuelta por OSV.
        package_name: Nombre del paquete auditado para filtrar bloques relevantes.
        current_version: Versión del inventario local para contextualizar el parche.

    Returns:
        str | None: Cadena con la versión parcheada recomendada, o None si es Zero-Day.
    """
    affected_blocks = vuln_data.get("affected", [])
    collected_fixes: list[str] = []

    for block in affected_blocks:
        pkg_info = block.get("package", {})
        if pkg_info and pkg_info.get("name") != package_name:
            continue

        ranges = block.get("ranges", [])
        for rng in ranges:
            events = rng.get("events", [])
            for event in events:
                if "fixed" in event:
                    collected_fixes.append(str(event["fixed"]))

    return select_best_fixed_version(tuple(collected_fixes), current_version)


def extract_severity_score(vuln_data: Mapping[str, Any]) -> str:
    """Extrae la métrica o severidad declarada en el registro de la vulnerabilidad."""
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
    """Transforma una vulnerabilidad cruda en un registro de auditoría estandarizado."""
    vuln_id = str(vuln.get("id", "ID-DESCONOCIDO"))
    summary = str(vuln.get("summary", "Sin resumen disponible.")).strip()
    fixed_version = extract_fixed_version(vuln, dep["name"], dep["version"])
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
    """Procesa de forma pura todos los hallazgos reportados por el escáner."""
    findings = []

    for item in scan_results:
        dep = item["dependency"]
        for vuln in item["vulnerabilities"]:
            findings.append(process_vulnerability_record(vuln, dep))

    return tuple(findings)
