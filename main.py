"""Punto de entrada y orquestador del proceso de auditoría diaria.

Coordina la lectura del inventario, escaneo contra OSV.dev, clasificación
de hallazgos, filtrado por caché local, generación del reporte y retorno de
códigos de salida conformes a estándares de CI/CD.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from src.auditor import evaluate_findings
from src.config import CACHE_FILE_PATH, load_inventory
from src.reporter import generate_markdown_report
from src.scanner import scan_inventory


# ==============================================================================
# GESTIÓN FUNCIONAL DE LA CACHÉ LOCAL
# ==============================================================================
def load_processed_cache(cache_path: Path = CACHE_FILE_PATH) -> set[str]:
    """Carga el conjunto de identificadores de vulnerabilidades ya notificadas."""
    if not cache_path.is_file():
        return set()

    try:
        with open(cache_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            entries = data.get("processed_vulnerabilities", [])
            return {str(item["id"]) for item in entries if "id" in item}
    except (json.JSONDecodeError, OSError):
        return set()


def update_processed_cache(
    new_findings: Sequence[Mapping[str, Any]],
    cache_path: Path = CACHE_FILE_PATH,
) -> None:
    """Persiste los nuevos identificadores en el archivo local de caché."""
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    existing_entries: list[dict[str, Any]] = []

    if cache_path.is_file():
        try:
            with open(cache_path, "r", encoding="utf-8") as file:
                data = json.load(file)
                existing_entries = data.get("processed_vulnerabilities", [])
        except (json.JSONDecodeError, OSError):
            existing_entries = []

    existing_ids = {entry["id"] for entry in existing_entries if "id" in entry}
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    updated = list(existing_entries)
    for finding in new_findings:
        vuln_id = finding["id"]
        if vuln_id not in existing_ids:
            updated.append({
                "id": vuln_id,
                "package": finding["package_name"],
                "ecosystem": finding["ecosystem"],
                "first_reported_at": timestamp,
                "mitigation_type": "fixed_version" if finding["has_patch"] else "zero_day",
            })
            existing_ids.add(vuln_id)

    with open(cache_path, "w", encoding="utf-8") as file:
        json.dump({"processed_vulnerabilities": updated}, file, indent=2)


# ==============================================================================
# PIPELINE DE EJECUCIÓN
# ==============================================================================
def run_pipeline() -> int:
    """Ejecuta el pipeline completo de auditoría y mitigación.

    Returns:
        int: Código de salida estándar:
            - 0: Éxito (Sin alertas o todas con mitigación resuelta).
            - 1: Alerta (Se detectaron vulnerabilidades activas o Zero-Days).
            - 2: Error irrecuperable de infraestructura o archivos.
    """
    try:
        inventory = load_inventory()
    except Exception as exc:
        print(f"[FATAL] Error de configuración o inventario: {exc}", file=sys.stderr)
        return 2

    project_name = inventory["project_name"]
    dependencies = inventory["dependencies"]

    print(f"[*] Iniciando auditoría para '{project_name}' ({len(dependencies)} dependencias)...")

    try:
        raw_scan_results = scan_inventory(dependencies)
    except ConnectionError as err:
        print(f"[FATAL] Error de conectividad con OSV: {err}", file=sys.stderr)
        return 2

    # Evaluación y clasificación determinista
    all_findings = evaluate_findings(raw_scan_results)

    # Filtrado contra memoria local (Caché)
    cached_ids = load_processed_cache()
    new_findings = tuple(item for item in all_findings if item["id"] not in cached_ids)

    if not new_findings:
        print("[+] No se detectaron vulnerabilidades nuevas que requieran alerta.")
        return 0

    # Construcción del reporte Markdown
    report_markdown = generate_markdown_report(new_findings, project_name)
    print("\n" + report_markdown + "\n")

    # Actualización del estado
    update_processed_cache(new_findings)
    print(f"[+] Estado actualizado. {len(new_findings)} vulnerabilidades guardadas en caché.")

    # Si hay al menos un Zero-Day, se eleva el código de salida a 1 para monitoreo
    has_zero_day = any(not item["has_patch"] for item in new_findings)
    return 1 if has_zero_day else 0


if __name__ == "__main__":
    sys.exit(run_pipeline())
