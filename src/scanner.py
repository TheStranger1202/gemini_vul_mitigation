"""Módulo de recolección y consulta HTTP hacia OSV.dev.

Opera de forma determinista enviando paquetes y versiones al endpoint
de consulta por lote o individual, aplicando reintentos exponenciales
para tolerar fallos transitorios de red.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Sequence
import requests

from src.config import (
    INITIAL_BACKOFF_SECONDS,
    MAX_API_RETRIES,
    OSV_API_URL,
    REQUEST_TIMEOUT_SECONDS,
)


def build_osv_payload(dep: Mapping[str, str]) -> dict[str, Any]:
    """Genera el cuerpo JSON exigido por la API de OSV.dev para consultas de versión.

    Args:
        dep: Diccionario normalizado con 'ecosystem', 'name' y 'version'.

    Returns:
        dict[str, Any]: Payload formateado según la especificación de OSV.
    """
    return {
        "version": dep["version"],
        "package": {
            "name": dep["name"],
            "ecosystem": dep["ecosystem"],
        },
    }


def query_single_dependency_with_backoff(
    dependency: Mapping[str, str],
    max_retries: int = MAX_API_RETRIES,
    base_delay: float = INITIAL_BACKOFF_SECONDS,
) -> dict[str, Any]:
    """Ejecuta una petición POST a OSV.dev aplicando reintentos exponenciales.

    Args:
        dependency: Dependencia a auditar.
        max_retries: Cantidad máxima de reintentos ante fallas no terminales.
        base_delay: Tiempo base en segundos para el cálculo del backoff.

    Returns:
        dict[str, Any]: Diccionario con la respuesta cruda deserializada de OSV.
        Si no hay vulnerabilidades, retorna un diccionario con clave 'vulns' vacía.

    Raises:
        ConnectionError: Si se agotan los reintentos sin obtener respuesta exitosa.
    """
    payload = build_osv_payload(dependency)
    headers = {"Content-Type": "application/json"}

    for attempt in range(1, max_retries + 1):
        try:
            response = requests.post(
                OSV_API_URL,
                json=payload,
                headers=headers,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )

            # Si el endpoint responde exitosamente (200 OK)
            if response.status_code == 200:
                data = response.json()
                return data if "vulns" in data else {"vulns": []}

            # Si el servicio está saturado (429) o fallando temporalmente (5xx)
            if response.status_code in (429, 500, 502, 503, 504):
                sleep_time = base_delay * (2 ** (attempt - 1))
                time.sleep(sleep_time)
                continue

            # Errores 4xx permanentes (excepto 429) no deben reintentarse
            response.raise_for_status()

        except (requests.exceptions.RequestException, requests.exceptions.Timeout):
            if attempt == max_retries:
                raise ConnectionError(
                    f"Fallo irrecuperable al consultar OSV para: {dependency['name']} "
                    f"tras {max_retries} intentos."
                )
            sleep_time = base_delay * (2 ** (attempt - 1))
            time.sleep(sleep_time)

    return {"vulns": []}


def scan_inventory(
    dependencies: Sequence[Mapping[str, str]],
) -> tuple[dict[str, Any], ...]:
    """Audita una secuencia de dependencias contra OSV.dev.

    Args:
        dependencies: Tupla o lista de dependencias a verificar.

    Returns:
        tuple[dict[str, Any], ...]: Tupla inmutable que contiene cada dependencia
        emparejada con la lista de vulnerabilidades encontradas.
    """
    scan_results = []

    for dep in dependencies:
        raw_result = query_single_dependency_with_backoff(dep)
        vulns = raw_result.get("vulns", [])
        if vulns:
            scan_results.append({
                "dependency": dep,
                "vulnerabilities": tuple(vulns),
            })

    return tuple(scan_results)
