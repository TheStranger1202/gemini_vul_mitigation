"""Módulo de configuración e inventario bajo paradigma funcional.

Este módulo centraliza las constantes de infraestructura, resuelve rutas absolutas
de almacenamiento y provee funciones puras para validar y cargar el inventario
de software que será auditado contra la base de datos de OSV.dev.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

# ==============================================================================
# RESOLUCIÓN DETERMINISTA DE RUTAS
# ==============================================================================
# Se calcula la raíz del proyecto respecto a la posición física de este archivo.
# Evita fallos cuando el script se invoca desde diferentes directorios de trabajo.
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# Rutas centralizadas de almacenamiento local
DATA_DIR: Path = PROJECT_ROOT / "data"
DEFAULT_INVENTORY_PATH: Path = DATA_DIR / "inventory.json"
CACHE_FILE_PATH: Path = DATA_DIR / "cache.json"

# ==============================================================================
# PARÁMETROS OPERATIVOS Y RESILIENCIA DE RED
# ==============================================================================
OSV_API_URL: str = "https://api.osv.dev/v1/query"
REQUEST_TIMEOUT_SECONDS: int = 10  # Tiempo máximo de espera por respuesta HTTP
MAX_API_RETRIES: int = 3           # Intentos permitidos ante caídas de red
INITIAL_BACKOFF_SECONDS: float = 2.0  # Base para cálculo de espera exponencial


# ==============================================================================
# FUNCIONES PURAS DE VALIDACIÓN Y PARSEO
# ==============================================================================
def validate_dependency(raw_dep: Mapping[str, Any], index: int) -> dict[str, str]:
    """Valida y sanea un registro individual de dependencia.

    Args:
        raw_dep: Diccionario con los datos sin procesar del JSON.
        index: Índice numérico del elemento para trazabilidad en mensajes de error.

    Returns:
        dict[str, str]: Diccionario con las claves 'ecosystem', 'name' y 'version'
        saneadas y libres de espacios en blanco adicionales.

    Raises:
        ValueError: Si algún campo requerido falta o contiene cadenas vacías.
    """
    if not isinstance(raw_dep, dict):
        raise ValueError(f"La dependencia en el índice {index} debe ser un objeto JSON.")

    # Saneamiento de cadenas: eliminación de espacios en blanco iniciales/finales
    ecosystem = str(raw_dep.get("ecosystem", "")).strip()
    name = str(raw_dep.get("name", "")).strip()
    version = str(raw_dep.get("version", "")).strip()

    # Validación de campos obligatorios para la API de OSV
    if not ecosystem:
        raise ValueError(f"Falta el campo 'ecosystem' en el índice {index}.")
    if not name:
        raise ValueError(f"Falta el campo 'name' en el índice {index}.")
    if not version:
        raise ValueError(f"Falta el campo 'version' en el índice {index}.")

    return {
        "ecosystem": ecosystem,
        "name": name,
        "version": version,
    }


def parse_inventory_content(raw_data: Any) -> dict[str, Any]:
    """Valida la estructura raíz del inventario y transforma las dependencias.

    Aplica un enfoque inmutable: transforma la lista de dependencias en una tupla
    para evitar efectos secundarios durante la ejecución del programa.

    Args:
        raw_data: Objeto deserializado de la carga del JSON.

    Returns:
        dict[str, Any]: Estructura validada con el nombre del proyecto y
        una tupla de dependencias procesadas.

    Raises:
        ValueError: Si el JSON no tiene las propiedades raíz obligatorias.
    """
    if not isinstance(raw_data, dict):
        raise ValueError("La raíz del inventario debe ser un objeto JSON.")

    project_name = raw_data.get("project_name")
    if not isinstance(project_name, str) or not project_name.strip():
        raise ValueError("El campo 'project_name' debe ser una cadena no vacía.")

    raw_dependencies = raw_data.get("dependencies")
    if not isinstance(raw_dependencies, list):
        raise ValueError("El campo 'dependencies' debe ser una lista.")

    # Mapeo funcional iterando sobre cada elemento para validación individual
    validated_dependencies = [
        validate_dependency(dep, idx) for idx, dep in enumerate(raw_dependencies)
    ]

    return {
        "project_name": project_name.strip(),
        "dependencies": tuple(validated_dependencies),  # Tupla para garantizar inmutabilidad
    }


def read_json_file(file_path: Path) -> Any:
    """Lee y deserializa un archivo JSON desde el disco.

    Args:
        file_path: Ruta absoluta o relativa del archivo a leer.

    Returns:
        Any: Contenido deserializado del archivo JSON.

    Raises:
        FileNotFoundError: Si el archivo no existe en la ruta dada.
        json.JSONDecodeError: Si el archivo no contiene un JSON válido.
    """
    if not file_path.is_file():
        raise FileNotFoundError(f"Archivo no encontrado en: {file_path}")

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


# ==============================================================================
# PUNTO DE ENTRADA PÚBLICO
# ==============================================================================
def load_inventory(path: Path | None = None) -> dict[str, Any]:
    """Orquesta la lectura y validación del inventario de software.

    Esta función compone la lectura física de I/O con la validación de dominio.

    Args:
        path: Ruta personalizada opcional. Si es None, utiliza DEFAULT_INVENTORY_PATH.

    Returns:
        dict[str, Any]: Inventario saneado e inmutable listo para auditoría.
    """
    target_path = path if path is not None else DEFAULT_INVENTORY_PATH
    raw_content = read_json_file(target_path)
    return parse_inventory_content(raw_content)
