# Estrategia de Pruebas Unitarias (TDD)

Las pruebas se ejecutarán utilizando el framework `pytest`. Los tests no deben golpear la API real de OSV.dev, sino utilizar *Mocks* (simulaciones) de las respuestas JSON.

## Matriz de Pruebas Críticas

### 1. Pruebas de Lógica (Módulo: `auditor.py`)
* **`test_auditor_with_fixed_version`**: 
  * *Input:* Mock de JSON de OSV que incluye el bloque `"events": [{"fixed": "2.15.0"}]`.
  * *Expectativa:* El auditor debe retornar un objeto indicando `has_patch: True` y `fixed_version: "2.15.0"`.
* **`test_auditor_zero_day`**: 
  * *Input:* Mock de JSON de OSV donde el evento `fixed` no existe.
  * *Expectativa:* El auditor debe retornar `has_patch: False` para forzar la generación del prompt de asistencia IA.

### 2. Pruebas de Resiliencia (Módulo: `scanner.py`)
* **`test_scanner_backoff_retry`**: 
  * *Input:* Mock de la librería `requests` que devuelve un `HTTP 503 (Service Unavailable)` en los dos primeros intentos y un `HTTP 200` en el tercero.
  * *Expectativa:* La función no debe lanzar una excepción fatal; debe esperar el tiempo de *backoff*, reintentar y retornar los datos del tercer intento exitoso.

### 3. Pruebas de Estado (Módulo: `main.py`)
* **`test_cache_filters_duplicates`**: 
  * *Input:* Pasar una lista de CVEs donde el ID "GHSA-123" ya existe en `cache.json`.
  * *Expectativa:* La lista enviada al `auditor.py` debe tener longitud 0 (el duplicado es descartado).
