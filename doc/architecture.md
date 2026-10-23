# Arquitectura del Sistema

El sistema sigue un flujo de extracción local y consulta externa determinista, dividido en cuatro módulos:

1. **`config.py` (Contexto):** Carga el inventario de dependencias local (ej. `requirements.txt`, `package.json`).
2. **`scanner.py` (Extractor OSV):** Realiza consultas HTTP POST a la API de `osv.dev/v1/query` utilizando el ecosistema y la versión del paquete.
3. **`auditor.py` (Lógica y Cruce):** Evalúa el JSON de respuesta. Si existe el campo `fixed`, extrae la versión segura. Si no, lo clasifica como Zero-Day.
4. **`reporter.py` (Notificador):** Transforma el veredicto en instrucciones de actualización accionables o genera plantillas de *prompts* para análisis manual.
## Códigos de Salida (Exit Codes)
El controlador `main.py` devolverá códigos de salida estándar del sistema operativo para facilitar su integración en pipelines de CI/CD:

* **`Exit Code 0` (Éxito):** Ejecución finalizada correctamente. No se encontraron vulnerabilidades nuevas, o las encontradas fueron procesadas y reportadas con éxito.
* **`Exit Code 1` (Alerta de Seguridad):** Ejecución exitosa, pero se detectó al menos una vulnerabilidad Zero-Day (sin parche). Útil para hacer fallar un pipeline (Build) de forma preventiva.
* **`Exit Code 2` (Falla de Infraestructura):** Error irrecuperable. Ocurre si el archivo `inventory.json` está corrupto, o si la API de OSV.dev no responde tras agotar todos los intentos de *Backoff*.
## Diagrama de Flujo (PlantUML)

```plantuml
@startuml
title Flujo Determinista Híbrido: OSV Threat Auditor

participant "main.py\n(Controlador)" as Main
database "Caché Local" as Cache
participant "scanner.py\n(Motor OSV)" as Scanner
database "API OSV.dev" as OSV
participant "auditor.py\n(Lógica)" as Auditor
participant "reporter.py\n(Notificador)" as Reporter

Main -> Cache: Cargar IDs reportados
Main -> Scanner: auditar_inventario(dependencias)
Scanner -> OSV: POST /query (Paquete + Versión)
OSV --> Scanner: JSON con CVEs y parches
Scanner --> Main: CVEs confirmadas
Main -> Main: Filtrar duplicados en caché

Main -> Auditor: evaluar_mitigacion(cves_nuevas)
Auditor -> Auditor: Extraer campo 'fixed_version'
Auditor --> Main: Datos de parcheo estructurados

Main -> Reporter: generar_reporte(datos_parcheo)
Reporter -> Reporter: Generar comandos de actualización\no plantillas de prompts (Zero-Days)
Reporter --> Main: Markdown final

Main -> Cache: Guardar nuevos IDs
@enduml
