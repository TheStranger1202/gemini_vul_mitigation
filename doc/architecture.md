# Arquitectura del Sistema

El sistema sigue un flujo de extracción local y consulta externa determinista, dividido en cuatro módulos:

1. **`config.py` (Contexto):** Carga el inventario de dependencias local (ej. `requirements.txt`, `package.json`).
2. **`scanner.py` (Extractor OSV):** Realiza consultas HTTP POST a la API de `osv.dev/v1/query` utilizando el ecosistema y la versión del paquete.
3. **`auditor.py` (Lógica y Cruce):** Evalúa el JSON de respuesta. Si existe el campo `fixed`, extrae la versión segura. Si no, lo clasifica como Zero-Day.
4. **`reporter.py` (Notificador):** Transforma el veredicto en instrucciones de actualización accionables o genera plantillas de *prompts* para análisis manual.

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
