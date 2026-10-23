# Esquemas de Datos (Data Schemas)

## 1. Inventario de Entrada (`data/inventory.json`)
Este archivo actúa como la fuente de verdad del *Tech Stack* que `scanner.py` consultará contra la API de OSV.dev.

\`\`\`json
{
  "project_name": "Core-Backend",
  "last_updated": "2026-10-23",
  "dependencies": [
    {
      "ecosystem": "PyPI",
      "name": "requests",
      "version": "2.25.0"
    },
    {
      "ecosystem": "npm",
      "name": "express",
      "version": "4.17.1"
    },
    {
      "ecosystem": "Maven",
      "name": "org.apache.logging.log4j:log4j-core",
      "version": "2.14.1"
    }
  ]
}
\`\`\`
*(Nota: El campo `ecosystem` debe coincidir con los estándares de OSV: npm, PyPI, Maven, Go, Rust, etc.)*

## 2. Caché de Estado (`data/cache.json`)
Utilizado por `main.py` para persistir el historial de vulnerabilidades reportadas y evitar la fatiga de alertas.

\`\`\`json
{
  "processed_vulnerabilities": [
    {
      "cve_id": "GHSA-jfh8-c2jp-5v3q",
      "package": "log4j-core",
      "ecosystem": "Maven",
      "first_reported_at": "2026-10-23T11:30:00Z",
      "mitigation_type": "fixed_version"
    }
  ]
}
\`\`\`
