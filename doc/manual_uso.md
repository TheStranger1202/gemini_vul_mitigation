# Manual de Operación y Mantenimiento: OSV Threat Auditor

Guía operativa para analistas de seguridad y desarrolladores. Explica cómo definir inventarios reales, depurar la memoria del sistema e integrar nuevas fuentes de datos.

---

## 1. Configuración del Inventario Real (`data/inventory.json`)

El archivo `data/inventory.json` es la fuente de verdad del Tech Stack auditado. Para auditar proyectos reales de la empresa, reemplaza la lista de dependencias respetando el estándar de nombres y ecosistemas admitidos por OSV.dev.

### Ecosistemas Soportados
El campo `"ecosystem"` debe coincidir exactamente con una de las siguientes etiquetas admitidas:
* **`PyPI`**: Librerías de Python (`requests`, `django`, `fastapi`).
* **`npm`**: Paquetes de Node.js/JavaScript (`express`, `lodash`, `react`).
* **`Maven`**: Paquetes de Java/Kotlin bajo formato `groupId:artifactId` (ej. `org.apache.logging.log4j:log4j-core`).
* **`Go`**: Módulos de Go (ej. `golang.org/x/crypto`).
* **`crates.io`**: Paquetes del ecosistema Rust (ej. `serde`, `tokio`).
* **`NuGet`**: Paquetes de .NET/C# (ej. `Newtonsoft.Json`).
* **`Packagist`**: Dependencias de PHP (ej. `symfony/http-foundation`).

### Ejemplo de Configuración Real
```json
{
  "project_name": "Servicio-Autenticacion-Produccion",
  "last_updated": "2026-10-23",
  "dependencies": [
    {
      "ecosystem": "PyPI",
      "name": "fastapi",
      "version": "0.95.0"
    },
    {
      "ecosystem": "npm",
      "name": "jsonwebtoken",
      "version": "8.5.1"
    }
  ]
}
