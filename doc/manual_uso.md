# Manual de Operación y Extensibilidad: OSV Threat Auditor

Este documento detalla la operación del motor de auditoría, las especificaciones de la base de datos OSV.dev, la manipulación del inventario corporativo y la arquitectura para extender el escáner a fuentes de datos adicionales.

---

## 1. Fundamentos: ¿Por qué OSV.dev?

**OSV (Open Source Vulnerabilities)** es una iniciativa de código abierto liderada por **Google** y la **OpenSSF (Open Source Security Foundation)** para resolver la fragmentación histórica de los avisos de seguridad.

### Diferencias frente al NVD tradicional (NIST)
* **Precisión de versión:** El NVD utiliza cadenas CPE (*Common Platform Enumeration*), propensas a errores tipográficos y desactualizaciones humanas. OSV utiliza el esquema RFC-OSV, mapeando versiones semánticas y *commit hashes* exactos de Git.
* **Cobertura Unificada:** OSV agrega en tiempo real las bases de datos de **GitHub Security Advisories (GHSA)**, PyPA (Python), RustSec, Go Vulnerability Database, Debian, Alpine y Android bajo una misma API pública.
* **Infraestructura y Conectividad:** La API de OSV (`https://api.osv.dev/v1/query`) no requiere llaves de autenticación (API Keys), no impone costos de tokens y opera sobre redes de distribución global con alta tolerancia a la concurrencia.

---

## 2. Configuración del Inventario Corporativo (`data/inventory.json`)

El archivo `data/inventory.json` es la fuente de verdad del software bajo auditoría. La función pura `load_inventory` en `src/config.py` valida la presencia obligatoria de los campos `project_name` y `dependencies`.

### Esquema Obligatorio
```json
{
  "project_name": "Nombre-Del-Servicio-O-Proyecto",
  "last_updated": "AAAA-MM-DD",
  "dependencies": [
    {
      "ecosystem": "<ECOSISTEMA_VALIDO>",
      "name": "<NOMBRE_EXACTO_DEL_PAQUETE>",
      "version": "<VERSION_ACTUAL_EN_USO>"
    }
  ]
}
```

### Ecosistemas Soportados
El valor del campo `"ecosystem"` debe respetar la convención de OSV:

| Ecosistema | Plataforma | Formato del Nombre (`name`) | Ejemplo |
| :--- | :--- | :--- | :--- |
| **`PyPI`** | Python | Nombre de la librería tal cual aparece en pip | `"requests"`, `"django"`, `"fastapi"` |
| **`npm`** | Node.js / JS | Nombre del paquete (incluyendo `@scope` si aplica) | `"express"`, `"lodash"`, `"@angular/core"` |
| **`Maven`** | Java / Kotlin | Identificador completo `groupId:artifactId` | `"org.apache.logging.log4j:log4j-core"` |
| **`Go`** | Lenguaje Go | Ruta del módulo completo | `"golang.org/x/crypto"` |
| **`crates.io`** | Rust | Nombre del crate | `"serde"`, `"tokio"`, `"rand"` |
| **`NuGet`** | .NET / C# | Identificador de paquete NuGet | `"Newtonsoft.Json"` |
| **`Packagist`** | PHP | `vendor/package` | `"symfony/http-foundation"` |
| **`RubyGems`** | Ruby | Nombre de la gema | `"rails"`, `"nokogiri"` |

---

## 3. Gestión del Ciclo de Vida y Alertas (Caché de Estado)

El sistema implementa persistencia ligera en `data/cache.json` para evitar notificar vulnerabilidades que el equipo técnico ya tiene en seguimiento.

### Comportamiento del Filtro
1. En cada ejecución, `main.py` extrae los IDs de `data/cache.json`.
2. Si un CVE/GHSA detectado por OSV ya se encuentra en el conjunto, es omitido del reporte Markdown.
3. Si el CVE/GHSA es nuevo, se incluye en el reporte y se anexa a la caché con marca de tiempo UTC.

### Casos de Mantenimiento

* **Forzar re-auditoría completa (Hard Reset):**  
  Para generar un informe exhaustivo con todos los hallazgos históricos:
  ```bash
  rm data/cache.json
  python main.py
  ```

* **Operación en Entornos Efímeros (CI/CD):**  
  En runners de GitHub Actions, GitLab CI o Jenkins, el directorio `data/` puede persistirse entre ejecuciones configurando mecanismos nativos de *Cache Actions* sobre la ruta `data/cache.json`.

---

## 4. Guía de Extensibilidad: Integrar Fuentes Adicionales

El sistema está diseñado bajo el paradigma funcional. La capa de extracción (`scanner.py`) es independiente de la capa lógica (`auditor.py`). Para agregar una fuente secundaria de vulnerabilidades (ej. una API interna de la empresa o Snyk):

### Paso 1: Implementar la función de consulta pura en `src/scanner.py`
Define una función que realice la llamada HTTP y transforme la respuesta al contrato mínimo que espera el auditor (`id`, `summary`, y el bloque `affected` con eventos `fixed`):

```python
def query_internal_security_api(dep: Mapping[str, str]) -> dict[str, Any]:
    """Consulta la base de datos interna de la empresa."""
    # Ejemplo conceptual:
    # response = requests.get(f"https://sec.internal.net/api/{dep['name']}/{dep['version']}")
    # return normalize_to_osv_format(response.json())
    return {"vulns": []}
```

### Paso 2: Componer las fuentes en `scan_inventory`
En `src/scanner.py`, concatena los resultados de múltiples llamadas funcionales sin mutar listas globales:

```python
def scan_inventory(
    dependencies: Sequence[Mapping[str, str]],
) -> tuple[dict[str, Any], ...]:
    scan_results = []

    for dep in dependencies:
        # Consulta a OSV.dev
        osv_findings = query_single_dependency_with_backoff(dep).get("vulns", [])
        
        # Consulta a fuente secundaria
        custom_findings = query_internal_security_api(dep).get("vulns", [])
        
        # Fusión inmutable de hallazgos
        total_vulns = tuple(osv_findings) + tuple(custom_findings)
        
        if total_vulns:
            scan_results.append({
                "dependency": dep,
                "vulnerabilities": total_vulns,
            })

    return tuple(scan_results)
```

Dado que `src/auditor.py` solo inspecciona diccionarios y tuplas genéricas, **no es necesario modificar una sola línea de la capa de auditoría ni del reporteador**.
