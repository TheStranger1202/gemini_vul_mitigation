# OSV Threat Auditor

> **Auditor determinista de dependencias con mitigación híbrida y costo cero.**  
> Diseñado para identificar vulnerabilidades confirmadas en entornos de producción y generar planes de remediación accionables sin incurrir en costos de tokens de IA.

---

## 🎯 Propuesta de Valor y Arquitectura

Las herramientas tradicionales de ciberseguridad basadas puramente en LLMs sufren de alucinaciones, cuotas de API costosas y exposición de datos privados. Por otro lado, los escáneres estáticos tradicionales reportan falsos positivos sin contextualizar el ciclo de vida del software.

**OSV Threat Auditor** resuelve este problema mediante un enfoque híbrido:
* **Costo Cero ($0):** Utiliza la infraestructura pública y gratuita de **OSV.dev** (mantenida por Google y la OpenSSF).
* **Determinismo Matemático:** Cruza directamente las versiones en uso contra rangos de parches oficiales (`fixed`), garantizando cero alucinaciones.
* **Mitigación Accionable:** Genera de forma instantánea el comando o la versión exacta a la cual actualizar la librería.
* **Asistencia Híbrida para Zero-Days:** Si una vulnerabilidad no cuenta con un parche disponible en el mercado, el motor genera un *prompt* técnico preconfigurado para consultar un LLM de confianza sin requerir integración con APIs de pago.
* **Prevención de Fatiga de Alertas:** Incorpora una caché de estado local para notificar cada CVE una única vez.
* **Paradigma Funcional Puro:** Desarrollado bajo principios de inmutabilidad, funciones puras y cero dependencias de Programación Orientada a Objetos (OOP).

---

## 📂 Estructura del Repositorio

```text
.
├── data/
│   ├── inventory.json        # Inventario de componentes auditados
│   └── cache.json            # Histórico de vulnerabilidades procesadas (ignorado en Git)
├── docs/
│   ├── architecture.md       # Diagramas y flujos de datos
│   ├── manual_de_uso.md      # Manual operativo y guía de extensibilidad
│   ├── data_schemas.md       # Contratos JSON
│   └── testing.md            # Estrategia TDD
├── src/
│   ├── __init__.py
│   ├── auditor.py            # Motor de clasificación y cruce de versiones
│   ├── config.py             # Configuración central y validación funcional
│   ├── reporter.py           # Formateo de Markdown y generación de prompts
│   └── scanner.py            # Cliente HTTP con Exponential Backoff
├── tests/
│   └── test_auditor.py       # Pruebas unitarias
├── .gitignore
├── main.py                   # Orquestador y punto de entrada CLI
├── pytest.ini                # Configuración del entorno de pruebas
├── README.md
└── requirements.txt          # Dependencias fijadas (Lockfile)
```

---

## 🚀 Inicio Rápido

### 1. Requisitos Previos
* Python 3.10 o superior.
* Entorno virtual de Python (`venv`).

### 2. Instalación
```bash
# Clonar el repositorio
git clone <URL_DEL_REPOSITORIO>
cd gemini_vul_mitigation

# Crear y activar el entorno virtual
python3 -m venv .venv
source .venv/bin/activate

# Instalar dependencias exactas
pip install -r requirements.txt
```

### 3. Ejecución de Pruebas Unitarias
```bash
pytest tests/
```

### 4. Ejecución del Escáner
```bash
python main.py
```

---

## ⚙️ Códigos de Salida para CI/CD

El script `main.py` retorna códigos de salida estándar para integrarse en pipelines automatizados:

| Código | Significado | Acción recomendada en Pipeline |
| :---: | :--- | :--- |
| `0` | **Éxito:** Sin vulnerabilidades o todas cuentan con parche reportado. | Permitir despliegue (Build Success). |
| `1` | **Alerta Crítica:** Se detectó al menos un Zero-Day activo sin parche. | Detener despliegue / Notificar al equipo de seguridad. |
| `2` | **Fallo Operativo:** Inventario malformado o error irrecuperable de red. | Marcar fallo de infraestructura en el pipeline. |

Para instrucciones sobre cómo configurar el inventario corporativo real, depurar la caché o integrar nuevas bases de datos de vulnerabilidades, consulta el [Manual de Operación y Extensibilidad](docs/manual_de_uso.md).
