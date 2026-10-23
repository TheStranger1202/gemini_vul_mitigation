# OSV Threat Auditor (Zero-Cost Vuln Sentinel)

Motor de auditoría determinista que analiza dependencias del proyecto contra la base de datos de Open Source Vulnerabilities (OSV.dev). Diseñado para proporcionar Inteligencia de Amenazas Accionable sin depender de APIs de terceros de pago.

## Valor de Negocio y Ventajas
* **Costo Cero ($0):** Utiliza bases de datos públicas y gratuitas, eliminando la necesidad de tokens de IA para el análisis estándar.
* **Privacidad Absoluta:** El inventario de software y las vulnerabilidades detectadas nunca se envían a LLMs de terceros.
* **Cero Falsos Positivos:** El análisis es 100% determinista basado en el cruce de versiones exactas, eliminando las alucinaciones de IA.
* **Mitigación Híbrida:** Genera comandos de actualización directos para vulnerabilidades parcheadas, y elabora *prompts* pre-cargados con contexto técnico para asistir en la mitigación de Zero-Days.
