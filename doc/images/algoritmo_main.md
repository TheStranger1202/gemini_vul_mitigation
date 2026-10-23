1. INICIO PROCESO DIARIO
2. ENTORNO = Cargar configuración y variables
3. cache_cves_procesados = Cargar base de datos local (ej. IDs guardados en SQLite/JSON)

4. cves_brutas = Scanner.obtener_cves_recientes(24, 7.0)
5. cves_nuevas = CREAR Lista Vacía

6. // Filtrar duplicados históricos
7. PARA CADA cve EN cves_brutas HACER:
   a. SI cve.id NO ESTÁ EN cache_cves_procesados:
      - AÑADIR cve a cves_nuevas

8. SI cves_nuevas está vacía:
   a. Registrar en log: "Sin vulnerabilidades nuevas. Terminando."
   b. TERMINAR PROCESO

9. cves_analizadas = ESPERAR Analyzer.evaluar_asincrono(cves_nuevas, ENTORNO.stack)
10. reporte = Reporter.crear_reporte(cves_analizadas)

11. SI reporte contiene datos:
    a. Reporter.enviar_notificacion(reporte)
    b. // Guardar estado para no volver a reportarlas
    c. PARA CADA cve EN cves_nuevas:
       - GUARDAR cve.id EN cache_cves_procesados

12. FIN PROCESO
