1. FUNCION obtener_cves_recientes(horas_atras, umbral_cvss):
2. intentos_maximos = 3
3. retraso_base = 5 segundos

4. PARA intento DESDE 1 HASTA intentos_maximos HACER:
   a. INTENTAR:
      - respuesta = Llamar API (NVD/OSV) por vulnerabilidades de las últimas 'horas_atras'
      - SI respuesta es EXITOSA:
        - cves_filtradas = Filtrar respuesta DONDE cvss >= umbral_cvss
        - RETORNAR cves_filtradas
   b. CAPTURAR ERROR (Timeout, 50x, 429):
      - SI intento == intentos_maximos: 
        - Registrar error crítico y ABORTAR
      - SINO:
        - Esperar (retraso_base * 2^intento) segundos
        - Registrar advertencia: "Reintentando conexión a API..."

5. FIN FUNCION
