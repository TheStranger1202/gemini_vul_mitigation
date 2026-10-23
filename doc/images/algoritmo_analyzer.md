1. FUNCION ASINCRONA evaluar_asincrono(lista_cves, stack_empresa):
2. tareas_concurrentes = CREAR Lista Vacía

3. PARA CADA cve EN lista_cves HACER:
   a. prompt = Construir_Prompt(cve, stack_empresa)
   b. AÑADIR tarea_asincrona( llamar_gemini_con_reintentos(prompt) ) A tareas_concurrentes

4. // Ejecutar todas las llamadas en paralelo
5. resultados = ESPERAR TODAS LAS tareas_concurrentes
6. RETORNAR resultados filtrando errores
7. FIN FUNCION

8. FUNCION ASINCRONA llamar_gemini_con_reintentos(prompt):
9. PARA intento DESDE 1 HASTA 3 HACER:
   a. INTENTAR:
      - respuesta = ESPERAR API_GEMINI(prompt, formato="json")
      - RETORNAR respuesta
   b. CAPTURAR ERROR_429_TOO_MANY_REQUESTS:
      - Esperar 10 segundos
   c. CAPTURAR OTRO_ERROR:
      - Registrar error y RETORNAR Nulo
10. RETORNAR Nulo
11. FIN FUNCION
