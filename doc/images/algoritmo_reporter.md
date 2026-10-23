1. FUNCION crear_reporte(lista_cves_analizadas):
2. lineas_reporte = CREAR Lista Vacía

3. PARA CADA cve_evaluado EN lista_cves_analizadas HACER:
   a. SI cve_evaluado.afecta_nuestro_stack ES VERDADERO:
      - AÑADIR "### " + cve_evaluado.cve_id A lineas_reporte
      - AÑADIR "**Impacto:** " + cve_evaluado.justificacion_impacto A lineas_reporte
      - AÑADIR "**Mitigación:**" A lineas_reporte
      - PARA CADA paso EN cve_evaluado.plan_mitigacion:
        - AÑADIR "- " + paso A lineas_reporte
      - AÑADIR "---" (Separador) A lineas_reporte
   
4. SI lineas_reporte NO ESTÁ VACÍA:
   a. RETORNAR UNIR(lineas_reporte, con saltos de línea)
5. SINO:
   a. RETORNAR Nulo
6. FIN FUNCION
