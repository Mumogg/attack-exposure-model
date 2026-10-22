# Prevalencia (Red Canary)

`red_canary_2026.csv` es la plantilla que lee el paso 4 (`src/aem/config.py`, `PREVALENCE_FILE`). **Quedó vacía al congelar el experimento** (RUNBOOK §j), así que la columna `prevalence` de las salidas dice `sin dato disponible`. Llenarla cambiaría las salidas del pipeline y exigiría un run-id nuevo.

Columnas:
- `technique_id`: ID de ATT&CK tal como aparece en el informe (p. ej. `T1059.001`).
- `rank`: puesto en la clasificación del informe (entero).
- `source_note`: referencia opcional (página, tabla).

Si una técnica no figura, la salida dice literalmente `sin dato disponible`. No se hereda la prevalencia de la técnica padre.

Los rankings reales de Red Canary están en `context/` (ediciones 2019 y 2020 del repositorio público, y el top 10 de 2026). Son **solo contexto para la discusión**: ningún código los lee. Ver `context/README.md`.
