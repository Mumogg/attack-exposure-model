# Análisis de sensibilidad. No sustituye los resultados principales; la configuración confirmada (D-20, D-21) no cambió

Corrida `2026-10-18-main` · modelo `gemini-3.8-flash` · sin llamadas a la API (se releen las salidas por corrida guardadas).

- Configuración actual (`data/model_config.yaml`): `covered_min` = 4, `partial_min` = 1, `subtechnique_policy` = `no_inherit`. Cada fila cambia **un solo** parámetro; el resto queda como en la configuración actual.
- «Brechas»: técnicas de referencia que el paso 2 deja en «parcial» o «sin cobertura» (denominador del indicador 3 del modelo).
- Persistencia del modelo en %: media `_fail0` y su DE muestral; las columnas `_valid` están en el CSV y el JSON. Razones `mut/orig` y `anon/orig` sobre `_fail0`.
- Paso 3: acciones de todas las corridas válidas (técnicas de `extracted_validated`, analista automático), y cuántas cambian respecto de la configuración actual. El paso 3 no tiene indicador.
- La fila «actual» coincide exactamente con el indicador 3 de `results/results.json`.
- El enfoque tradicional no depende de estos parámetros (D-62) y no se repite aquí.

| Parámetro | Valor | Escenario | Brechas | orig media _fail0 | mut media _fail0 | anon media _fail0 | orig DE _fail0 | mut DE _fail0 | anon DE _fail0 | mut/orig _fail0 | anon/orig _fail0 | paso 3: Act | paso 3: Attend | paso 3: Track* | paso 3: Track | paso 3: acciones distintas de la configuración actual |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| actual | covered_min=4, partial_min=1, no_inherit | gunra | 28 | 34.29 | 30.71 | 32.14 | 4.79 | 7.82 | 2.53 | 0.8958 | 0.9375 | 54 | 99 | 76 | 44 | 0 |
| covered_min | 3 | gunra | 23 | 37.39 | 33.04 | 34.78 | 5.83 | 9.53 | 3.07 | 0.8837 | 0.9302 | 54 | 99 | 61 | 59 | 15 |
| covered_min | 5 | gunra | 35 | 42.29 | 38.86 | 38.86 | 3.73 | 6.26 | 2.56 | 0.9189 | 0.9189 | 54 | 130 | 89 | 0 | 75 |
| partial_min | 2 | gunra | 28 | 34.29 | 30.71 | 32.14 | 4.79 | 7.82 | 2.53 | 0.8958 | 0.9375 | 56 | 112 | 61 | 44 | 17 |
| subtechnique_policy | inherit_parent | gunra | 28 | 34.29 | 30.71 | 32.14 | 4.79 | 7.82 | 2.53 | 0.8958 | 0.9375 | 39 | 109 | 76 | 49 | 20 |
| actual | covered_min=4, partial_min=1, no_inherit | interlock | 18 | 52.22 | 56.67 | 56.67 | 3.04 | 4.65 | 7.24 | 1.0851 | 1.0851 | 16 | 70 | 100 | 46 | 0 |
| covered_min | 3 | interlock | 15 | 49.33 | 54.67 | 54.67 | 3.65 | 5.58 | 8.69 | 1.1081 | 1.1081 | 16 | 70 | 70 | 76 | 30 |
| covered_min | 5 | interlock | 23 | 50.43 | 52.17 | 53.91 | 2.38 | 5.32 | 4.96 | 1.0345 | 1.069 | 16 | 70 | 131 | 15 | 31 |
| partial_min | 2 | interlock | 18 | 52.22 | 56.67 | 56.67 | 3.04 | 4.65 | 7.24 | 1.0851 | 1.0851 | 16 | 103 | 67 | 46 | 33 |
| subtechnique_policy | inherit_parent | interlock | 18 | 52.22 | 56.67 | 56.67 | 3.04 | 4.65 | 7.24 | 1.0851 | 1.0851 | 1 | 84 | 101 | 46 | 16 |
| actual | covered_min=4, partial_min=1, no_inherit | akira | 25 | 38.4 | 36.0 | 40.0 | 3.58 | 6.32 | 5.66 | 0.9375 | 1.0417 | 0 | 115 | 192 | 67 | 0 |
| covered_min | 3 | akira | 19 | 28.42 | 26.32 | 29.47 | 2.88 | 6.45 | 7.98 | 0.9259 | 1.037 | 0 | 102 | 155 | 117 | 63 |
| covered_min | 5 | akira | 35 | 48.0 | 45.71 | 48.57 | 3.13 | 7.28 | 5.71 | 0.9524 | 1.0119 | 0 | 168 | 192 | 14 | 106 |
| partial_min | 2 | akira | 25 | 38.4 | 36.0 | 40.0 | 3.58 | 6.32 | 5.66 | 0.9375 | 1.0417 | 0 | 129 | 178 | 67 | 14 |
| subtechnique_policy | inherit_parent | akira | 25 | 38.4 | 36.0 | 40.0 | 3.58 | 6.32 | 5.66 | 0.9375 | 1.0417 | 0 | 88 | 204 | 82 | 27 |
