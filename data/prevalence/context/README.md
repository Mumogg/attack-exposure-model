# Prevalencia de Red Canary: tablas de contexto

Estas tablas son **solo contexto para la discusión de la tesis**. Ningún código del pipeline, de la evaluación ni del reporte lee esta carpeta (lo comprueba `tests/test_prevalence_context.py`). La columna `prevalence` de las salidas del experimento sale de la plantilla `../red_canary_2026.csv`, que quedó vacía al congelar el experimento (RUNBOOK §j): por eso dice `sin dato disponible`.

Los valores son **puestos en un ranking publicado por el proveedor**, no tasas ni porcentajes. «sin dato» significa que la técnica no tiene puesto ese año en la fuente.

## `red_canary_2019_2020.csv`

- **Fuente:** Red Canary, repositorio `redcanaryco/public-research`, `technique_prevalence/techniques_with_prevalence.json`, commit `9542012a8e003b7e71f221d213e6dbd96292c2fc` (la carpeta no cambia desde el 2020-06-11). Descargado el 2026-10-21.
- **Licencia:** MIT, «Copyright (c) 2020 Red Canary, Inc.». El aviso completo está en `LICENSE-red-canary-public-research.txt` y acompaña a esta tabla, como exige la licencia.
- **Años:** la fuente trae solo `ranking_2019` y `ranking_2020`, que son las ediciones 2019 y 2020 del *Threat Detection Report*. La fuente no indica el periodo de los datos.
- **Filas:** las 121 técnicas con puesto en al menos una edición (115 en 2020, 67 en 2019), de 614 registros de la fuente. Las otras 493 no tienen puesto en ninguna edición.
- **Columnas:**
  - `technique_id`, `technique_name`: tal como los publica Red Canary, con IDs de ATT&CK anteriores a las subtécnicas (p. ej. `T1086` PowerShell).
  - `ranking_2019`, `ranking_2020`: puesto entero o `sin dato`.
  - `attack_v19_2_id`, `attack_v19_2_status`: el ID vigente en ATT&CK Enterprise v19.2. Sale del bundle `data/attack/enterprise-attack-19.2.json`: el mismo ID si sigue vigente (56), el reemplazo oficial de la relación `revoked-by` si fue revocado (57), o `sin dato` si está obsoleto sin reemplazo (4) o no existe en v19.2 (4, IDs de PRE-ATT&CK).
  - `source_url`, `retrieved_date`, `note`.
- **SHA-256 de los archivos descargados:** `techniques_with_prevalence.json` `282c9aaeaea6178811e900ca3ffde202d9a65ca78b29f2d81096a5ad254d6115`; `techniques_with_prevalence.yaml` (mismo contenido que el JSON) `44b87820446c677bc895ecd9749e9417f8051c31470b94b9ac18dce7e7504ceb`.

## `red_canary_2026_top10.csv`

- **Fuente:** Red Canary, *2026 Threat Detection Report*, https://redcanary.com/threat-detection-report/techniques/, consultada el 2026-10-21. Datos de 2025 («observed in confirmed threats across the Red Canary customer base in 2025»).
- **Contenido:** solo puesto, ID y nombre de las 10 técnicas del gráfico, en el orden de la página. La página no tiene licencia abierta («All rights reserved»), así que no se copia nada más. Tampoco dice qué cuenta el ranking.
- La página escribe el tercer ID como «T1059:003»; la tabla usa `T1059.003` y lo anota en `note`. Los 10 IDs están vigentes en ATT&CK v19.2.
- No se mezcla con la tabla de 2019–2020: son ediciones, metodologías y versiones de ATT&CK distintas.

## Cómo se generó

Descarga manual (no es parte de `aem`, sin llamadas a la API de Gemini) con `gh api repos/redcanaryco/public-research/contents/<archivo>?ref=master -H 'Accept: application/vnd.github.raw'`, y conversión con un script local que solo selecciona filas y columnas y agrega el ID de v19.2. Ningún valor se completó ni se estimó.
