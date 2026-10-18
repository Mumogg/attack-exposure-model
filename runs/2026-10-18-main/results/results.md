# Resultados de la evaluación — corrida `2026-10-18-main`

**RESULTADO PARCIAL: faltan escenarios** — ESCENARIOS OMITIDOS: akira (sin texto local)

- Modelo: `gemini-3.8-flash` · temperatura 0 · ATT&CK 19.2 · 5 corridas por escenario × versión · modo demo: no
- Media y desviación estándar muestral (n−1). «sin dato disponible»: no hay corridas o el valor no está definido.
- Cada media se informa dos veces (D-67): `_fail0` cuenta cada corrida fallida (`failed_runs`) como 0 y `_valid` usa solo las corridas válidas. Indicadores 1 y 3 (modelo): media principal: `_fail0`; `_valid` es secundaria. Indicador 5: ambas con el mismo peso; contar una falla como 0 violaciones favorece al modelo.
- Origen: gemini-api · versión del modelo: gemini-3.8-flash · fecha: 2026-10-18 · hash SHA-256 de las plantillas de prompt: extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b
- No hay indicador para el paso 3 ni para la revisión global (criterio del analista).

Escenarios/versiones sin texto (no evaluados): akira: orig, akira: mut, akira: anon

## Corridas por escenario y versión (válidas, fallidas y motivo de cada falla)

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| scenario | version | runs_total | runs_valid | failed_runs | empty_runs | failure_reasons |
|---|---|---|---|---|---|---|
| gunra | orig | 5 | 5 | 0 | 0 | ninguna |
| gunra | mut | 5 | 5 | 0 | 0 | ninguna |
| gunra | anon | 5 | 5 | 0 | 0 | ninguna |
| interlock | orig | 5 | 5 | 0 | 0 | ninguna |
| interlock | mut | 5 | 5 | 0 | 0 | ninguna |
| interlock | anon | 5 | 5 | 0 | 0 | ninguna |

## Indicador 1 — Precisión y exhaustividad del paso 1 (%, sobre extracted_raw; media principal: `_fail0`)

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| scenario | version | level | runs_total | runs_valid | failed_runs | precision_mean_fail0 | precision_sd_fail0 | precision_mean_valid | precision_sd_valid | recall_mean_fail0 | recall_sd_fail0 | recall_mean_valid | recall_sd_valid |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gunra | orig | exact | 5 | 5 | 0 | 82.5 | 6.95 | 82.5 | 6.95 | 43.89 | 3.62 | 43.89 | 3.62 |
| gunra | orig | parent | 5 | 5 | 0 | 97.89 | 2.88 | 97.89 | 2.88 | 53.12 | 3.12 | 53.12 | 3.12 |
| gunra | mut | exact | 5 | 5 | 0 | 81.62 | 7.0 | 81.62 | 7.0 | 40.56 | 6.09 | 40.56 | 6.09 |
| gunra | mut | parent | 5 | 5 | 0 | 97.89 | 2.9 | 97.89 | 2.9 | 50.62 | 6.77 | 50.62 | 6.77 |
| gunra | anon | exact | 5 | 5 | 0 | 84.52 | 8.81 | 84.52 | 8.81 | 40.56 | 2.48 | 40.56 | 2.48 |
| gunra | anon | parent | 5 | 5 | 0 | 97.64 | 3.24 | 97.64 | 3.24 | 48.75 | 3.56 | 48.75 | 3.56 |
| interlock | orig | exact | 5 | 5 | 0 | 89.83 | 5.69 | 89.83 | 5.69 | 54.4 | 2.19 | 54.4 | 2.19 |
| interlock | orig | parent | 5 | 5 | 0 | 89.83 | 5.69 | 89.83 | 5.69 | 59.13 | 2.38 | 59.13 | 2.38 |
| interlock | mut | exact | 5 | 5 | 0 | 92.21 | 5.53 | 92.21 | 5.53 | 56.0 | 4.9 | 56.0 | 4.9 |
| interlock | mut | parent | 5 | 5 | 0 | 92.21 | 5.53 | 92.21 | 5.53 | 60.87 | 5.32 | 60.87 | 5.32 |
| interlock | anon | exact | 5 | 5 | 0 | 90.73 | 7.32 | 90.73 | 7.32 | 57.6 | 4.56 | 57.6 | 4.56 |
| interlock | anon | parent | 5 | 5 | 0 | 90.73 | 7.32 | 90.73 | 7.32 | 62.61 | 4.96 | 62.61 | 4.96 |
| akira | orig | exact | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | orig | parent | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | mut | exact | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | mut | parent | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | anon | exact | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | anon | parent | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |

## Indicador 2 — Corrección del cruce de cobertura (paso 2, sobre la referencia)

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| scenario | reference_techniques | matches | accuracy | mismatches |
|---|---|---|---|---|
| gunra | 36 | 36 | 100.0 | ninguna |
| interlock | 25 | 25 | 100.0 | ninguna |
| akira | 38 | 38 | 100.0 | ninguna |

## Indicador 3 — Persistencia en el reconocimiento de la exposición (%). Denominador: técnicas de referencia con brecha (modelo) o todas las técnicas de referencia (tradicional); media principal del modelo: `_fail0`

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| scenario | approach | denominator_techniques | failed_runs | orig_mean_fail0 | orig_sd_fail0 | orig_mean_valid | orig_sd_valid | mut_mean_fail0 | mut_sd_fail0 | mut_mean_valid | mut_sd_valid | anon_mean_fail0 | anon_sd_fail0 | anon_mean_valid | anon_sd_valid | persistence_mut_over_orig_fail0 | persistence_mut_over_orig_valid | persistence_anon_over_orig_fail0 | persistence_anon_over_orig_valid | ioc_matches |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gunra | modelo | 28 | orig 0, mut 0, anon 0 | 34.29 | 4.79 | 34.29 | 4.79 | 30.71 | 7.82 | 30.71 | 7.82 | 32.14 | 2.53 | 32.14 | 2.53 | 0.8958 | 0.8958 | 0.9375 | 0.9375 |  |
| gunra | tradicional | 36 | no aplica (sin LLM) | 100.0 | determinístico | 100.0 | determinístico | 0.0 | determinístico | 0.0 | determinístico | 0.0 | determinístico | 0.0 | determinístico | 0.0 | 0.0 | 0.0 | 0.0 | orig 17, mut 0, anon 0 |
| interlock | modelo | 18 | orig 0, mut 0, anon 0 | 52.22 | 3.04 | 52.22 | 3.04 | 56.67 | 4.65 | 56.67 | 4.65 | 56.67 | 7.24 | 56.67 | 7.24 | 1.0851 | 1.0851 | 1.0851 | 1.0851 |  |
| interlock | tradicional | 25 | no aplica (sin LLM) | 100.0 | determinístico | 100.0 | determinístico | 0.0 | determinístico | 0.0 | determinístico | 0.0 | determinístico | 0.0 | determinístico | 0.0 | 0.0 | 0.0 | 0.0 | orig 19, mut 0, anon 0 |
| akira | modelo | 25 | orig 0, mut 0, anon 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |  |
| akira | tradicional | 38 | no aplica (sin LLM) | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |

## Indicador 4 — Fidelidad de los resúmenes (chequeo automático; la revisión manual está en la hoja)

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| techniques_summarized | llm_failures | auto_check_ok | auto_check_ok_pct | manual_review |
|---|---|---|---|---|
| 49 | 0 | 49 | 100.0 | pendiente (hoja de revisión) |

## Indicador 5 — Cumplimiento de los límites (violaciones; `_fail0` y `_valid` con el mismo peso. Aviso: contar una corrida fallida como 0 violaciones favorece al modelo)

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| scenario | version | output | runs_total | runs_valid | failed_runs | violations_total | violations_mean_fail0 | violations_sd_fail0 | violations_mean_valid | violations_sd_valid | extra_fields | evaluative_text |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gunra | orig | paso 1 (extracción) | 5 | 5 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 |
| gunra | mut | paso 1 (extracción) | 5 | 5 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 |
| gunra | anon | paso 1 (extracción) | 5 | 5 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 |
| interlock | orig | paso 1 (extracción) | 5 | 5 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 |
| interlock | mut | paso 1 (extracción) | 5 | 5 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 |
| interlock | anon | paso 1 (extracción) | 5 | 5 | 0 | 0 | 0.0 | 0.0 | 0.0 | 0.0 | 0 | 0 |
| akira | orig | paso 1 (extracción) | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | mut | paso 1 (extracción) | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| akira | anon | paso 1 (extracción) | 0 | 0 | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible |
| todos | - | paso 4 (resúmenes, uno por técnica) | 49 | 49 | ver indicador 4 (llm_failures) | 0 | sin dato disponible | sin dato disponible | sin dato disponible | sin dato disponible | 0 | 0 |

## Anexo — Indicador 1: técnicas omitidas y erróneas (en cuántas corridas)

_gemini-api · modelo `gemini-3.8-flash` (gemini-3.8-flash) · 2026-10-18 · prompts extract_v1.txt=950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3; summary_v1.txt=8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b_

| scenario | version | level | kind | technique_id | runs |
|---|---|---|---|---|---|
| gunra | orig | exact | omitida | T1003 | 5/5 |
| gunra | orig | exact | omitida | T1005 | 5/5 |
| gunra | orig | exact | omitida | T1040 | 4/5 |
| gunra | orig | exact | omitida | T1048 | 5/5 |
| gunra | orig | exact | omitida | T1049 | 5/5 |
| gunra | orig | exact | omitida | T1059.003 | 4/5 |
| gunra | orig | exact | omitida | T1078.002 | 5/5 |
| gunra | orig | exact | omitida | T1114 | 5/5 |
| gunra | orig | exact | omitida | T1133 | 5/5 |
| gunra | orig | exact | omitida | T1530 | 5/5 |
| gunra | orig | exact | omitida | T1539 | 5/5 |
| gunra | orig | exact | omitida | T1550.002 | 3/5 |
| gunra | orig | exact | omitida | T1550.003 | 4/5 |
| gunra | orig | exact | omitida | T1555 | 5/5 |
| gunra | orig | exact | omitida | T1556.006 | 3/5 |
| gunra | orig | exact | omitida | T1560 | 4/5 |
| gunra | orig | exact | omitida | T1567 | 5/5 |
| gunra | orig | exact | omitida | T1572 | 4/5 |
| gunra | orig | exact | omitida | T1657 | 5/5 |
| gunra | orig | exact | omitida | T1678 | 5/5 |
| gunra | orig | exact | omitida | T1679 | 5/5 |
| gunra | orig | exact | omitida | T1685 | 5/5 |
| gunra | orig | exact | errónea | T1021.004 | 1/5 |
| gunra | orig | exact | errónea | T1136.001 | 2/5 |
| gunra | orig | exact | errónea | T1550.004 | 4/5 |
| gunra | orig | exact | errónea | T1556 | 3/5 |
| gunra | orig | exact | errónea | T1560.001 | 2/5 |
| gunra | orig | exact | errónea | T1567.002 | 5/5 |
| gunra | orig | parent | omitida | T1005 | 5/5 |
| gunra | orig | parent | omitida | T1040 | 4/5 |
| gunra | orig | parent | omitida | T1048 | 5/5 |
| gunra | orig | parent | omitida | T1049 | 5/5 |
| gunra | orig | parent | omitida | T1059 | 4/5 |
| gunra | orig | parent | omitida | T1114 | 5/5 |
| gunra | orig | parent | omitida | T1133 | 5/5 |
| gunra | orig | parent | omitida | T1530 | 5/5 |
| gunra | orig | parent | omitida | T1539 | 5/5 |
| gunra | orig | parent | omitida | T1550 | 1/5 |
| gunra | orig | parent | omitida | T1555 | 5/5 |
| gunra | orig | parent | omitida | T1560 | 2/5 |
| gunra | orig | parent | omitida | T1572 | 4/5 |
| gunra | orig | parent | omitida | T1657 | 5/5 |
| gunra | orig | parent | omitida | T1678 | 5/5 |
| gunra | orig | parent | omitida | T1679 | 5/5 |
| gunra | orig | parent | omitida | T1685 | 5/5 |
| gunra | orig | parent | errónea | T1136 | 2/5 |
| gunra | mut | exact | omitida | T1003 | 5/5 |
| gunra | mut | exact | omitida | T1005 | 5/5 |
| gunra | mut | exact | omitida | T1040 | 5/5 |
| gunra | mut | exact | omitida | T1048 | 5/5 |
| gunra | mut | exact | omitida | T1049 | 5/5 |
| gunra | mut | exact | omitida | T1059.003 | 5/5 |
| gunra | mut | exact | omitida | T1078.001 | 1/5 |
| gunra | mut | exact | omitida | T1078.002 | 5/5 |
| gunra | mut | exact | omitida | T1098 | 2/5 |
| gunra | mut | exact | omitida | T1114 | 5/5 |
| gunra | mut | exact | omitida | T1133 | 5/5 |
| gunra | mut | exact | omitida | T1530 | 4/5 |
| gunra | mut | exact | omitida | T1539 | 5/5 |
| gunra | mut | exact | omitida | T1550.002 | 4/5 |
| gunra | mut | exact | omitida | T1550.003 | 5/5 |
| gunra | mut | exact | omitida | T1555 | 5/5 |
| gunra | mut | exact | omitida | T1556.006 | 2/5 |
| gunra | mut | exact | omitida | T1560 | 5/5 |
| gunra | mut | exact | omitida | T1567 | 5/5 |
| gunra | mut | exact | omitida | T1572 | 4/5 |
| gunra | mut | exact | omitida | T1657 | 5/5 |
| gunra | mut | exact | omitida | T1678 | 5/5 |
| gunra | mut | exact | omitida | T1679 | 5/5 |
| gunra | mut | exact | omitida | T1685 | 5/5 |
| gunra | mut | exact | errónea | T1021.004 | 1/5 |
| gunra | mut | exact | errónea | T1136.001 | 2/5 |
| gunra | mut | exact | errónea | T1550.004 | 3/5 |
| gunra | mut | exact | errónea | T1556 | 2/5 |
| gunra | mut | exact | errónea | T1560.001 | 4/5 |
| gunra | mut | exact | errónea | T1567.002 | 5/5 |
| gunra | mut | parent | omitida | T1005 | 5/5 |
| gunra | mut | parent | omitida | T1040 | 5/5 |
| gunra | mut | parent | omitida | T1048 | 5/5 |
| gunra | mut | parent | omitida | T1049 | 5/5 |
| gunra | mut | parent | omitida | T1059 | 5/5 |
| gunra | mut | parent | omitida | T1078 | 1/5 |
| gunra | mut | parent | omitida | T1098 | 2/5 |
| gunra | mut | parent | omitida | T1114 | 5/5 |
| gunra | mut | parent | omitida | T1133 | 5/5 |
| gunra | mut | parent | omitida | T1530 | 4/5 |
| gunra | mut | parent | omitida | T1539 | 5/5 |
| gunra | mut | parent | omitida | T1550 | 2/5 |
| gunra | mut | parent | omitida | T1555 | 5/5 |
| gunra | mut | parent | omitida | T1560 | 1/5 |
| gunra | mut | parent | omitida | T1572 | 4/5 |
| gunra | mut | parent | omitida | T1657 | 5/5 |
| gunra | mut | parent | omitida | T1678 | 5/5 |
| gunra | mut | parent | omitida | T1679 | 5/5 |
| gunra | mut | parent | omitida | T1685 | 5/5 |
| gunra | mut | parent | errónea | T1136 | 2/5 |
| gunra | anon | exact | omitida | T1003 | 5/5 |
| gunra | anon | exact | omitida | T1005 | 5/5 |
| gunra | anon | exact | omitida | T1040 | 5/5 |
| gunra | anon | exact | omitida | T1048 | 5/5 |
| gunra | anon | exact | omitida | T1049 | 5/5 |
| gunra | anon | exact | omitida | T1059.003 | 5/5 |
| gunra | anon | exact | omitida | T1078.001 | 1/5 |
| gunra | anon | exact | omitida | T1078.002 | 5/5 |
| gunra | anon | exact | omitida | T1098 | 2/5 |
| gunra | anon | exact | omitida | T1105 | 2/5 |
| gunra | anon | exact | omitida | T1114 | 5/5 |
| gunra | anon | exact | omitida | T1133 | 5/5 |
| gunra | anon | exact | omitida | T1530 | 5/5 |
| gunra | anon | exact | omitida | T1539 | 2/5 |
| gunra | anon | exact | omitida | T1550.002 | 4/5 |
| gunra | anon | exact | omitida | T1550.003 | 5/5 |
| gunra | anon | exact | omitida | T1555 | 5/5 |
| gunra | anon | exact | omitida | T1556.006 | 3/5 |
| gunra | anon | exact | omitida | T1560 | 3/5 |
| gunra | anon | exact | omitida | T1567 | 5/5 |
| gunra | anon | exact | omitida | T1572 | 5/5 |
| gunra | anon | exact | omitida | T1657 | 5/5 |
| gunra | anon | exact | omitida | T1678 | 5/5 |
| gunra | anon | exact | omitida | T1679 | 5/5 |
| gunra | anon | exact | omitida | T1685 | 5/5 |
| gunra | anon | exact | errónea | T1021.004 | 1/5 |
| gunra | anon | exact | errónea | T1136 | 1/5 |
| gunra | anon | exact | errónea | T1136.001 | 1/5 |
| gunra | anon | exact | errónea | T1550.004 | 1/5 |
| gunra | anon | exact | errónea | T1556 | 3/5 |
| gunra | anon | exact | errónea | T1560.001 | 2/5 |
| gunra | anon | exact | errónea | T1567.002 | 5/5 |
| gunra | anon | parent | omitida | T1005 | 5/5 |
| gunra | anon | parent | omitida | T1040 | 5/5 |
| gunra | anon | parent | omitida | T1048 | 5/5 |
| gunra | anon | parent | omitida | T1049 | 5/5 |
| gunra | anon | parent | omitida | T1059 | 5/5 |
| gunra | anon | parent | omitida | T1078 | 1/5 |
| gunra | anon | parent | omitida | T1098 | 2/5 |
| gunra | anon | parent | omitida | T1105 | 2/5 |
| gunra | anon | parent | omitida | T1114 | 5/5 |
| gunra | anon | parent | omitida | T1133 | 5/5 |
| gunra | anon | parent | omitida | T1530 | 5/5 |
| gunra | anon | parent | omitida | T1539 | 2/5 |
| gunra | anon | parent | omitida | T1550 | 4/5 |
| gunra | anon | parent | omitida | T1555 | 5/5 |
| gunra | anon | parent | omitida | T1560 | 1/5 |
| gunra | anon | parent | omitida | T1572 | 5/5 |
| gunra | anon | parent | omitida | T1657 | 5/5 |
| gunra | anon | parent | omitida | T1678 | 5/5 |
| gunra | anon | parent | omitida | T1679 | 5/5 |
| gunra | anon | parent | omitida | T1685 | 5/5 |
| gunra | anon | parent | errónea | T1136 | 2/5 |
| interlock | orig | exact | omitida | T1016 | 5/5 |
| interlock | orig | exact | omitida | T1036.005 | 5/5 |
| interlock | orig | exact | omitida | T1048 | 5/5 |
| interlock | orig | exact | omitida | T1056 | 5/5 |
| interlock | orig | exact | omitida | T1078 | 5/5 |
| interlock | orig | exact | omitida | T1078.002 | 5/5 |
| interlock | orig | exact | omitida | T1105 | 4/5 |
| interlock | orig | exact | omitida | T1204.004 | 4/5 |
| interlock | orig | exact | omitida | T1530 | 5/5 |
| interlock | orig | exact | omitida | T1555.003 | 4/5 |
| interlock | orig | exact | omitida | T1558.003 | 5/5 |
| interlock | orig | exact | omitida | T1657 | 5/5 |
| interlock | orig | exact | errónea | T1057 | 4/5 |
| interlock | orig | exact | errónea | T1484.001 | 4/5 |
| interlock | orig | parent | omitida | T1016 | 5/5 |
| interlock | orig | parent | omitida | T1036 | 5/5 |
| interlock | orig | parent | omitida | T1048 | 5/5 |
| interlock | orig | parent | omitida | T1078 | 5/5 |
| interlock | orig | parent | omitida | T1105 | 4/5 |
| interlock | orig | parent | omitida | T1204 | 4/5 |
| interlock | orig | parent | omitida | T1530 | 5/5 |
| interlock | orig | parent | omitida | T1555 | 4/5 |
| interlock | orig | parent | omitida | T1558 | 5/5 |
| interlock | orig | parent | omitida | T1657 | 5/5 |
| interlock | orig | parent | errónea | T1057 | 4/5 |
| interlock | orig | parent | errónea | T1484 | 4/5 |
| interlock | mut | exact | omitida | T1016 | 3/5 |
| interlock | mut | exact | omitida | T1036.005 | 5/5 |
| interlock | mut | exact | omitida | T1048 | 5/5 |
| interlock | mut | exact | omitida | T1056 | 5/5 |
| interlock | mut | exact | omitida | T1078 | 5/5 |
| interlock | mut | exact | omitida | T1078.002 | 5/5 |
| interlock | mut | exact | omitida | T1105 | 5/5 |
| interlock | mut | exact | omitida | T1204.004 | 4/5 |
| interlock | mut | exact | omitida | T1219 | 1/5 |
| interlock | mut | exact | omitida | T1530 | 5/5 |
| interlock | mut | exact | omitida | T1555.003 | 2/5 |
| interlock | mut | exact | omitida | T1558.003 | 5/5 |
| interlock | mut | exact | omitida | T1657 | 5/5 |
| interlock | mut | exact | errónea | T1057 | 4/5 |
| interlock | mut | exact | errónea | T1484.001 | 2/5 |
| interlock | mut | parent | omitida | T1016 | 3/5 |
| interlock | mut | parent | omitida | T1036 | 5/5 |
| interlock | mut | parent | omitida | T1048 | 5/5 |
| interlock | mut | parent | omitida | T1078 | 5/5 |
| interlock | mut | parent | omitida | T1105 | 5/5 |
| interlock | mut | parent | omitida | T1204 | 4/5 |
| interlock | mut | parent | omitida | T1219 | 1/5 |
| interlock | mut | parent | omitida | T1530 | 5/5 |
| interlock | mut | parent | omitida | T1555 | 2/5 |
| interlock | mut | parent | omitida | T1558 | 5/5 |
| interlock | mut | parent | omitida | T1657 | 5/5 |
| interlock | mut | parent | errónea | T1057 | 4/5 |
| interlock | mut | parent | errónea | T1484 | 2/5 |
| interlock | anon | exact | omitida | T1016 | 4/5 |
| interlock | anon | exact | omitida | T1036.005 | 4/5 |
| interlock | anon | exact | omitida | T1048 | 5/5 |
| interlock | anon | exact | omitida | T1056 | 5/5 |
| interlock | anon | exact | omitida | T1078 | 5/5 |
| interlock | anon | exact | omitida | T1078.002 | 5/5 |
| interlock | anon | exact | omitida | T1105 | 4/5 |
| interlock | anon | exact | omitida | T1204.004 | 4/5 |
| interlock | anon | exact | omitida | T1530 | 5/5 |
| interlock | anon | exact | omitida | T1555.003 | 3/5 |
| interlock | anon | exact | omitida | T1558.003 | 5/5 |
| interlock | anon | exact | omitida | T1657 | 4/5 |
| interlock | anon | exact | errónea | T1057 | 2/5 |
| interlock | anon | exact | errónea | T1090.003 | 1/5 |
| interlock | anon | exact | errónea | T1135 | 1/5 |
| interlock | anon | exact | errónea | T1484.001 | 4/5 |
| interlock | anon | parent | omitida | T1016 | 4/5 |
| interlock | anon | parent | omitida | T1036 | 4/5 |
| interlock | anon | parent | omitida | T1048 | 5/5 |
| interlock | anon | parent | omitida | T1078 | 5/5 |
| interlock | anon | parent | omitida | T1105 | 4/5 |
| interlock | anon | parent | omitida | T1204 | 4/5 |
| interlock | anon | parent | omitida | T1530 | 5/5 |
| interlock | anon | parent | omitida | T1555 | 3/5 |
| interlock | anon | parent | omitida | T1558 | 5/5 |
| interlock | anon | parent | omitida | T1657 | 4/5 |
| interlock | anon | parent | errónea | T1057 | 2/5 |
| interlock | anon | parent | errónea | T1090 | 1/5 |
| interlock | anon | parent | errónea | T1135 | 1/5 |
| interlock | anon | parent | errónea | T1484 | 4/5 |

Hojas de revisión manual: `2026-10-18-main_indicator4_summaries.csv`, `2026-10-18-main_indicator5_sample.csv` (carpeta `eval/review_sheets/`).
