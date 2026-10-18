# Plan de implementación — attack-exposure-model

**Objetivo:** prototipo de CLI que, dado un reporte de amenaza y el perfil de una organización ficticia, produce un CSV de exposición por técnica ATT&CK v19.2, más el arnés de evaluación de los cinco indicadores de la tesis.

**Arquitectura:** canalización de 4 pasos (`step1`…`step4`) con datos validados por `pydantic` entre pasos. La IA (Gemini) solo aparece detrás de una interfaz `LLMClient` en el paso 1 (extracción) y en el resumen del paso 4; todo lo demás es código determinístico. Las respuestas del LLM se guardan en una caché en disco que habilita el modo `--demo` sin API key.

**Stack:** Python ≥ 3.11 · pydantic · PyYAML · python-dotenv · typer · rich · mitreattack-python 6.3 · google-genai 2.x · pytest.

**Especificación:** `CLAUDE.md` (raíz del repositorio).

## Restricciones globales
- La IA nunca asigna prioridad, urgencia ni acciones; ningún esquema de salida del LLM tiene campos evaluativos.
- ATT&CK Enterprise **v19.2** (`enterprise-attack-19.2.json`); orden de tácticas leído de la matriz.
- `temperature = 0`; salida JSON con esquema; registro de modelo, fecha/hora, temperatura y SHA-256 del prompt.
- Los tests nunca llaman a la API real.
- Identificadores/comentarios/commits en inglés; CLI y documentación en español.
- Nada de texto de The DFIR Report en git; la API key solo en `.env`.
- `pathlib` en todo; sin comandos de shell en el código.

## Estructura
La de `CLAUDE.md` §4, con estos agregados:
- `src/aem/reports.py`: conversión HTML→texto de CISA, eliminación del mapeo ATT&CK y extracción del mapeo de referencia.
- `src/aem/boundaries.py`: patrones de lenguaje evaluativo (usado por el paso 4 y el indicador 5).
- `src/aem/pipeline.py`: orquesta los 4 pasos (lo usan `aem run` y `aem eval`).
- `src/aem/prompts/`: plantillas de prompt versionadas (su hash queda registrado).
- `data/model_config.yaml`: umbrales y políticas configurables.
- `data/scenarios.yaml`: catálogo de escenarios (URL, archivos, tipo de fuente).
- `data/boundary_patterns.yaml`: patrones del indicador 5.

## Orden (bloques de `CLAUDE.md` §10)
1. Esqueleto + `PLAN.md` + `DECISIONS.md`.
2. `models.py`, `config.py`, `attack_data.py`, `aem fetch-data` (ATT&CK) + tests.
3. `step2_coverage.py` + borrador `fictional_org.yaml` + tests.
4. `step3_prioritize.py` + `ssvc_tree.yaml` + tests.
5. `step4_reference.py` + plantilla de prevalencia + tests.
6. `llm.py` + `step1_extract.py` + tests con mocks.
7. `output.py` + `pipeline.py` + `aem run` / `aem demo`.
8. Escenarios: CISA (descarga, strip, referencia), DFIR (solo IDs), `make_variants.py`, `baseline_ioc.py`.
9. `metrics.py`, `run_experiments.py`, `aem eval`, hojas de revisión.
10. README y revisión final.

## Foco de revisión (riesgos no cubiertos por la especificación)
1. El LLM devuelve un JSON fuera de esquema o vacío → el paso 1 debe fallar con un mensaje claro y guardar la respuesta cruda, no seguir con una lista vacía en silencio.
2. Los boletines de CISA llevan los IDs **en línea** (`[T1190]`) además de la tabla → el texto `stripped` también debe quitarlos o la extracción copiaría la respuesta (test).
3. Repetir 5 corridas con `temperature=0` y caché por prompt devolvería 5 veces la misma respuesta → la clave de caché incluye el número de réplica (test).
4. Nombres de archivo (`main.exe`, `psexec.py`) que parecen dominios → el extractor de IoC no debe tratarlos como dominios al generar la variante `mut` (test).
5. Técnicas extraídas que no figuran en `analyst_context` → en modo `auto` se usa un activo por defecto declarado en el YAML, nunca un valor inventado (test).

## Estimación de llamadas a la API para `aem eval` (bloque 9, 2026-10-17)

**Paso 1 (extracción).** 3 escenarios × 2 versiones (`orig`, `mut`) × 5 corridas = **30 combinaciones**. Cada combinación hace una llamada por fragmento del reporte (D-11: el texto se envía completo si tiene ≤ 100 000 caracteres).
- Gunra `stripped`: 33 194 caracteres → 1 fragmento. Interlock: 29 608 → 1 fragmento.
- Akira: el tamaño se conoce cuando Sebas coloque el texto. Si queda ≤ 100 000 caracteres, 1 fragmento; si no, ≈ ⌈largo / 28 000⌉ fragmentos (30 000 con 2 000 de solapamiento).
- Total paso 1: **30 llamadas** si los tres caben en un fragmento; en el peor caso razonable (Akira de ~120 000 caracteres → 5 fragmentos) 20 + 10 × 5 = **70 llamadas**.

**Paso 4 (resúmenes).** Caché por técnica (D-44): un resumen por técnica distinta validada en cualquier corrida, sin importar escenario, versión ni réplica. Cota inferior: las **78 técnicas** distintas de los tres mapeos de referencia, si el LLM las encuentra todas; a eso se suman las técnicas propuestas fuera de la referencia (falsos positivos válidos). Estimación: **80–120 llamadas**. Las técnicas que solo aparecen como `needs_review` no se resumen (el modo `auto` las excluye).

**Verificación del modelo.** 1 llamada `models.get` por proceso (no genera contenido).

**Total estimado:** ≈ **110–150 llamadas** (hasta ≈ 190 en el peor caso de fragmentación de Akira).

**Tiempo a `GEMINI_RPM` = 10** (pausa mínima de 6 s entre llamadas, `src/aem/llm.py`):
- Solo por el límite: 110–150 × 6 s ≈ **11–15 min** (≈ 19 min en el peor caso).
- Latencia: una extracción con ~8 000–9 000 tokens de entrada puede tardar 10–40 s; 30 extracciones añaden ≈ 5–20 min. Los resúmenes son cortos (1–3 s cada uno, por debajo de la pausa de 6 s).
- **Estimación realista: 20–35 minutos** para la primera corrida completa. Reintentos por HTTP 429 (espera 2, 4, 8, 16, 32 s) pueden alargarla.
- Los límites diarios de la capa gratuita no son cifras oficiales; si se alcanza uno, `aem eval` se detiene con un error claro y, al volver a ejecutarlo, **reutiliza la caché**: solo repite las llamadas que faltan.
- Con la caché completa, `aem eval --demo` reproduce todo sin API key y sin llamadas (segundos).

## Bitácora (una línea por bloque)
- Bloque 2 ✔ models/config/attack_data/fetch + tests (39). Pendiente: comando CLI `fetch-data` se conecta en el bloque 7.
- Bloque 3 ✔ step2_coverage + borrador fictional_org.yaml (79 técnicas, coverage_design) + tests (60). Pendiente: Sebas define las brechas definitivas.
- Bloque 4 ✔ step3_prioritize + ssvc_tree.yaml (tabla completa, ajuste por exposición solo en Acceso Inicial, analista auto/interactivo, revisión global) + tests (109).
- Bloque 5 ✔ step4_reference (lote, 5 campos, filtro evaluativo), boundary_patterns.yaml, plantilla de prevalencia vacía + tests (131). Pendiente: Sebas llena red_canary_2026.csv.
- Bloque 6 ✔ llm.py (caché, demo, reintentos, verificación de modelo) + step1_extract + LLMSummarizer + tests (156).
- Bloque 7 ✔ output.py (CSV fijo, BOM, orden acción→matriz), pipeline.py, cli.py (fetch-data, run, demo) + decisiones confirmadas por Sebas (D-10, D-22, D-45, D-60, D-61; D-03 sigue pendiente) + tests (175).
- Bloque 8 ✔ reports.py/scenarios.py (HTML→texto, strip D-10, mapeos de referencia Gunra 36 / Interlock 25 / Akira 38, todos válidos en v19.2), aem fetch-data/prepare-reports/make-variants, eval/make_variants.py (RFC 5737, .invalid, semilla), eval/baseline_ioc.py (D-62/D-63) + tests (212). Pendiente: Sebas coloca el texto de Akira.
- Bloque 9 ✔ estimación de llamadas (arriba), eval/metrics.py (5 indicadores), eval/run_experiments.py, aem eval (CSV + Markdown + JSON, hojas de revisión en eval/review_sheets/), ApiError vs InvalidResponse en llm.py + tests (229). Pendiente: Sebas corre `aem eval` con la API key real. SIGUIENTE: bloque 10 (README, revisión de secretos, RESUMEN_PARA_TESIS.md).
