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

## Bitácora (una línea por bloque)
- Bloque 2 ✔ models/config/attack_data/fetch + tests (39). Pendiente: comando CLI `fetch-data` se conecta en el bloque 7.
