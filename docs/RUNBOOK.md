# RUNBOOK — de la API key a los resultados de la tesis

Pasos en orden para correr los experimentos reales. Cada bloque indica los comandos exactos; donde Windows difiere, se muestra aparte. En Windows, `aem` acepta rutas con `/`, así que los comandos de `aem` son iguales en los tres sistemas.

**Antes de cada sesión** (en cada terminal nueva), desde la carpeta del repositorio:

| Sistema | Activar el entorno |
|---|---|
| Linux / macOS | `source .venv/bin/activate` |
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` (si PowerShell lo bloquea, una sola vez: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`) |

Comprobación rápida: `pytest -q` debe terminar en verde. Ninguna prueba llama a la API real.

---

## a. API key de Google AI Studio → `.env`

1. Entre a https://aistudio.google.com con su cuenta de Google y abra **Get API key** → **Create API key**. Copie la clave (empieza por `AIza`).
2. Cree el archivo `.env` a partir de la plantilla:

   | Sistema | Comando |
   |---|---|
   | Linux / macOS | `cp .env.example .env` |
   | Windows (PowerShell) | `Copy-Item .env.example .env` |

3. Abra `.env` con un editor de texto y complete `GEMINI_API_KEY=<su clave>` (sin comillas ni espacios). Deje `GEMINI_MODEL`, `GEMINI_RPM` y `GEMINI_MAX_RETRIES` como están, salvo que el modelo no exista (ver el paso b).
4. Verifique que git **no** verá el archivo:

   ```bash
   git check-ignore -v .env      # debe imprimir: .gitignore:2:.env   .env
   git status --short            # .env NO debe aparecer
   ```

La clave nunca se escribe en la caché, en las salidas ni en los registros.

## b. Corrida de prueba real con Gunra (`aem run`) y revisión del CSV

```bash
aem run --report data/reports/gunra_aa26-222a_stripped.txt --analyst-mode auto --out runs/prueba/gunra
```

- Tarda unos minutos (1 llamada de extracción + 1 resumen por técnica, con una pausa de 6 s entre llamadas a `GEMINI_RPM=10`).
- Si dice que el modelo no está disponible, cambie en `.env` a `GEMINI_MODEL=gemini-3.5-flash-lite` (el alternativo que propone el mensaje) y repita. Use el mismo modelo en todo el experimento.
- La respuesta queda en la caché `runs/llm_cache/` y es la misma que usará `aem eval` en la corrida 0 de Gunra `orig`, así que la prueba no gasta llamadas de más.
- Para probar el modo con analista en la terminal, use `--analyst-mode interactive` y otra carpeta en `--out`; el experimento usa siempre `auto`.

Revise la salida en `runs/prueba/gunra/`:

1. **Los nombres de archivo no deben empezar por `FAKE_`.** Si empiezan así, la consola también dijo «FAKE». Alguna respuesta no vino de la API real; no siga hasta resolverlo.
2. Abra `gunra_aa26-222a_stripped_exposure.csv` con LibreOffice Calc o Excel. Está en UTF-8 con BOM, así que los acentos se ven bien. Columnas: `technique_id, technique_name, tactics, coverage_validated, criticality, exposure, action, summary, source_link, mitigations, data_sources, groups, prevalence`. Compruebe que:
   - las filas vengan agrupadas por `action` (Act, Attend, Track*, Track);
   - `summary` sean como máximo 3 oraciones en inglés, sin urgencia ni recomendaciones (si el filtro descartó uno, dice `resumen no disponible`);
   - `prevalence` diga `sin dato disponible` mientras no llene el CSV del paso d.
3. En `run_record.json`, `meta.llm_sources` debe ser `["gemini-api"]` y `meta.model_versions` muestra la versión exacta del modelo.

La carpeta `runs/prueba/` se puede borrar o versionar; lo que importa conservar es la caché.

## c. Texto de Akira, `aem prepare-reports` y `aem make-variants`

1. Coloque el texto siguiendo `docs/report_preparation.md` §5: texto plano UTF-8 en `data/reports/akira_dfir_2026.txt`, con el encabezado `MITRE ATT&CK` en una línea propia.
2. Prepare el texto (quita la sección del mapeo y todos los IDs):

   ```bash
   aem prepare-reports
   ```

   Debe decir que los IDs de la sección **coinciden** con `data/reference_mappings/akira.csv`. Si dice «NO coincide», no siga: revise el texto pegado.
3. Genere las variantes `mut` de los tres escenarios y los IoC conocidos:

   ```bash
   aem make-variants
   ```

   Por escenario muestra cuántos IoC se reemplazaron y cierra con «verificación: ningún IoC del original queda en mut». Si queda alguno, el comando falla e indica el valor y la línea. En ese caso, avíseme con ese mensaje (no edite la variante a mano).
   También lista los «tokens sin defang con forma de IoC» que dejó intactos (en Gunra e Interlock, los enlaces de referencia de las notas). Para Akira, abra `data/reports/akira_dfir_2026_mut.diff` y revise que esa lista no contenga un IoC real del actor escrito sin defang. Si lo contiene, avíseme.
4. Ejecute `pytest -q`. Ahora también corren sobre Akira la prueba de que el texto `stripped` no tiene IDs y la de que `mut` no conserva IoC.
5. Compruebe que nada de Akira quedó a la vista de git:

   ```bash
   git status --short            # no debe aparecer ningún data/reports/akira_dfir_2026*
   ```

   `aem make-variants` reescribe `data/org/known_iocs_generated.yaml`, que **sí** se versiona: solo contiene IoC (hashes, IP, dominios), no texto del reporte.

## d. CSV de prevalencia (Red Canary 2026)

Archivo: `data/prevalence/red_canary_2026.csv`. Ya tiene la fila de encabezado; agregue una fila por técnica que figure en el *2026 Threat Detection Report* de Red Canary.

| Columna | Contenido | Reglas |
|---|---|---|
| `technique_id` | ID de ATT&CK tal como aparece en el informe | `T####` o `T####.###`; un ID mal formado detiene el programa con un error |
| `rank` | puesto en la clasificación del informe | entero sin decimales |
| `source_note` | referencia opcional | p. ej. página o tabla; puede ir vacía |

Formato de ejemplo. **EJEMPLO, valores inventados: no copie estas filas.**

```csv
technique_id,rank,source_note
T0000,999,EJEMPLO - valor inventado
T0000.000,998,EJEMPLO - valor inventado
```

- Solo técnicas que el informe lista. No complete huecos con la técnica padre: si una técnica no figura, la salida dirá `sin dato disponible`.
- Si edita en Excel, guarde como **CSV UTF-8 (delimitado por comas)**. LibreOffice: juego de caracteres UTF-8, separador coma.
- Verifique que se lee bien:

  ```bash
  python -c "from aem.step4_reference import load_prevalence as l; d=l('data/prevalence/red_canary_2026.csv'); print(len(d), 'técnicas'); print(list(d.items())[:3])"
  ```

La prevalencia no cambia ninguna llamada al LLM ni ningún indicador; solo aparece en el CSV de `aem run`.

## e. `aem eval` completo

Use siempre un `--run-id` explícito. El nombre por defecto es la fecha de hoy, y si reanuda otro día crearía una carpeta distinta.

| Sistema | Comando (evita que el equipo se suspenda) |
|---|---|
| Linux | `systemd-inhibit aem eval --run-id 2026-10-20` |
| macOS | `caffeinate -i aem eval --run-id 2026-10-20` |
| Windows | `aem eval --run-id 2026-10-20` (antes, en Configuración → Energía, ponga «Suspender: nunca» mientras corre) |

(Cambie `2026-10-20` por la fecha en que lo inicie.)

- **Duración estimada** (`docs/PLAN.md`): ≈ 110–150 llamadas, **20–35 minutos** con `GEMINI_RPM=10`; hasta ≈ 190 llamadas si Akira se divide en muchos fragmentos. Los reintentos por HTTP 429 la alargan.
- La consola muestra `escenario · versión · corrida k/5`. Al final indica cuántas corridas no tuvieron salida utilizable y dónde quedó `results.md`.
- **Si se corta por un límite de la API** (cuota diaria, 429 persistente, sin conexión), el comando termina con un error claro. Todas las respuestas ya obtenidas quedan en la caché. Para reanudar, repita **exactamente el mismo comando** (mismo `--run-id`, mismo `GEMINI_MODEL`); si fue la cuota diaria, espere a que se renueve. Solo se piden las llamadas que faltan. Repítalo hasta que termine sin error.
- Resultado: `runs/2026-10-20/results/` (`results.md`, un CSV por tabla y `results.json`). **Si en lugar de eso aparece `results_FAKE/`**, alguna respuesta no vino de la API real: esas tablas no sirven para la tesis.
- Revise primero la tabla «Corridas por escenario y versión» de `results.md`: `runs_total`, `runs_valid`, `failed_runs` y el motivo de cada falla. Cada indicador trae dos medias: `_valid` (solo corridas válidas) y `_fail0` (las fallidas cuentan como 0).
- Cada fila de cada tabla lleva `llm_source`, `model`, `model_version`, `run_date` y `prompt_templates_sha256`, que son los datos para citar la corrida.
- Comprobación de reproducibilidad (sin API key ni llamadas, segundos):

  ```bash
  aem eval --demo --run-id 2026-10-20-demo
  ```

  Las tablas deben coincidir con las de la corrida real, salvo `run_date` si la repite otro día.

## f. Hojas de revisión manual

Están en `eval/review_sheets/`; la parte de Akira, en `eval/review_sheets/private/`. Ábralas con LibreOffice o Excel, llene **solo** las columnas vacías, no cambie los nombres de columna y guarde como CSV UTF-8.

**Indicador 4: `<run-id>_indicator4_summaries.csv`.** Una fila por técnica resumida.
- Compare `summary` con `source_description` (la descripción de ATT&CK de la que salió).
- `ok (si/no)`: `si` si el resumen es fiel. Eso significa que no agrega nada que no esté en la descripción, no omite lo esencial y no valora urgencia ni recomienda acciones.
- `observación`: el motivo, sobre todo cuando pone `no`.
- `auto_check` es el chequeo automático (D-68). Es solo una ayuda: la medida es su revisión.

**Indicador 5: `<run-id>_indicator5_sample.csv`** y **`private/<run-id>_indicator5_sample_private.csv`** (Akira). Una muestra fija de 30 textos producidos por la IA (citas del paso 1 y resúmenes del paso 4).
- `contiene_valoracion (si/no)`: `si` si el texto valora, prioriza o recomienda (p. ej. «critical», «should patch», «urgent») más allá de lo que dice la fuente.
- `observación`: el fragmento que lo justifica.

Conteo rápido, cuando estén llenas:

```bash
python -c "import csv,sys; r=list(csv.DictReader(open(sys.argv[1],encoding='utf-8-sig'))); c=sys.argv[2]; print(sum(x[c].strip().lower()=='si' for x in r),'de',len(r))" eval/review_sheets/2026-10-20_indicator4_summaries.csv "ok (si/no)"
```

(Para el indicador 5, cambie el archivo y la columna por `contiene_valoracion (si/no)`.)

## g. Qué se versiona y qué no

| Se versiona (sí) | No se versiona (nunca) |
|---|---|
| `runs/llm_cache/` (caché pública, necesaria para `--demo`) | `.env` (su API key) |
| `runs/<run-id>/results/` y las salidas de Gunra e Interlock en `runs/<run-id>/` | `runs/llm_cache_private/` (prompts con el texto de Akira) |
| `eval/review_sheets/*.csv` llenas | `runs/*/private/` (salidas de Akira con citas) |
| `data/prevalence/red_canary_2026.csv`, `data/org/known_iocs_generated.yaml`, `data/reports/*_mut*` de CISA | `eval/review_sheets/private/` (muestra de Akira) |
| | `data/reports/akira_dfir_2026*` (texto, `stripped`, variante y diff) |

Todo lo de la columna derecha ya está en `.gitignore`. Antes de cada commit, verifique:

```bash
git status --short                                   # revise la lista completa
git check-ignore -v runs/llm_cache_private/ runs/2026-10-20/private/ eval/review_sheets/private/ data/reports/akira_dfir_2026.txt
git add -A
git diff --cached --name-only | grep -i -E "akira_dfir|private|\.env$"   # no debe imprimir nada
git grep -n "AIza" -- . ':!docs/RUNBOOK.md'          # no debe imprimir nada (claves de Google)
git commit -m "eval: corrida real 2026-10-20"
```

En Windows (PowerShell), cambie `grep -i -E "…"` por `Select-String -Pattern "akira_dfir|private|\.env$"`. Si `git check-ignore` no imprime una de las rutas, esa ruta **no** está ignorada: no haga commit y avíseme. Puede ser normal si la carpeta todavía no existe.

## h. URL del repositorio y declaración de uso de IA en el README

1. Cree el repositorio en GitHub, vacío y sin README. Con `gh`: `gh repo create Mumogg/attack-exposure-model --public` (o `--private`). También puede hacerlo desde github.com.
2. En `README.md`, reemplace las marcas `[PENDIENTE: confirmar URL]`:
   - las dos líneas `git clone …` de la instalación;
   - `url` y `note` de la entrada BibTeX de «Cómo citar».
3. Complete la sección «Declaración de uso de IA en el desarrollo» con el texto que exija la universidad. Un **borrador** que puede adaptar:

   > Este repositorio se desarrolló con asistencia de Claude Code (Anthropic), que escribió código, pruebas y documentación siguiendo las especificaciones y decisiones del autor, quien revisó y aprobó cada cambio. El modelo evaluado usa Gemini (Google) como componente en los pasos 1 y 4, tal como se describe arriba. Los resultados reportados provienen de la ejecución con la API real de Gemini; ningún resultado fue generado ni editado por el asistente de desarrollo.

4. Enlace el remoto y suba, cuando lo decida:

   ```bash
   git remote add origin https://github.com/Mumogg/attack-exposure-model.git
   git push -u origin main
   ```

## i. Actualizar `docs/RESUMEN_PARA_TESIS.md` con los resultados reales

1. Tome las cifras de `runs/<run-id>/results/results.md`, no de la consola.
2. En el resumen, agregue o actualice:
   - **Datos de la corrida:** `run-id`, fecha, `model` y `model_version`, y los hashes de `prompt_templates_sha256`.
   - **Corridas:** por escenario y versión, las totales, válidas y fallidas, con el motivo de cada falla.
   - **Indicadores 1, 3 y 5:** media ± desviación estándar en las dos vistas, `_valid` y `_fail0`, junto con `failed_runs`. Decida cuál es la principal (D-67).
   - **Indicador 2:** exactitud y discrepancias.
   - **Indicadores 4 y 5:** resultados de su revisión manual (conteos del paso f).
3. Revise la tabla de decisiones `PENDIENTE DE CONFIRMAR` del resumen (D-03, D-62, D-63, D-65, D-66, D-67, D-68, D-70). Confirme o cambie cada una en `docs/DECISIONS.md`.
4. Si lo prefiere, pídale a Claude: «actualiza RESUMEN_PARA_TESIS.md con runs/<run-id>/results/results.md y las hojas revisadas».
5. Haga commit (ver paso g).
