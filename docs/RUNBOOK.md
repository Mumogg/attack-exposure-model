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

1. Entre a https://aistudio.google.com con su cuenta de Google y abra **Get API key** → **Create API key**. Copie la clave (empieza por `AIza`). Active la **facturación** del proyecto: en la capa gratuita, la cuota diaria de `gemini-3.8-flash` fue de 20 solicitudes (2026-10-18) y el experimento necesita más de 80 (D-75).
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
3. **Complete los nombres de Akira para la versión `anon`.** `data/anon_names.yaml` trae para Akira solo los nombres del título (Akira → ActorX, BumbleBee → LoaderX, AdaptixC2 → C2FrameworkX). Para completarlo, ejecute el sugeridor:

   ```bash
   aem suggest-anon-names --scenario akira
   ```

   - **Qué muestra:** una lista numerada de candidatos con las veces que aparece cada uno, 1–2 fragmentos de contexto y su clasificación («probable amenaza» o «probable herramienta legítima/general») con el motivo. El criterio se imprime al principio.
   - **Qué escribe:** `data/reports/private/akira_anon_candidates.md`, con la misma lista y al final las filas YAML listas para copiar de los «probable amenaza» que aún no están listados. Esa carpeta está ignorada por git porque el archivo contiene fragmentos del reporte.
   - **No modifica** `data/anon_names.yaml`.

   Para cada candidato «probable amenaza», decida:

   | Si es… | Qué hacer |
   |---|---|
   | el actor o grupo, un alias, la familia de ransomware, o un malware, loader, backdoor, RAT o framework de C2 propio de la campaña | Copie su fila a `data/anon_names.yaml` bajo `akira:` y revise `replacement` (ActorX, LoaderX, BackdoorX, C2FrameworkX…; no repita uno que ya signifique otra cosa) y `role`. |
   | una palabra común en un título o una cita («Emerging», «Research»), un nombre de persona o un lugar | No lo copie. |
   | una herramienta legítima o de uso general (PowerShell, RDP, AnyDesk, PsExec, Impacket, RClone, Rubeus, Cobalt Strike…) | No lo copie. |

   Revise también los «probable herramienta legítima/general»: el criterio es simple y puede clasificar mal un nombre poco común. Si un nombre está en la lista y en el texto pero el sugeridor no lo propuso, aparece un **AVISO**.

   Como comprobación, `aem suggest-anon-names` sin `--scenario` hace lo mismo con Gunra e Interlock: todos sus nombres listados deben salir como propuestos («Ya en anon_names.yaml y propuestos: …») y sin AVISO.

   Las mayúsculas no importan, y el espacio de un nombre también se busca como guion. Una grafía con otra forma (p. ej. un nombre corto) sí se agrega como fila aparte.
4. Genere las versiones `mut` y `anon` de los tres escenarios y los IoC conocidos:

   ```bash
   aem make-variants
   ```

   Por escenario muestra cuántos IoC se reemplazaron en `mut` y cuántos nombres en `anon`, y cierra con la verificación de que no sobrevive ninguno. Si sobrevive alguno, el comando falla e indica cuál y en qué línea: avíseme con ese mensaje y no edite la variante a mano. Si dice «no aparecen en el texto: …», ese nombre de la lista no está en el reporte; revise la grafía.
5. **Revise los tokens sin defang que `make-variants` dejó intactos en Akira.** La consola los lista como «tokens sin defang con forma de IoC se dejaron intactos» con su línea (también están en `plain_candidates_kept` de `data/reports/akira_dfir_2026_mut_log.json`). Para cada uno:

   | Qué es | Qué hacer |
   |---|---|
   | Enlace de referencia o fuente (blog, otro informe, MITRE, VirusTotal) | Nada: es una cita, no un IoC. |
   | Nombre de archivo o script (`x.ps1`, `y.pl`, `z.exe`) o versión (`1.2.3.4`) | Nada: describe comportamiento. |
   | Servicio legítimo (p. ej. `mega.io`, `temp.sh`) usado por el actor | Nada: es comportamiento. Si el reporte lo lista en su sección de IoC, avíseme. |
   | IP, dominio o correo **del actor** escrito sin defang que no figura en la sección de IoC defanged | Avíseme con el valor y la línea: hay que tratarlo como IoC para que también cambie en `mut`/`anon`. |
   | IP privada de la red de la víctima (`10.x`, `192.168.x`) | Nada: no es un IoC del actor. |

   Para verlos en contexto, abra `data/reports/akira_dfir_2026_mut.diff` o busque la línea en `data/reports/akira_dfir_2026_stripped.txt`.
6. Ejecute `pytest -q`. Ahora también corren sobre Akira las pruebas de que el texto `stripped` no tiene IDs y de que `mut` y `anon` no conservan IoC ni nombres.
7. Compruebe que nada de Akira quedó a la vista de git:

   ```bash
   git status --short            # no debe aparecer ningún data/reports/akira_dfir_2026*
   ```

   `aem make-variants` reescribe `data/org/known_iocs_generated.yaml` (solo Gunra e Interlock) y los `*_mut*`/`*_anon*` de CISA, que **sí** se versionan. Los IoC conocidos de Akira van a `data/reports/private/known_iocs_private.yaml`, que **no** se versiona (D-76).

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

## e. `aem preflight` y `aem eval` completo

Primero, la comprobación (no gasta llamadas de generación; solo consulta que el modelo exista):

```bash
aem preflight
```

Muestra una línea por comprobación con **OK**, **FALTA** o **AVISO**: API key y modelo, checksum de ATT&CK, texto de Akira y que su versión `stripped` no tenga IDs, prevalencia, versiones `orig`/`mut`/`anon` de los tres escenarios y reglas de `.gitignore`. Al final da la estimación de llamadas y tiempo. Corrija cada **FALTA** antes de seguir; un **AVISO** (p. ej. prevalencia vacía) no bloquea. `aem eval` repite esta comprobación al empezar y **no arranca** si hay un FALTA. Si falta el texto de Akira, el preflight lo marca como AVISO: `aem eval` corre Gunra e Interlock, avisa «ESCENARIOS OMITIDOS: akira (sin texto local)» y deja la corrida marcada como «RESULTADO PARCIAL». Para completarla, coloque el texto (paso c) y repita `aem eval` con el **mismo** `--run-id`. Lo ya obtenido sale de la caché y solo se llama a la API para Akira (D-73).

**Obligatorio: use siempre `--run-id <fecha>`.** Sin él, el nombre es la fecha de hoy, y si reanuda otro día crearía otra carpeta con una corrida a medias.

| Sistema | Comando (evita que el equipo se suspenda) |
|---|---|
| Linux | `systemd-inhibit aem eval --run-id 2026-10-20` |
| macOS | `caffeinate -i aem eval --run-id 2026-10-20` |
| Windows | `aem eval --run-id 2026-10-20` (antes, en Configuración → Energía, ponga «Suspender: nunca» mientras corre) |

(Cambie `2026-10-20` por la fecha en que lo inicie.)

- **Duración estimada** (`docs/PLAN.md`): 3 escenarios × 3 versiones (`orig`, `mut`, `anon`) × 5 corridas = 45 extracciones (105 si Akira se divide en 5 fragmentos) + 80–120 resúmenes ≈ **125–165 llamadas**, **25–45 minutos** con `GEMINI_RPM=10`; hasta ≈ 225 llamadas y ≈ 60 minutos en el peor caso. Los reintentos por HTTP 429 la alargan. `aem preflight` da la cifra exacta de extracciones. La estimación supone la capa de pago: con la gratuita (20 solicitudes por día, D-75), el experimento llevaría varios días.
- La consola muestra `escenario · versión · corrida k/5`. Al final indica cuántas corridas no tuvieron salida utilizable y dónde quedó `results.md`.
- **Si se corta por un límite de la API** (cuota diaria, 429 persistente, sin conexión), el comando termina con un error claro. Todas las respuestas ya obtenidas quedan en la caché. Para reanudar, repita **exactamente el mismo comando** (mismo `--run-id`, mismo `GEMINI_MODEL`); si fue la cuota diaria, espere a que se renueve. Solo se piden las llamadas que faltan. Repítalo hasta que termine sin error. Cada intento fallido (429, 5xx) queda en `runs/<run-id>/api_events.jsonl` con el cuerpo del error sin la clave: `quotaMetric`, `quotaId`, `retryDelay`. Si la API indica un `retryDelay`, se espera al menos eso. Si la cuota agotada es **diaria** (`quotaId` con `PerDay`), si el 429 menciona una cuota que no es por minuto, o si el 429 persiste tras los reintentos, `aem eval` se detiene sin degradar ninguna salida: tampoco en los resúmenes del paso 4, y lo dice (D-74).
- Resultado: `runs/2026-10-20/results/` (`results.md`, un CSV por tabla y `results.json`). **Si en lugar de eso aparece `results_FAKE/`**, alguna respuesta no vino de la API real: esas tablas no sirven para la tesis.
- Revise primero la tabla «Corridas por escenario y versión» de `results.md`: `runs_total`, `runs_valid`, `failed_runs` y el motivo de cada falla. Cada indicador trae dos medias: `_fail0` (las fallidas cuentan como 0) y `_valid` (solo corridas válidas). En los indicadores 1 y 3 la **principal es `_fail0`**; en el 5, ambas pesan igual (D-67).
- El indicador 3 compara `orig` con `mut` y con `anon`: la diferencia entre `mut` y `anon` estima cuánto de la persistencia se debe a reconocer la amenaza por su nombre (limitación C2).
- Cada fila de cada tabla lleva `llm_source`, `model`, `model_version`, `run_date` y `prompt_templates_sha256`, que son los datos para citar la corrida.
- Comprobación de reproducibilidad (sin API key ni llamadas, segundos):

  ```bash
  aem eval --demo --run-id 2026-10-20-demo
  ```

  Las tablas deben coincidir con las de la corrida real, salvo `run_date` si la repite otro día.

### Resumen para la tesis: `aem report`

Cuando `runs/2026-10-20/results/` exista (sin errores ni `results_FAKE/`), genere el resumen:

```bash
aem report --run-id 2026-10-20
```

- **Qué lee:** solo `runs/2026-10-20/results/results.json`. Si la corrida solo tiene `results_FAKE/`, o el archivo está marcado como FAKE, se niega y lo dice.
- **Qué escribe** en `docs/resultados/2026-10-20/`:
  - `resumen.md`: modelo (ID y versión), fecha, hash de las plantillas de prompt y una tabla por indicador. En cada tabla, `_fail0` va primero, luego `_valid`, la DE y las corridas totales, válidas y fallidas. Los números se copian tal como están en `results.json`.
  - una sección «Datos faltantes»: celdas «sin dato disponible», escenarios no evaluados y cuántas filas de las salidas por corrida no tienen `data_sources` o `prevalence`;
  - una sección «Lo que estos números permiten y no permiten afirmar», con C1–C3 y las advertencias de D-67;
  - `indicador1_precision.png`, `indicador1_exhaustividad.png` e `indicador3_persistencia.png`: barras con la media `_fail0` y la DE como barra de error, `orig`/`mut`/`anon` por escenario, distinguidas por trama y tono de gris.
- Si actualizó el repositorio desde una versión sin este comando, reinstale una vez para obtener `matplotlib`: `pip install -e .`
- `docs/resultados/` se versiona: contiene solo cifras, sin texto de los reportes.

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
| `runs/<run-id>/results/` y las salidas de Gunra e Interlock en `runs/<run-id>/`; `docs/resultados/<run-id>/` (`aem report`) | `runs/llm_cache_private/` (prompts con el texto de Akira) |
| `eval/review_sheets/*.csv` llenas | `runs/*/private/` (salidas de Akira con citas) |
| `data/prevalence/red_canary_2026.csv`, `data/org/known_iocs_generated.yaml`, `data/reports/*_mut*` y `*_anon*` de CISA, `data/anon_names.yaml` (solo nombres, no texto) | `eval/review_sheets/private/` (muestra de Akira) |
| | `data/reports/akira_dfir_2026*` (texto, `stripped`, variante y diff) |
| | `data/reports/private/` (candidatos de nombres e IoC conocidos de Akira, D-76) |

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

**Obligatorio antes de subir a GitHub (y recomendable después de cada commit):**

```bash
aem check-repo
```

Revisa los archivos versionados, el índice y **todo el historial de git** en busca de:
- un `.env`;
- patrones de API keys (nunca imprime la clave);
- archivos dentro de carpetas `private/` o `llm_cache_private/` y los archivos `data/reports/akira_dfir_2026*`;
- texto del reporte de DFIR, buscando frases distintivas de su copia local en `data/reports/akira_dfir_2026.txt`. Sin esa copia, avisa que no pudo buscarlo.

Termina con **OK** o con la lista exacta de hallazgos (`archivo:línea (en <commits>)`) y código de salida 1. Si encuentra algo, **no suba**: avíseme. Si está en el historial, borrar el archivo no basta, hay que reescribir el historial antes de publicar.

## h. URL del repositorio y declaración de uso de IA en el README

Hay dos README con el mismo contenido: `README.md` (inglés, el principal) y `README.es.md` (español). Todo cambio se hace en los dos; `tests/test_readmes.py` comprueba que tengan las mismas secciones, las mismas marcas pendientes (`[PENDING: …]` en inglés, `[PENDIENTE: …]` en español), el mismo BibTeX y la misma URL.

1. Cree el repositorio en GitHub, vacío y sin README. Con `gh`: `gh repo create Mumogg/attack-exposure-model --public` (o `--private`). También puede hacerlo desde github.com.
2. En `README.md` y `README.es.md`, reemplace las marcas `[PENDIENTE: confirmar URL]`:
   - las dos líneas `git clone …` de la instalación;
   - `url` y `note` de la entrada BibTeX de «Cómo citar».
3. Complete la sección «Declaración de uso de IA en el desarrollo» (en inglés, «Declaration of AI use in development») con el texto que exija la universidad. Un **borrador** que puede adaptar:

   > Este repositorio se desarrolló con asistencia de Claude Code (Anthropic), que escribió código, pruebas y documentación siguiendo las especificaciones y decisiones del autor, quien revisó y aprobó cada cambio. El modelo evaluado usa Gemini (Google) como componente en los pasos 1 y 4, tal como se describe arriba. Los resultados reportados provienen de la ejecución con la API real de Gemini; ningún resultado fue generado ni editado por el asistente de desarrollo.

4. Ejecute `aem check-repo` (paso g). Solo si termina en **OK**, enlace el remoto y suba cuando lo decida:

   ```bash
   aem check-repo
   git remote add origin https://github.com/Mumogg/attack-exposure-model.git
   git push -u origin main
   ```

## i. Actualizar `docs/RESUMEN_PARA_TESIS.md` con los resultados reales

1. Tome las cifras de `docs/resultados/<run-id>/resumen.md` (`aem report`) o de `runs/<run-id>/results/results.md`, no de la consola.
2. En el resumen, agregue o actualice:
   - **Datos de la corrida:** `run-id`, fecha, `model` y `model_version`, y los hashes de `prompt_templates_sha256`.
   - **Corridas:** por escenario y versión, las totales, válidas y fallidas, con el motivo de cada falla.
   - **Indicadores 1 y 3:** media ± desviación estándar con `_fail0` como cifra principal y `_valid` como secundaria, junto con `failed_runs` (D-67). En el indicador 3, las tres versiones (`orig`, `mut`, `anon`) y las razones mut/orig y anon/orig.
   - **Indicador 5:** `_fail0` y `_valid` con el mismo peso, con el aviso de que contar una falla como 0 favorece al modelo.
   - **Indicador 2:** exactitud y discrepancias.
   - **Indicadores 4 y 5:** resultados de su revisión manual (conteos del paso f).
3. Revise la tabla de decisiones `PENDIENTE DE CONFIRMAR` del resumen (D-03, D-62, D-65 y las que se agreguen). Confirme o cambie cada una en `docs/DECISIONS.md`.
4. Si lo prefiere, pídale a Claude: «actualiza RESUMEN_PARA_TESIS.md con runs/<run-id>/results/results.md y las hojas revisadas».
5. Haga commit (ver paso g).
