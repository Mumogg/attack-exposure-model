# CLAUDE.md — attack-exposure-model

Instrucciones para Claude Code. Léelas completas antes de escribir una línea de código.

---

## 0. Contexto: qué es esto y para qué sirve

Sebas (Sebastián Murillo Mora) está haciendo su Trabajo Final de Graduación (licenciatura en Ingeniería en Sistemas de Computación, Universidad Fidélitas, Costa Rica). El título aprobado es:

> «Diseño de un modelo de evaluación de amenazas cibernéticas asistido por inteligencia artificial basado en MITRE ATT&CK para entornos empresariales».

Fecha límite del borrador completo: **2 de diciembre de 2026**. Hoy es mediados de octubre de 2026, así que el tiempo es corto. Prioriza que **funcione y se pueda medir** antes que pulir.

Este repositorio es el **prototipo mínimo** del modelo, que se publicará en GitHub con licencia abierta **solo con fines de reproducibilidad** de las simulaciones de la tesis. No es una herramienta lista para producción y no debe prometerlo en ningún README ni mensaje.

### La idea central (no la pierdas)
El modelo **no detecta si una organización fue comprometida**. Evalúa **para qué técnicas de MITRE ATT&CK la organización está expuesta o no tiene capacidad de detección**, dado un reporte de amenaza. Razón de diseño: una IA puede mutar el artefacto de un ataque (hashes, IPs, dominios, código) con facilidad, pero no el comportamiento (la técnica) que necesita ejecutar; por eso se evalúa por técnicas y no por indicadores de compromiso (IoC).

### Principio de diseño que NO se puede violar
**IA donde hay lenguaje natural, código donde hay datos estructurados, criterio humano donde hay consecuencias.**
- La IA hace **solo dos cosas**: (1) extraer y mapear técnicas ATT&CK desde el texto de un reporte; (2) condensar la descripción larga de una técnica en un resumen breve.
- La IA **nunca** asigna prioridades, urgencia ni recomienda acciones. Esto se garantiza **por arquitectura** (campos de salida fijos, ninguno evaluativo; la priorización ocurre en un paso donde la IA no participa), **no por instrucciones en el prompt**. El prompt además lo prohíbe, pero el diseño no depende de eso.

### Estado actual (2026-10-21)
- **Corrida final `2026-10-18-main` completa y congelada** (`docs/RUNBOOK.md` §j, commit de referencia `2996515`). Solo se admiten cambios de documentación, CI y correcciones que no cambien ninguna salida. No toques el código de los pasos 1 a 4 ni de la evaluación (`src/aem`, `eval`), los prompts, `data/org`, los escenarios, los textos de los reportes ni los mapeos de referencia: cualquier cambio congelado exige un run-id nuevo.
- **Revisión humana integrada:** las tres hojas (indicador 4: 71 filas; indicador 5 público: 15; indicador 5 privado de Akira: 15) están completas e integradas con `aem integrate-review` (commit `21c413b`). Las hojas **no se ordenan ni se filtran** en la hoja de cálculo: `aem review-check` lo rechaza. Se guardan como CSV UTF-8.
- **Prevalencia (D-78):** la plantilla `data/prevalence/red_canary_2026.csv` queda vacía, como se congeló; la columna `prevalence` del experimento dice `sin dato disponible`. Los rankings reales de Red Canary están en `data/prevalence/context/`, solo como contexto para la discusión de la tesis; ningún código del pipeline los lee (test).

---

## 1. Dónde crear el proyecto

Crea el repositorio en una carpeta llamada `attack-exposure-model` **dentro de la carpeta `github`, que está en el disco/volumen de 1 TB cuya etiqueta es `info`**.

- Primero localiza ese disco. Detecta el sistema operativo y busca el volumen con etiqueta `info` (Windows: `Get-Volume` o `wmic logicaldisk get name,volumename`; macOS: `/Volumes/info`; Linux: `lsblk -o NAME,LABEL,SIZE,MOUNTPOINT` y `/media`, `/mnt`).
- Si encuentras la carpeta `github` en ese disco, trabaja ahí. **Si el disco no aparece, hay varios candidatos o la carpeta `github` no existe, detente y pregúntale a Sebas la ruta exacta antes de crear nada.**
- No crees ni modifiques nada fuera de `…/github/attack-exposure-model/`.
- El repositorio usa git, rama `main`, publicado en https://github.com/Mumogg/attack-exposure-model. **Haz `push` solo cuando Sebas lo pida explícitamente**, y no crees tags ni releases hasta que él lo pida.

---

## 2. Reglas de trabajo para ti (Claude Code)

1. **Antes de programar**, escribe un plan corto (estructura de carpetas, dependencias, orden de implementación) y guárdalo en `docs/PLAN.md`. Después sigue sin esperar aprobación, salvo que aparezca algo de la sección 11 (bloqueantes).
2. **Commits pequeños** y frecuentes, mensajes en inglés, en formato `tipo: descripción` (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
3. **Tests con `pytest`** para toda lógica determinística. **Los tests nunca llaman a la API real**: usa mocks o respuestas guardadas.
4. **Nunca inventes datos.** Esto incluye: técnicas de ATT&CK, IDs, mitigaciones, la prevalencia de Red Canary, o el contenido de los reportes. Si un dato no está disponible, el programa dice `sin dato disponible` o se detiene con un error claro.
5. **Secretos:** la API key va solo en `.env` (nunca en el código ni en commits). Crea `.env.example` y un `.gitignore` correcto **en el primer commit**.
6. **Compatible con Windows, macOS y Linux:** usa `pathlib`, no rutas escritas a mano, y evita comandos específicos de un shell en el código.
7. **Idioma:** identificadores, comentarios y commits en **inglés**; textos de la CLI y documentación en **español** (es una tesis costarricense). El README principal es `README.md`, en **inglés**; `README.es.md` es la versión en español, con las mismas secciones (lo comprueba `tests/test_readmes.py`). Todo cambio se hace en los dos.
8. **No ejecutes malware ni código ofensivo.** Este repo solo **analiza texto** y datos estructurados. Atomic Red Team y CALDERA se usan aparte, en un laboratorio aislado, y no forman parte de este repo (deja solo una nota en `docs/lab_notes.md`).
9. Sé honesto en los README: marca como *adaptación propia, pendiente de validación* todo lo que Sebas todavía no haya confirmado (ver `docs/DECISIONS.md`).

---

## 3. Stack

- Python **3.11+**, entorno virtual, `pyproject.toml` (o `requirements.txt` si es más simple).
- Dependencias mínimas: `pydantic`, `pyyaml`, `python-dotenv`, `typer` (CLI), `rich` (tablas y prompts), `mitreattack-python` (acceso a los datos STIX de ATT&CK), SDK oficial de Gemini (`google-genai`), `pytest`.
- **Verifica en la documentación oficial vigente** el nombre exacto del paquete, la forma de pedir salida JSON con esquema (`response_mime_type` / `response_schema` o equivalente) y la lista de modelos. El SDK y los modelos cambian seguido; no confíes en tu memoria.
- Sin framework web. Interfaz = **línea de comandos**. (Una interfaz web local simple es opcional y va al final, solo si sobra tiempo.)

### LLM
- Proveedor: **Google Gemini** (los reportes usados son públicos y la organización es ficticia, así que no hay datos sensibles). La capa gratuita no alcanzaba: las corridas finales usaron la capa de pago (D-75), sin cambiar modelo, parámetros ni prompts.
- Modelo por defecto: **`gemini-3.8-flash`**; alternativa: `gemini-3.5-flash-lite`. Léelo de la variable de entorno `GEMINI_MODEL`. En la primera ejecución verifica con la API que el modelo existe; si no, avisa claramente y sugiere el alternativo.
- Parámetros: `temperature = 0`, salida JSON con esquema fijo. Registra siempre: ID exacto del modelo, fecha y hora, temperatura, hash SHA-256 del prompt.
- Respeta los límites de la capa gratuita (aprox. 10 solicitudes por minuto; **no son cifras oficiales**: configúralas en `.env` como `GEMINI_RPM`): pausa entre llamadas y reintentos con espera exponencial ante HTTP 429.
- **Caché y modo demo:** toda respuesta del LLM se guarda en disco, con clave = hash(modelo + prompt + parámetros). El flag `--demo` usa **solo** esa caché y falla con un mensaje claro si falta una entrada; así cualquiera puede reproducir sin API key. Las respuestas de las corridas finales **sí se commitean** (carpeta `runs/`).

---

## 4. Estructura de carpetas

```
attack-exposure-model/
├── CLAUDE.md                  (este archivo)
├── README.md  README.es.md    (inglés, principal; español; ver sección 9)
├── LICENSE                    (MIT)
├── .gitignore  .env.example  pyproject.toml
├── docs/
│   ├── PLAN.md  DECISIONS.md  lab_notes.md
├── src/aem/
│   ├── cli.py                 (comandos: ver sección 6)
│   ├── config.py  models.py   (pydantic: todos los esquemas)
│   ├── llm.py                 (cliente Gemini + caché + demo + reintentos)
│   ├── attack_data.py         (carga de ATT&CK v19.2 desde STIX)
│   ├── step1_extract.py       (IA)
│   ├── step2_coverage.py      (script)
│   ├── step3_prioritize.py    (analista + árbol SSVC adaptado + agrupación)
│   ├── step4_reference.py     (script + IA solo para el resumen)
│   └── output.py              (CSV + archivo de revisión global)
├── data/
│   ├── attack/                (JSON STIX descargado; en .gitignore; solo script + checksum)
│   ├── org/fictional_org.yaml (organización ficticia, estilo DeTT&CT)
│   ├── ssvc_tree.yaml         (tabla de decisión editable)
│   ├── prevalence/red_canary_2026.csv  (plantilla del paso 4; vacía, congelada, D-78)
│   ├── prevalence/context/    (rankings reales de Red Canary; solo contexto, ningún código los lee)
│   ├── reports/               (textos; ver sección 7)
│   └── reference_mappings/    (CSV de técnicas de referencia por escenario)
├── eval/
│   ├── make_variants.py  baseline_ioc.py  metrics.py  run_experiments.py
│   └── review_sheets/         (hojas de revisión manual; la de Akira en private/, ignorada por git)
├── runs/                      (respuestas crudas del LLM + resultados; se commitea, salvo runs/*/private/ y runs/llm_cache_private/, D-69)
└── tests/
```

---

## 5. El modelo: los 4 pasos (especificación)

### Entradas
1. **YAML de la organización** (`data/org/fictional_org.yaml`), basado en la metodología DeTT&CT (https://github.com/rabobank-cdc/DeTTECT). Esquema propio simplificado (valídalo con pydantic):
   - `organization`: nombre ficticio.
   - `assets`: lista con `id`, `name`, `criticality` (`alta|media|baja`), `processes_regulated_data` (bool), `exposure` (`internet|interna|aislada`).
   - `data_sources`: fuentes de datos que la organización registra, con `name` y `quality` (0–5).
   - `detections`: por técnica de ATT&CK, `technique_id`, `score` (escala DeTT&CT de detección 0–5) y `data_sources` que la respaldan.
   - `analyst_context`: para la simulación reproducible, la criticidad y la exposición que el analista asignaría por técnica (`technique_id`, `asset_id`).
   - `known_iocs`: IoC que la organización «ya conoce» (solo para el enfoque tradicional de comparación; ver sección 8).
   - **Importante:** el YAML ficticio debe tener **brechas de cobertura conocidas de antemano** (técnicas sin detección, otras con detección parcial). Estas brechas las define Sebas; tú generas un borrador razonable cubriendo las técnicas de los tres escenarios con una mezcla de cubiertas/parciales/sin cobertura, y lo marcas como `# BORRADOR: Sebas decide las brechas` y en `docs/DECISIONS.md`.
2. **Reporte de amenaza** en texto plano (`.txt` o `.md`).

### Paso 1 — Extracción y mapeo (IA)
- Entrada: texto completo del reporte. Salida: lista estructurada de técnicas **ATT&CK Enterprise v19.2**.
- Esquema JSON por técnica: `technique_id` (p. ej. `T1021.001`), `technique_name`, `evidence_quote` (cita textual corta del reporte que lo justifica). **No agregues campos de confianza, severidad, prioridad ni recomendación.**
- El prompt: pide solo extraer técnicas **descritas en el reporte** (no inferir lo que «probablemente» ocurre), exige el ID exacto y prohíbe explícitamente evaluar, priorizar o recomendar.
- Reportes largos: si exceden el contexto o dan mala calidad, divide en fragmentos con solapamiento y unifica sin duplicar. Documenta cómo.
- **Validación por código** (no por la IA): cada ID debe existir en ATT&CK v19.2 y no estar revocado/deprecado. Los IDs inválidos o deprecados se marcan `needs_review` y se muestran al analista; **no se descartan en silencio**.
- Guarda **dos listas por separado**: `extracted_raw` (lo que devolvió el LLM) y `extracted_validated` (tras la revisión del analista). Las métricas de la sección 8 se calculan sobre la lista **raw**.
- Revisión del analista: CLI interactiva (aceptar / quitar / agregar IDs) o `--analyst-mode auto` (acepta todo; solo para experimentos). Siempre registra qué hizo el analista.

### Paso 2 — Análisis de cobertura (script determinístico, sin IA)
- Para cada técnica validada, busca en el YAML sus detecciones y fuentes de datos y clasifica en **tres niveles: `cubierta`, `parcial`, `sin cobertura`**.
- Regla por defecto, adaptada de las escalas de DeTT&CT (**marcar como adaptación propia, a confirmar por Sebas**): `score` 0 o sin entrada → `sin cobertura`; 1–3 → `parcial`; 4–5 → `cubierta`. Los umbrales viven en `config` y se documentan en `docs/DECISIONS.md`.
- Sub-técnicas: si la técnica de la lista es una sub-técnica sin entrada propia en el YAML, **no heredes cobertura de la técnica padre en silencio**: usa una política explícita y configurable (por defecto: sin cobertura) y regístrala en `DECISIONS.md`.
- Mismas entradas → mismo resultado, siempre (tests).

### Paso 3 — Priorización contextual (analista + árbol adaptado de SSVC)
Referencia: SSVC v2.0 (Spring et al., 2021, SEI-CMU). Es una **adaptación** de un árbol pensado para vulnerabilidades, aplicada a técnicas adversarias.

Orden dentro del paso:
1. **Validación previa de la cobertura:** el analista revisa la clasificación del paso 2 y puede corregirla si conoce controles que no están en el YAML. Guarda `coverage_original`, `coverage_validated` y el motivo.
2. **Árbol de decisión por técnica**, con tres criterios:
   - `coverage_validated` (viene del paso 2 / analista).
   - `criticality` del activo afectado (`alta|media|baja`, la da el analista; considera si procesa datos personales o regulados).
   - `exposure` (`internet|interna|aislada`), **solo para técnicas de la táctica Acceso Inicial (Initial Access)**; para las demás no se pregunta ni se usa.
3. **Salida del árbol: una de cuatro acciones, con nombres en inglés** (así se llaman en SSVC): `Track` (registrar y mantener bajo seguimiento ordinario), `Track*` (registrar con seguimiento reforzado), `Attend` (atender fuera del ciclo habitual de trabajo), `Act` (atender de forma prioritaria).
4. **Revisión global de la cadena:** el script muestra al analista el conjunto de técnicas ordenadas por táctica (orden de la matriz) y le hace **una sola pregunta**: *«¿Existe algún punto de la cadena en el que la organización cuente con cobertura suficiente para interrumpir el ataque?»* El analista responde sí/no, indica en qué táctica(s) y puede agregar una nota. Se guarda en un **archivo complementario** (`global_review.json`). **El análisis lo hace el humano; el script no responde esa pregunta ni sugiere respuesta.**
5. **Agrupación y ordenamiento (script, sin intervenir en la decisión):** agrupa por acción asignada.
- La tabla de decisión vive en `data/ssvc_tree.yaml` (editable, sin tocar código). **Propuesta inicial, marcada como pendiente de confirmación por Sebas:**
  - Técnicas que no son de Acceso Inicial, por (cobertura, criticidad):
    - cubierta: baja→`Track`, media→`Track`, alta→`Track*`
    - parcial: baja→`Track`, media→`Track*`, alta→`Attend`
    - sin cobertura: baja→`Track*`, media→`Attend`, alta→`Act`
  - Técnicas de Acceso Inicial: se aplica la tabla anterior y luego la exposición ajusta un nivel (orden `Track < Track* < Attend < Act`): `internet` sube un nivel (tope `Act`), `aislada` baja un nivel (piso `Track`), `interna` no cambia.
- **Nunca** calcules la acción con ninguna llamada a un LLM.

### Paso 4 — Consolidación de información de referencia (script + IA solo para el resumen)
- Un script consulta los datos STIX de ATT&CK (`mitreattack-python`) **en lote para todas las técnicas a la vez** y recupera exactamente **cinco campos de referencia**:
  1. `summary`: resumen breve de la descripción de la técnica + `source_link` (URL de attack.mitre.org construida **por código**, no por el LLM).
  2. `mitigations`: mitigaciones asociadas como **catálogo de identificadores** (`M####` + nombre), **sin recomendar cuál aplicar**.
  3. `data_sources`: fuentes de datos que permiten detectarla (campo de ATT&CK).
  4. `groups`: grupos de amenaza que la emplean (nombres, de ATT&CK).
  5. `prevalence`: prevalencia en entornos reales según **Red Canary (2026), *2026 Threat Detection Report*** leída de `data/prevalence/red_canary_2026.csv`; si la técnica no figura, el valor es literalmente `sin dato disponible`. La plantilla quedó vacía al congelar el experimento (D-78), así que en `2026-10-18-main` todas las filas dicen `sin dato disponible`.
- **La IA interviene solo para condensar la descripción larga** (máx. 3 oraciones, sin añadir información que no esté en la descripción fuente, sin valoraciones). Si el LLM falla, el campo queda `resumen no disponible` y el enlace igualmente se muestra.
- **Prohibido en la salida de este paso:** cualquier campo de urgencia, prioridad, riesgo, recomendación de acción o «relevancia».
- **Plantilla de prevalencia:** `data/prevalence/red_canary_2026.csv`, con encabezado `technique_id,rank,source_note` y **sin datos inventados**. **Se queda vacía** (D-78): llenarla cambiaría las salidas del pipeline y exigiría un run-id nuevo. Los rankings reales de Red Canary (ediciones 2019 y 2020 del repositorio público, licencia MIT, y el top 10 de 2026) están en `data/prevalence/context/`, solo como contexto para la discusión; ningún código del pipeline, de la evaluación ni del reporte los lee.
- Datos de ATT&CK: usa la **versión 19.2** (https://github.com/mitre-attack/attack-stix-data , archivo `enterprise-attack-19.2.json`). Escribe `scripts` / comando `fetch-data` que lo descargue y guarde su checksum; verifica que ese archivo exista; si el nombre difiere, ajústalo y regístralo. **El orden de las tácticas debe leerse de los datos de la matriz** (en v19 *Defense Evasion* se dividió en *Stealth* y *Defense Impairment*): no lo escribas a mano.

### Salida del modelo
- **Un CSV** por amenaza analizada, una fila por técnica. Columnas fijas y en este orden:
  `technique_id, technique_name, tactics, coverage_validated, criticality, exposure, action, summary, source_link, mitigations, data_sources, groups, prevalence`
- Orden de filas: primero por grupo de acción (`Act`, `Attend`, `Track*`, `Track`), y **dentro de cada grupo, por secuencia de ataque (orden de la táctica en la matriz)**; una técnica con varias tácticas se ordena por la primera. **El script no establece prioridades entre técnicas con una misma acción.**
- `exposure` queda vacío salvo en técnicas de Acceso Inicial.
- Archivo complementario `global_review.json` con la respuesta del analista a la revisión global.
- Codificación UTF-8 con BOM para que Excel lo abra bien. La salida **no afirma que la organización haya sido comprometida** ni contiene recomendaciones generadas por IA.
- Un test debe fallar si alguna columna evaluativa nueva aparece en el CSV (salvo `action`, que es del analista) o si el LLM produce texto de urgencia.

---

## 6. CLI

Comandos (con `typer`), todos con `--help` en español:
- `aem fetch-data`: descarga ATT&CK v19.2 y los reportes de CISA (sección 7).
- `aem run --report <txt> --org <yaml> [--analyst-mode interactive|auto] [--demo] --out <carpeta>`: corre los 4 pasos.
- `aem make-variants`: genera la variante con IoC modificados de cada reporte.
- `aem eval`: corre el experimento completo (sección 8) y genera las tablas.
- `aem demo`: atajo para correr el escenario de Gunra en modo `--demo`, sin API key.
- Además: `prepare-reports`, `suggest-anon-names`, `preflight`, `review-check`, `integrate-review` (integra las hojas de revisión en una corrida ya evaluada, sin `aem eval` ni API), `report` (`--html`, `--private`), `sensitivity`, `provenance` y `check-repo` (`--deep`). El uso de cada uno está en `docs/RUNBOOK.md`.

---

## 7. Escenarios y datos de los reportes

Tres escenarios, todos evaluados contra la **misma organización ficticia**:
1. **Gunra** — boletín #StopRansomware de CISA/FBI, **AA26-222A**, 10 de agosto de 2026. https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a
2. **Interlock** — boletín #StopRansomware de CISA, **AA25-203A**, 22 de julio de 2025. https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-203a
3. **Akira (The DFIR Report)** — «From Bing search to ransomware: BumbleBee and AdaptixC2 deliver Akira», 29 de junio de 2026. https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/

(Extra opcional, **no hacer a menos que Sebas lo pida**: reporte de IBM X-Force sobre Slopoly, sin mapeo ATT&CK.)

Tratamiento:
- **Los boletines de CISA incluyen las tablas del mapeo ATT&CK** (secciones «MITRE ATT&CK tactics and techniques»). Úsalas así:
  - De esas tablas extrae el **mapeo de referencia** → `data/reference_mappings/<escenario>.csv` (`technique_id,technique_name,tactic`). Verifica cada ID contra ATT&CK v19.2 y deja una columna `valid_in_v19_2` (los de 2025 pueden haber cambiado).
  - **Antes de dárselo al LLM, elimina del texto la sección que contiene el mapeo ATT&CK**, para que la extracción no consista en copiar la tabla de referencia. Guarda el texto resultante como `<escenario>_stripped.txt`, y documenta en `docs/` exactamente qué secciones se quitaron.
  - Los boletines de CISA son documentos del gobierno de EE. UU.; se pueden incluir en el repo.
- **DFIR Report (Akira):** su contenido **tiene derechos de autor: no lo copies al repo.** El repo incluye solo el enlace, instrucciones para descargarlo y colocar el texto en `data/reports/akira_dfir_2026.txt` (en `.gitignore`), y el mapeo de referencia (**solo IDs de técnicas**, que son datos, no texto) tomado de la sección ATT&CK del reporte (38 técnicas en `data/reference_mappings/akira.csv`). Esa sección también debe retirarse del texto antes de dárselo al LLM. Si no puedes descargarlo con seguridad, **pídele a Sebas que lo ponga a mano**; no lo reconstruyas de memoria.
- Descargas: si no tienes acceso de red a algún sitio, dilo y pide el archivo; no inventes el contenido.
- Cada escenario existe en **tres versiones**: `orig`, `mut` (indicadores modificados, ver 8) y `anon` (además, nombres del actor y del malware reemplazados; D-72).

---

## 8. Evaluación (lo que mide la tesis)

El comité pidió diseñar, ejecutar y evaluar simulaciones controladas con criterios de comparación e indicadores. Implementa en `eval/` lo siguiente. **Cada combinación escenario × versión se corre 5 veces** con los mismos parámetros (el LLM no responde igual siempre) y se reporta media y desviación estándar. Guarda cada respuesta cruda en `runs/<fecha>/…`.

**Indicador 1 — Precisión y exhaustividad del paso 1.** Sobre `extracted_raw` frente a `reference_mappings`: precisión = técnicas propuestas correctas / propuestas; exhaustividad = técnicas de referencia identificadas / de referencia. Reporta a **nivel de sub-técnica exacta** y a **nivel de técnica padre** (ambos), y lista las omitidas y las erróneas.

**Indicador 2 — Corrección del cruce de cobertura (paso 2).** Sobre la lista de referencia (para aislar el paso 2 del error del LLM), verifica que las brechas detectadas coincidan con las definidas en el YAML. Debe dar 100 %; si no, es un bug.

**Indicador 3 — Persistencia en el reconocimiento de la exposición.** Definición de la tesis: *porcentaje de técnicas del escenario cuya brecha de cobertura (modelo) o cuya presencia (enfoque tradicional) es reconocida en la variante con indicadores modificados, comparado con el mismo porcentaje en el escenario original.*
- **Variante `mut`** (`make_variants.py`): reemplaza hashes (mismo largo, hexadecimal aleatorio con semilla fija), direcciones IP y nombres de dominio/URL por valores nuevos que **no apunten a hosts reales** (IPs en rangos de documentación RFC 5737; dominios `.invalid` o `example.*`), **conservando intacto el comportamiento descrito**. Registra la semilla y un diff.
- **Enfoque tradicional** (`baseline_ioc.py`): extrae los IoC del reporte con expresiones regulares y los compara con `known_iocs` del YAML; si hay al menos una coincidencia, «reconoce» la amenaza (todas las técnicas del escenario); si no, ninguna. En `orig`, `known_iocs` contiene una porción de los IoC reales del reporte (fija y reproducible, con semilla); en `mut`, por construcción ya no coinciden. **Esta política es una simplificación pendiente de confirmar por Sebas: documéntala en `DECISIONS.md` y haz que sea configurable.**
- Modelo: de las técnicas con brecha según el YAML (`parcial` o `sin cobertura`) y presentes en la referencia, qué porcentaje flaggea el modelo en cada versión.

**Indicador 4 — Fidelidad de los resúmenes del paso 4.** Genera una **hoja de revisión manual** (CSV) con descripción original, resumen y columnas vacías `ok (si/no)` y `observación` para que Sebas la complete. Además calcula un chequeo automático básico (p. ej., que el resumen no contenga IDs o cifras que no aparezcan en la fuente). Las hojas de `2026-10-18-main` (indicadores 4 y 5) ya están completas e integradas con `aem integrate-review`; no se regeneran con `aem eval` ni se ordenan o filtran.

**Indicador 5 — Cumplimiento de los límites.** Comprobación automática de que ninguna salida de IA contenga campos o texto de valoración (lista de patrones en español e inglés: prioridad/priority, urgente/urgent, recomend*/recommend*, «debería»/«should», «crítico»/«critical», etc.). Cuenta las violaciones. Complementa con revisión manual de una muestra.

Entregables de `aem eval`: tablas en CSV y Markdown (`runs/<fecha>/results/`), y gráficos simples (barras con barras de error) en PNG si sobra tiempo. Todo reproducible con el modo demo.

> **No hay indicador para el paso 3 ni para la revisión global** (son criterio del analista). En la simulación el paso 3 lo realiza el autor con la criticidad y exposición **definidas de antemano** en `analyst_context` del YAML, y esto se declara como limitación (no es una validación independiente). Documéntalo en el README.

---

## 9. README (inglés y español)

Debe incluir: qué es y qué NO es (prototipo para reproducibilidad de una tesis; no producción); la idea central y el principio de diseño; diagrama de flujo en texto o Mermaid; instalación paso a paso en Windows/macOS/Linux; cómo obtener y poner la API key (`.env`); cómo correr el **modo demo sin API key**; cómo reproducir los resultados; estructura del repo; aviso sobre los datos (CISA incluido, DFIR no incluido por derechos de autor); limitaciones honestas; licencia MIT; cómo citarlo; y una sección «Declaración de uso de IA en el desarrollo» (ya redactada). La única marca pendiente en los README es la versión publicada del BibTeX (`[PENDIENTE: versión publicada]`), que se queda hasta la release.

---

## 10. Orden de implementación (sigue este orden)

1. Esqueleto: carpetas, `.gitignore`, `.env.example`, `pyproject`, LICENSE, `docs/PLAN.md`, `docs/DECISIONS.md`.
2. `models.py`, `config.py`, `attack_data.py` + `fetch-data` (ATT&CK v19.2) + tests.
3. `step2_coverage.py` + `fictional_org.yaml` borrador + tests.
4. `step3_prioritize.py` + `ssvc_tree.yaml` + tests (tabla completa, ajuste por exposición, solo Acceso Inicial).
5. `step4_reference.py` (parte de código; el resumen con LLM detrás de una interfaz mockeable) + plantilla de prevalencia + tests.
6. `llm.py` (Gemini, caché, demo, reintentos) + `step1_extract.py` + tests con mocks.
7. `output.py` + CSV + `global_review.json` + CLI `run` de punta a punta en `--demo` con un boletín de ejemplo.
8. Datos de escenarios: descarga de CISA, strip del mapeo, mapeos de referencia, `make_variants.py`, `baseline_ioc.py`.
9. `metrics.py`, `run_experiments.py`, `aem eval`, hojas de revisión manual.
10. README, pulido, revisión final de secretos y de `.gitignore`.

Cuando termines cada bloque: corre `pytest`, haz commit y deja una nota de una línea en `docs/PLAN.md` con lo hecho y lo pendiente.

---

## 11. Cuándo detenerte y preguntarle a Sebas (solo estos casos)

- No encuentras el disco `info` o la carpeta `github`, o hay ambigüedad (sección 1).
- No puedes descargar un reporte o dato y no hay forma legítima de obtenerlo.
- Un ID de técnica de los mapeos de referencia no existe en v19.2 y no sabes a cuál corresponde ahora.
- La API de Gemini devuelve un error de modelo/cuota que no puedes resolver con los pasos de la sección 3.
- Algo exigiría **copiar contenido con derechos de autor al repo** o **subir una credencial**.

Para todo lo demás: toma una decisión razonable, impleméntala configurable, y regístrala en `docs/DECISIONS.md` con la etiqueta **PENDIENTE DE CONFIRMAR** para que Sebas la revise.

---

## 12. Definición de «terminado»

- [ ] `pytest` pasa completo sin llamar a la API.
- [ ] `aem demo` corre de punta a punta **sin API key** y produce el CSV y `global_review.json`.
- [ ] Con API key, `aem run` procesa los boletines de Gunra e Interlock y el de Akira (si Sebas puso el texto).
- [ ] `aem eval` produce los cinco indicadores para los tres escenarios × `orig`/`mut`/`anon` × 5 corridas.
- [ ] No hay secretos ni texto de DFIR Report en el historial de git.
- [ ] `docs/DECISIONS.md` lista todo lo marcado **PENDIENTE DE CONFIRMAR**.
- [ ] El README es claro para alguien que nunca vio el proyecto.
