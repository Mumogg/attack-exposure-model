# Resumen para el marco metodológico

Documento de apoyo para redactar el marco metodológico de la tesis. Describe lo que hay **en el código** al 2026-10-17. Las cifras de resultados **no** están aquí: se obtienen al correr `aem eval` con la API key real (`runs/<fecha>/results/results.md`).

Fuentes de verdad, por si algo cambia: `data/model_config.yaml` (parámetros), `docs/DECISIONS.md` (decisiones), `docs/report_preparation.md` (preparación de reportes), `docs/PLAN.md` (estimación de llamadas y bitácora).

---

## 1. Qué se construyó, paso por paso

### 1.1 Datos de entrada

1. **ATT&CK Enterprise v19.2.** `aem fetch-data` descarga `enterprise-attack-19.2.json` del repositorio oficial `mitre-attack/attack-stix-data` y verifica su SHA-256 contra el valor registrado. Todo el modelo valida IDs, nombres, tácticas y relaciones contra ese archivo. El orden de las tácticas (secuencia de ataque) se lee de la matriz del propio archivo; en v19 *Defense Evasion* ya no existe y aparecen *Stealth* y *Defense Impairment*.
2. **Organización ficticia** (`data/org/fictional_org.yaml`): esquema propio simplificado inspirado en DeTT&CT, validado con pydantic. Contiene activos (criticidad, datos regulados, exposición), fuentes de datos con calidad 0–5, detecciones por técnica con puntaje 0–5 de la escala de detección de DeTT&CT, el contexto que el analista asignaría por técnica (`analyst_context`), la declaración de brechas pretendidas (`coverage_design`) y los IoC que la organización «ya conoce».
3. **Reportes de amenaza.** Tres escenarios (sección 3). Antes de dárselos al LLM se elimina el mapeo ATT&CK y todo ID de técnica o táctica.

### 1.2 El modelo (4 pasos)

| Paso | Componente | Tipo | Qué hace |
|---|---|---|---|
| 1 | `src/aem/step1_extract.py` | IA + código + analista | Gemini recibe el texto y devuelve, con esquema JSON fijo, una lista de técnicas: `technique_id`, `technique_name`, `evidence_quote` (cita textual). No hay campos de confianza, severidad ni prioridad. El código valida cada ID contra v19.2: los inexistentes, revocados, deprecados o mal formados se marcan `needs_review` y se muestran al analista (no se descartan en silencio). También verifica que la cita aparezca en el reporte. El analista acepta, quita o agrega IDs (modo interactivo) o, en experimentos, el modo `auto` acepta los válidos y excluye los `needs_review` (queda registrado). Se guardan por separado `extracted_raw` (lo que devolvió el LLM; base de las métricas) y `extracted_validated`. |
| 2 | `src/aem/step2_coverage.py` | Código | Para cada técnica validada busca su detección en el YAML y la clasifica en `cubierta`, `parcial` o `sin cobertura`. Determinístico. |
| 3 | `src/aem/step3_prioritize.py` | Analista + tabla | (a) El analista valida la cobertura del paso 2 (se guarda original, validada y motivo). (b) Árbol adaptado de SSVC v2.0: cobertura validada × criticidad del activo → acción; para técnicas de Acceso Inicial la exposición desplaza un nivel. (c) Revisión global: el script muestra la cadena en orden de la matriz y hace **una** pregunta al analista; la respuesta se guarda en `global_review.json`. (d) Agrupación por acción. Ninguna parte de este paso llama a un LLM. |
| 4 | `src/aem/step4_reference.py` | Código + IA (solo resumen) | Consulta en lote los datos STIX de las técnicas y arma cinco campos: resumen + enlace a attack.mitre.org (construido por código), mitigaciones (`M####` + nombre, sin recomendar ninguna), fuentes de datos, grupos y prevalencia (Red Canary 2026). La IA solo condensa la descripción de ATT&CK; si falla o produce lenguaje evaluativo ausente de la fuente, el campo dice `resumen no disponible`. |

**Salida** (`src/aem/output.py`): un CSV por amenaza (UTF-8 con BOM), una fila por técnica, con columnas fijas `technique_id, technique_name, tactics, coverage_validated, criticality, exposure, action, summary, source_link, mitigations, data_sources, groups, prevalence`, ordenado por acción (`Act`, `Attend`, `Track*`, `Track`) y dentro de cada acción por secuencia de ataque; más `global_review.json` y un registro de auditoría `run_record.json`. Un test falla si aparece una columna evaluativa nueva o si texto de urgencia del LLM llega al CSV.

**Garantía por arquitectura del principio «la IA no prioriza»:** los dos esquemas de salida del LLM tienen campos fijos no evaluativos; la acción se calcula en el paso 3 con una tabla editable (`data/ssvc_tree.yaml`) y datos del analista; los campos extra que devuelva el LLM se descartan y se cuentan como violación (indicador 5).

### 1.3 Preparación de los escenarios (`src/aem/reports.py`, `src/aem/scenarios.py`)

1. Conversión del HTML de CISA a texto (solo el cuerpo del boletín y su título).
2. Extracción del **mapeo de referencia** desde las tablas «MITRE ATT&CK Tactics and Techniques» → `data/reference_mappings/<escenario>.csv`, con la columna `valid_in_v19_2` calculada por código. Las filas cuyo ID es una táctica (`TA####`) se excluyen: la comparación es a nivel de técnica/sub-técnica.
3. Versión `stripped`: sin la sección del mapeo, sin la nota de versión de ATT&CK y sin ningún ID `T####`, `T####.###`, `TA####` del cuerpo (se quita el ID, la oración se conserva). Un test falla si algún `*_stripped.txt` contiene esos patrones.
4. Variante `mut` de cada `stripped` (`eval/make_variants.py`): mismos comportamientos, indicadores distintos (sección 2.6).

### 1.4 Evaluación (`eval/`, `aem eval`)

`eval/run_experiments.py` corre cada escenario × versión (`orig`, `mut`) × 5 corridas con el mismo pipeline de `aem run` en modo `auto`, guarda cada respuesta cruda y cada salida en `runs/<fecha>/…`, y calcula los cinco indicadores (`eval/metrics.py`). Produce tablas en CSV y Markdown (`runs/<fecha>/results/`) y dos hojas de revisión manual (`eval/review_sheets/`).

| Indicador | Definición implementada |
|---|---|
| 1. Precisión y exhaustividad del paso 1 | Sobre `extracted_raw` frente al mapeo de referencia (filas válidas en v19.2). Precisión = propuestas correctas / propuestas; exhaustividad = referencia identificada / referencia. A nivel de **sub-técnica exacta** y de **técnica padre**. Lista de omitidas y erróneas con su frecuencia en las corridas. |
| 2. Corrección del cruce de cobertura | El paso 2 se aplica a la **lista de referencia** (aísla el error del LLM) y se compara con `coverage_design`. Debe dar 100 %; otra cifra indica un error de programación. |
| 3. Persistencia | Modelo: % de técnicas de referencia con brecha (`parcial` o `sin cobertura`) cuyo ID exacto aparece en `extracted_raw`, en `orig` y en `mut`, y la razón mut/orig. Enfoque tradicional: IoC del reporte extraídos con expresiones regulares y comparados con los IoC conocidos; con ≥ 1 coincidencia reconoce todas las técnicas del escenario (100 %), si no, ninguna (0 %). |
| 4. Fidelidad de los resúmenes | Hoja de revisión manual (descripción original, resumen, `ok (si/no)`, `observación`) + chequeo automático (IDs o cifras ausentes de la fuente, más de 3 oraciones). |
| 5. Cumplimiento de los límites | Conteo automático de violaciones en toda salida de la IA: campos fuera del esquema y patrones evaluativos en español e inglés (`data/boundary_patterns.yaml`) que no estén en el texto fuente. Muestra aleatoria de 30 salidas para revisión manual. |

No hay indicador para el paso 3 ni para la revisión global: son criterio del analista.

---

## 2. Parámetros exactos

### 2.1 Modelo de lenguaje

| Parámetro | Valor |
|---|---|
| Proveedor | Google Gemini, capa gratuita |
| SDK | `google-genai` 2.31.0, `client.models.generate_content` |
| Modelo por defecto | `gemini-3.8-flash` (variable `GEMINI_MODEL`) |
| Modelo alternativo | `gemini-3.5-flash-lite` |
| ID exacto de la versión usada | se registra en cada respuesta (`model_version`, en `runs/llm_cache/` y `run_record.json`); **tomarlo de la corrida final** |
| Temperatura | 0 |
| Formato de salida | JSON con esquema (`response_mime_type = application/json`, `response_json_schema`) |
| Prompt de extracción | `src/aem/prompts/extract_v1.txt`, SHA-256 `950aafbfbcae093c37aa822069fbc6adae83b13631344bcd9603363c9acb6ec3` |
| Prompt de resumen | `src/aem/prompts/summary_v1.txt`, SHA-256 `8f199eae921a1064b44f197842a26489edd0ca4b36c2710f514fd668500cea1b` (máx. 3 oraciones, en inglés) |
| Límite de solicitudes | `GEMINI_RPM` = 10 por minuto (aproximado, no oficial): pausa mínima de 6 s |
| Reintentos | hasta 5 ante HTTP 429/5xx, espera exponencial 2, 4, 8, 16, 32 s |
| Caché | clave = SHA-256(modelo + prompt + parámetros + esquema + número de réplica); el número de réplica no se envía a la API |
| Registro por llamada | modelo, versión, fecha y hora UTC, temperatura, SHA-256 del prompt, réplica |
| Fragmentación | texto completo si ≤ 100 000 caracteres; si no, fragmentos de 30 000 con 2 000 de solapamiento, unidos por `technique_id` |

### 2.2 Datos y software

| Elemento | Valor |
|---|---|
| ATT&CK | Enterprise **v19.2**, `enterprise-attack-19.2.json`, SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4` |
| Python | ≥ 3.11 (desarrollo con 3.14.7) |
| Bibliotecas | `mitreattack-python` 6.3.1, `pydantic` 2.14.1, `typer` 0.27.3, `rich` 15.0.0, `PyYAML` 6.0.3, `pytest` 9.1.1 |
| Pruebas | 237 pruebas automatizadas; ninguna llama a la API real |

### 2.3 Diseño experimental

| Parámetro | Valor |
|---|---|
| Escenarios | 3 (Gunra, Interlock, Akira) |
| Versiones | 2 (`orig` = stripped, `mut` = IoC modificados) |
| Corridas por escenario × versión | **5** |
| Total de extracciones | 30 (si cada reporte cabe en un fragmento) |
| Resúmenes | 1 por técnica distinta (caché compartida, D-44) |
| Modo del analista en los experimentos | `auto` (criticidad y exposición predefinidas en `analyst_context`) |
| Estadísticos | media y desviación estándar muestral (n−1); porcentajes con 2 decimales |
| Muestra para revisión manual (indicador 5) | 30 salidas, semilla 20261017 |
| Estimación de llamadas | ≈ 110–150 (detalle en `docs/PLAN.md`), 20–35 min con `GEMINI_RPM = 10` |

### 2.4 Organización ficticia (borrador; brechas definidas por Sebas)

9 activos, 32 fuentes de datos, 56 detecciones y **78 técnicas** en `coverage_design` (todas las técnicas de referencia de los tres escenarios): 18 `cubierta`, 34 `parcial`, 26 `sin cobertura`. Activo por defecto de `analyst_context`: estaciones de trabajo (criticidad media, exposición interna).

### 2.5 Pasos 2 y 3

| Parámetro | Valor |
|---|---|
| Umbrales de cobertura | puntaje 0 o sin entrada → `sin cobertura`; 1–3 → `parcial`; 4–5 → `cubierta` |
| Sub-técnicas sin entrada propia | `no_inherit`: `sin cobertura` (no hereda del padre) |
| Tabla base (cobertura × criticidad baja/media/alta) | cubierta: Track/Track/Track* · parcial: Track/Track*/Attend · sin cobertura: Track*/Attend/Act |
| Ajuste por exposición (solo Acceso Inicial) | internet +1 nivel (tope Act), interna 0, aislada −1 (piso Track); orden Track < Track* < Attend < Act |

### 2.6 Variantes `mut` y enfoque tradicional

| Parámetro | Valor |
|---|---|
| Semilla de variantes | 20261017, combinada con el nombre del escenario |
| IPv4 de reemplazo | rangos de documentación **RFC 5737**: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Dominios de reemplazo | 10 letras aleatorias + TLD **`.invalid`** (RFC 2606); también para el host de las URL y el dominio de los correos |
| Hashes de reemplazo | hexadecimal aleatorio del mismo largo (MD5 32, SHA-1 40, SHA-256 64) y mismas mayúsculas |
| Comportamiento | resto del texto idéntico byte a byte (verificado por prueba); diff y tabla de reemplazos guardados |
| IoC reconocidos | MD5, SHA-1, SHA-256, IPv4, URL, correo y dominio; IPv4/URL/dominio/correo solo si están «defanged» (`[.]`, `hxxp`) |
| Reemplazos realizados | Gunra: 17 IPv4, 4 dominios, 4 correos, 4 SHA-256 · Interlock: 35 SHA-256, 3 SHA-1 · Akira: al colocar el texto |
| IoC conocidos por la organización | 50 % de los IoC únicos de `orig` (redondeo hacia arriba), semilla 20261017: Gunra 15 de 29, Interlock 19 de 38 |
| Umbral de reconocimiento | ≥ 1 coincidencia |

---

## 3. Escenarios y mapeos de referencia

| Escenario | Fuente | Fecha | Técnicas de referencia (válidas en v19.2) | Filas de táctica excluidas |
|---|---|---|---|---|
| Gunra | CISA/FBI #StopRansomware AA26-222A | 10/08/2026 | 36 (36) | TA0009 |
| Interlock | CISA #StopRansomware AA25-203A | 22/07/2025 | 25 (25) | TA0005, TA0006, TA0011 |
| Akira | The DFIR Report, «From Bing search to ransomware: BumbleBee and AdaptixC2 deliver Akira» | 29/06/2026 | 38 (38) | — |

En total, 78 técnicas distintas. El boletín de Interlock usaba ATT&CK v17; sus 25 IDs siguen siendo válidos en v19.2. El texto de Akira no se incluye en el repositorio (derechos de autor); su caché, sus salidas y sus citas quedan en carpetas ignoradas por git (D-69).

---

## 4. Decisiones (`docs/DECISIONS.md`) y su estado

«Técnica» = decisión de implementación sin etiqueta de confirmación (informativa o derivada directamente de la especificación).

| ID | Decisión | Estado |
|---|---|---|
| D-01 | Ubicación del repositorio (disco Info, carpeta Github) | Técnica |
| D-02 | Archivo `enterprise-attack-19.2.json` con checksum | Técnica |
| D-03 | `data_sources` = componentes de datos alcanzados por las estrategias de detección (v18+); columna conserva el nombre; el YAML usa nombres propios porque DeTT&CT es anterior a este cambio | **PENDIENTE DE CONFIRMAR** (Sebas verifica contra la documentación de v19) |
| D-04 | SDK `google-genai` y forma de pedir JSON con esquema | Técnica |
| D-10 | Limpieza de reportes: sección del mapeo, nota de versión y todo ID; test de garantía | **CONFIRMADA** (2026-10-17) |
| D-11 | Fragmentación de reportes largos | PENDIENTE DE CONFIRMAR |
| D-12 | Réplica en la clave de caché | Técnica |
| D-13 | Validación de la cita textual (advertencia `quote_not_found`) | Técnica |
| D-20 | Umbrales de cobertura sobre la escala de DeTT&CT | PENDIENTE DE CONFIRMAR |
| D-21 | Sub-técnicas sin entrada propia: no heredan | PENDIENTE DE CONFIRMAR |
| D-22 | Organización ficticia y `coverage_design` como verdad del indicador 2 | **CONFIRMADA** (2026-10-17): las brechas las define Sebas, el borrador es de Claude |
| D-30 | Tabla SSVC adaptada | PENDIENTE DE CONFIRMAR |
| D-31 | Activo por defecto en `analyst_context` | PENDIENTE DE CONFIRMAR |
| D-32 | Revisión global sin responder en modo `auto` | Técnica |
| D-40 | Limpieza de la descripción de ATT&CK antes de resumir | Técnica |
| D-41 | Filtro de lenguaje evaluativo en resúmenes (comparado con la fuente) | PENDIENTE DE CONFIRMAR |
| D-42 | Formato de prevalencia; sin herencia del padre | Técnica |
| D-43 | Grupos: solo `intrusion-set` con relación directa | Técnica |
| D-44 | Un resumen por técnica (caché compartida) | Técnica (pedido de Sebas) |
| D-45 | Resúmenes en inglés | **CONFIRMADA** (2026-10-17) |
| D-50 | Orden de filas del CSV | Técnica |
| D-51 | Separador `; ` y listas vacías como `sin dato disponible` | Técnica |
| D-52 | Archivos de salida de `aem run` | Técnica |
| D-60 | Akira: 38 técnicas | **CONFIRMADA** (2026-10-17) |
| D-61 | Filas de táctica (TA0005, TA0006, TA0009, TA0011) fuera de la referencia | **CONFIRMADA** (2026-10-17) |
| D-62 | Enfoque tradicional: 50 % de IoC conocidos, ≥ 1 coincidencia | PENDIENTE DE CONFIRMAR |
| D-63 | Reglas de extracción de IoC (defang obligatorio, correos, exclusiones) | PENDIENTE DE CONFIRMAR |
| D-64 | Definición del indicador 3 del modelo | Técnica |
| D-65 | Definición de violación (indicador 5) | PENDIENTE DE CONFIRMAR |
| D-66 | Construcción de la variante `mut` | PENDIENTE DE CONFIRMAR |
| D-67 | Cálculo de métricas (repetidos, corridas fallidas, n−1) | PENDIENTE DE CONFIRMAR |
| D-68 | Chequeo automático del indicador 4 | PENDIENTE DE CONFIRMAR |
| D-69 | Material con derechos de autor fuera de git | Técnica |

---

## 5. Limitaciones conocidas

1. **Validez externa limitada:** tres escenarios de ransomware y una sola organización ficticia.
2. **El paso 3 no se valida de forma independiente:** en la simulación lo ejecuta el autor con criticidad y exposición definidas de antemano (`analyst_context`, modo `auto`); la revisión global queda sin responder.
3. **Brechas definidas por el autor:** el indicador 2 verifica la implementación del paso 2, no la calidad del perfil de la organización.
4. **Adaptaciones propias sin validación externa:** umbrales sobre la escala de DeTT&CT, política de sub-técnicas, árbol SSVC aplicado a técnicas adversarias (SSVC fue diseñado para vulnerabilidades).
5. **Enfoque tradicional simplificado:** una coincidencia de IoC basta para «reconocer» todas las técnicas; los IoC conocidos son una fracción fija de los del propio reporte. En `mut` no hay coincidencias por construcción, así que su 0 % es esperado y lo que el indicador 3 compara es la persistencia del modelo frente a esa referencia.
6. **No determinismo del LLM** aun con temperatura 0; se mitiga con 5 corridas y se reporta la dispersión. Los resultados dependen del modelo y la fecha (se registran).
7. **Mapeo de referencia como verdad:** las tablas de CISA y la sección de The DFIR Report son el criterio de corrección; una técnica descrita en el texto pero ausente de esas tablas cuenta como «errónea».
8. **Resúmenes una vez por técnica:** los indicadores 4 y 5 los evalúan una vez, no cinco; el chequeo automático de fidelidad es aproximado y la revisión manual es la medida principal.
9. **Lista de patrones evaluativos** finita (español e inglés); se complementa con revisión manual de una muestra.
10. **Fuentes de datos (D-03):** en v19 se derivan de las estrategias de detección; no se cruzan automáticamente con las fuentes declaradas en el YAML.
11. **Prevalencia:** la plantilla de Red Canary 2026 está vacía hasta que Sebas la complete; mientras tanto la columna dice `sin dato disponible`.
12. **Reproducibilidad de Akira:** su caché no se publica (derechos de autor); quien clone el repositorio reproduce Gunra e Interlock en modo demo, no Akira.
13. **Capa gratuita de Gemini:** los límites no son oficiales y pueden cambiar.
14. **Reportes de CISA en línea:** el sitio puede cambiar; el repositorio conserva el texto convertido usado en la tesis.

---

## 6. Pendientes de Sebas antes de la corrida final

- Colocar el texto de Akira (`docs/report_preparation.md`) y ejecutar `aem prepare-reports` y `aem make-variants`.
- Llenar `data/prevalence/red_canary_2026.csv`.
- Revisar `coverage_design` y las decisiones **PENDIENTE DE CONFIRMAR**.
- Ejecutar `aem eval` con la API key, completar las hojas de `eval/review_sheets/` y subir `runs/` (sin `runs/llm_cache_private/` ni `runs/*/private/`, que git ya ignora).
- Confirmar la redacción de la declaración de uso de IA en el README.
