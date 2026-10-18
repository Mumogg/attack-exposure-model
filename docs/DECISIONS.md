# Registro de decisiones

Cada decisión tomada sin confirmación explícita de Sebas lleva la etiqueta **PENDIENTE DE CONFIRMAR**. Cuando Sebas la confirme o la cambie, se reemplaza por **CONFIRMADA (fecha)**.

## Entorno y datos

### D-01. Ubicación del repositorio
`/run/media/sebas/8b2a925b-…/Github/attack-exposure-model` (disco `Info`, 1 TB, carpeta `Github` con mayúscula). Era el único volumen con esa etiqueta. Informativa.

### D-02. Archivo de ATT&CK
`enterprise-attack-19.2.json` existe en `mitre-attack/attack-stix-data` con ese nombre exacto. Su SHA-256 se guarda en `data/attack/CHECKSUMS.sha256` y `aem fetch-data` lo verifica. Informativa.

### D-03. Campo `data_sources` del paso 4 — **PENDIENTE DE CONFIRMAR (Sebas lo verifica contra la documentación de ATT&CK v19)**
En ATT&CK v18+ las técnicas ya no tienen el campo `x_mitre_data_sources`; la detección se modela como *estrategia de detección → analíticas → componentes de datos*. El campo `data_sources` de la salida lista los **nombres de los componentes de datos** (p. ej. `Process Creation`, `Logon Session Creation`) que alcanzan la técnica por esa cadena. Los objetos `x-mitre-data-source` de v19 están todos deprecados. En el CSV la columna conserva el nombre `data_sources` (instrucción de Sebas, 2026-10-17).

**Nota sobre DeTT&CT:** el modelo de datos de DeTT&CT, en el que se inspira el YAML de la organización, es anterior a este cambio de ATT&CK (usa las *data sources* clásicas). Por eso el YAML declara sus fuentes con nombres propios (`data_sources[].name`, aquí escritos como componentes de datos de v19 para que sean legibles), que no se cruzan automáticamente con la columna `data_sources` del paso 4: son dos cosas distintas (lo que la organización registra frente a lo que ATT&CK asocia a la técnica).

### D-04. SDK de Gemini
Paquete `google-genai` 2.x. Se usa `client.models.generate_content` con `GenerateContentConfig(temperature=0, response_mime_type="application/json", response_json_schema=…)`, verificado por introspección del SDK instalado (2.31.0). La documentación vigente muestra además una API nueva (`client.interactions`), que no se usa porque `generate_content` sigue disponible y permite fijar `temperature`. La existencia del modelo se verifica con `client.models.get`. Modelos `gemini-3.8-flash` y `gemini-3.5-flash-lite` figuran como estables en https://ai.google.dev/gemini-api/docs/models (consulta del 2026-10-17).

## Paso 1 — Extracción

### D-10. Limpieza de los reportes antes de dárselos al LLM — **CONFIRMADA (2026-10-17)**
Los boletines de CISA no solo tienen la sección «MITRE ATT&CK Tactics and Techniques»: también etiquetan cada párrafo en línea (`[T1190]`, `[TA0001]`) y una nota inicial dice qué versión de ATT&CK usan. Si solo se quitara la sección, la extracción copiaría las etiquetas. Por eso el texto `_stripped` elimina: (1) la sección completa del mapeo ATT&CK (y sus tablas); (2) **todo** ID de técnica, sub-técnica o táctica que aparezca en el cuerpo (`T####`, `T####.###`, `TA####`, entre corchetes o no), quitando solo el ID y dejando la oración legible; (3) la nota que remite a la tabla de ATT&CK. Lo mismo se aplica al texto de Akira (The DFIR Report) que coloca Sebas. Un test (`tests/test_reports.py`) falla si algún `*_stripped.txt` contiene `\bT\d{4}(\.\d{3})?\b` o `\bTA\d{4}\b`. El detalle de cada tipo de sección o patrón eliminado está en `docs/report_preparation.md`.

### D-11. Fragmentación de reportes largos — **PENDIENTE DE CONFIRMAR**
Por defecto el reporte se envía completo si tiene ≤ `chunk_max_chars` caracteres (100 000 en `data/model_config.yaml`; los tres reportes están por debajo). Si lo supera, se divide en fragmentos de `chunk_size_chars` con `chunk_overlap_chars` de solapamiento, cortando en saltos de párrafo, y se unifican por `technique_id` conservando la primera cita.

### D-12. Réplicas y caché
La clave de caché es SHA-256 de (modelo + prompt + parámetros + esquema + número de réplica). El número de réplica no se envía a la API: solo separa las 5 corridas de cada combinación para que no se reutilice la misma respuesta. `aem run` usa la réplica 0.

### D-13. Validación de la cita textual
Además de validar el ID contra ATT&CK, el código comprueba que `evidence_quote` aparezca en el reporte (normalizando espacios y comillas). Si no aparece, se marca `quote_not_found` como advertencia para el analista; no cambia las métricas, que usan la lista cruda.

## Paso 2 — Cobertura

### D-20. Umbrales de cobertura — **PENDIENTE DE CONFIRMAR**
Adaptación propia de la escala de detección de DeTT&CT: `score` 0 o sin entrada → `sin cobertura`; 1–3 → `parcial`; 4–5 → `cubierta`. Configurables en `data/model_config.yaml` (`coverage.partial_min`, `coverage.covered_min`).

### D-21. Sub-técnicas sin entrada propia — **PENDIENTE DE CONFIRMAR**
Política `subtechnique_policy` en `data/model_config.yaml`. Por defecto `no_inherit`: una sub-técnica sin entrada propia queda `sin cobertura`, aunque el padre tenga detección. Alternativa `inherit_parent`: toma el puntaje del padre y lo registra como heredado. Una técnica padre **nunca** agrega la cobertura de sus sub-técnicas.

### D-22. Borrador de la organización ficticia — **CONFIRMADA como verdad de referencia del indicador 2 (2026-10-17): las brechas las define Sebas; el borrador es de Claude**
`data/org/fictional_org.yaml` es un borrador. Cubre las técnicas de referencia de los tres escenarios con una mezcla de cubiertas, parciales y sin cobertura. La sección `coverage_design` declara la brecha que se pretende para cada técnica; el indicador 2 compara el paso 2 contra esa declaración.

## Paso 3 — Priorización

### D-30. Tabla SSVC adaptada — **PENDIENTE DE CONFIRMAR**
`data/ssvc_tree.yaml` contiene la propuesta inicial de `CLAUDE.md` §5 sin cambios.

### D-31. Activo por defecto en `analyst_context` — **PENDIENTE DE CONFIRMAR**
`analyst_context` tiene `default_asset_id` y una lista `entries` (`technique_id`, `asset_id`). En modo `auto`, una técnica sin entrada propia usa el activo por defecto, y el registro del analista lo indica. Criticidad y exposición se leen del activo.

### D-32. Revisión global en modo `auto`
El script nunca responde la pregunta global. En modo `auto`, `global_review.json` queda con `answer: null` y `mode: "auto"`, explícitamente sin responder.

## Paso 4 — Referencia

### D-40. Limpieza de la descripción antes de resumir
Antes de enviarla al LLM, el código quita de la descripción de ATT&CK las marcas `(Citation: …)` y convierte los enlaces Markdown `[texto](url)` en `texto`. La hoja de revisión del indicador 4 muestra esta descripción limpia como fuente.

### D-41. Filtro de lenguaje evaluativo en resúmenes — **PENDIENTE DE CONFIRMAR**
Si un resumen contiene un patrón evaluativo (lista en `data/boundary_patterns.yaml`) que **no** aparece en la descripción fuente, el CSV muestra `resumen no disponible` y la violación queda registrada (cuenta para el indicador 5). Se compara con la fuente porque algunas descripciones de ATT&CK usan palabras como «critical» de forma descriptiva.

### D-42. Formato de prevalencia
Si la técnica figura en `red_canary_2026.csv`: `Red Canary 2026: puesto <rank>` (+ `source_note` si existe). Si no: `sin dato disponible`. No se hereda la prevalencia del padre.

### D-43. Grupos
Solo grupos (`intrusion-set`) no revocados ni deprecados con relación `uses` directa hacia la técnica. No incluye campañas ni software.

### D-44. Caché de resúmenes por técnica
El resumen del paso 4 depende solo de la descripción de ATT&CK, no del escenario. Por eso todas las llamadas de resumen usan la réplica 0: hay **un resumen por técnica**, compartido por todos los escenarios, versiones y corridas. Las 5 corridas repiten solo la extracción del paso 1. Consecuencia para los indicadores 4 y 5: los resúmenes se evalúan una vez por técnica, no cinco.

### D-45. Idioma de los resúmenes — **CONFIRMADA (2026-10-17)**
Los resúmenes del paso 4 se generan en inglés, el idioma de la descripción fuente de ATT&CK, para que los chequeos de fidelidad (indicador 4) y de límites (indicador 5) comparen textos en el mismo idioma. Se documenta en el README.

## Salida

### D-50. Orden de filas
Por acción (`Act`, `Attend`, `Track*`, `Track`). Dentro de cada acción, por el índice de táctica más temprano en la matriz (si una técnica tiene varias tácticas, cuenta la primera en el orden de la matriz). A igual táctica se ordena por `technique_id` solo para que el orden sea determinístico; no expresa prioridad.

### D-51. Listas en celdas
Las celdas con varios valores (`tactics`, `mitigations`, `data_sources`, `groups`) usan `; ` como separador. Una lista vacía se escribe `sin dato disponible`.

### D-52. Archivos de salida de `aem run`
En la carpeta `--out`: `<reporte>_exposure.csv` (UTF-8 con BOM), `global_review.json` y `run_record.json` (auditoría: `extracted_raw`, `extracted_validated`, acciones del analista, cobertura original y validada, registro de cada resumen y metadatos: modelo, temperatura, versión de ATT&CK, SHA-256 del reporte y de los prompts). Si el paso 1 no produce ninguna técnica válida, el programa se detiene con un error claro y guarda igualmente `run_record.json`.

## Evaluación

### D-60. Mapeo de referencia de Akira — **CONFIRMADA (2026-10-17)**
Se usan las **38 técnicas** que muestra la sección «MITRE ATT&CK» del reporte (consultada el 2026-10-17). El «32» de `CLAUDE.md` era un dato errado y se ignora.

### D-61. Filas de táctica en las tablas de CISA — **CONFIRMADA (2026-10-17)**
Las tablas de CISA incluyen a veces un ID de táctica (p. ej. `TA0009` Collection) en lugar de una técnica. Esas filas no entran en el mapeo de referencia, porque no son técnicas; se listan en `docs/report_preparation.md`. En concreto, las filas TA0005, TA0006, TA0009 y TA0011 quedan fuera: la comparación es a nivel de técnica/sub-técnica.

### D-62. Enfoque tradicional (IoC) — **PENDIENTE DE CONFIRMAR**
`aem make-variants` toma, con semilla fija (`baseline.seed` = 20261017), una fracción `baseline.known_ioc_fraction` (por defecto 0,5, redondeo hacia arriba) de los IoC **únicos** de la versión `orig` (stripped) de cada escenario y los escribe en `data/org/known_iocs_generated.yaml`, que el YAML de la organización referencia con `known_iocs_file`. Los IoC conocidos se comparan contra **todos** los escenarios (la organización «los conoce», sin importar de qué boletín vinieron). Si hay ≥ `baseline.min_matches` (por defecto 1) coincidencias por tipo y valor normalizado, el enfoque tradicional «reconoce» la amenaza y con ella todas las técnicas de referencia del escenario; si no, ninguna. Es una simplificación deliberada y configurable.

Nota: si Sebas coloca el texto de Akira y ejecuta `aem make-variants`, el archivo generado incluirá IoC de ese reporte (valores de indicadores, no texto del reporte). Sebas decide si se versiona.

### D-63. Extracción de IoC y dominios de referencia — **CONFIRMADA (2026-10-17)**
Tipos reconocidos (`eval/baseline_ioc.py`): MD5, SHA-1, SHA-256, SHA-512 (hexadecimal de 32/40/64/128 caracteres aislado), IPv4, URL, correo electrónico y dominio, más los tipos de D-70 (ID de qTox y cuentas). Reglas:
- `ioc.require_defang: true` (por defecto): IPv4, URL, dominios y correos solo cuentan si están escritos «defanged» (`[.]`, `[:]`, `hxxp`), que es como CISA y The DFIR Report publican los IoC. Así los enlaces de referencia de la sección «Notes» (Trend Micro, Talos, cisecurity.org…) no se toman por IoC. Los hashes no requieren esa marca.
- Con `require_defang: false`, un dominio sin `[.]` ni esquema solo cuenta si su TLD está en `ioc.domain_tlds`, para no confundir nombres de archivo (`main.exe`, `secretsdump.py`) con dominios.
- Los dominios institucionales (`cisa.gov`, `fbi.gov`, `mitre.org`…, lista `ioc.excluded_domains`) y sus subdominios se excluyen.
- En un correo, el IoC es la dirección completa (p. ej. `x@proton[.]me`), no el dominio del proveedor.
- Una URL ocupa su tramo completo: un hash dentro de una URL de referencia no cuenta por separado.
- Auditoría contra la sección de IoC de cada boletín (2026-10-17). Gunra: la sección lista 34 IoC únicos (17 IPv4, 4 dominios, 4 correos, 4 SHA-256, 4 ID de qTox, 1 cuenta). Sin D-70 se extraían 29; los 5 perdidos (4 qTox y la cuenta `forticloud-sync`) se perdían por tipo no reconocido, **no** por exigir defang. Interlock: la sección lista 38 (35 SHA-256, 3 SHA-1) y se extraen los 38. Ningún IoC extraído queda fuera de la sección. Con `require_defang: false` solo se agregarían enlaces de referencia de las notas (5 en Gunra, 8 + `soc@cisecurity.org` en Interlock), que no son IoC; por eso se mantiene `true`.
- Resultado actual (con D-70): Gunra 34 IoC únicos, Interlock 38.

### D-64. Indicador 3 del modelo
Denominador: técnicas de la referencia (válidas en v19.2) cuya cobertura según el paso 2 sobre el YAML es `parcial` o `sin cobertura`. Numerador: las que aparecen con ID exacto en `extracted_raw`. Se reporta el porcentaje en `orig` y en `mut` (media y desviación estándar de las 5 corridas) y la razón de medias mut/orig. Para el enfoque tradicional el denominador son todas las técnicas de referencia y el resultado es 100 % o 0 % (determinístico, D-62).

### D-65. Indicador 5 — **PENDIENTE DE CONFIRMAR**
Una violación es (a) un campo extra no previsto por el esquema en la salida del LLM (paso 1, o claves distintas de `summary` en el paso 4), o (b) un patrón evaluativo (`data/boundary_patterns.yaml`) en el texto generado que **no** aparece en su fuente: para `evidence_quote` y `technique_name` del paso 1, la fuente es el reporte más el nombre oficial de ATT&CK; para los resúmenes, la descripción de ATT&CK. Se cuenta cada patrón una vez por campo. El paso 1 se resume por escenario × versión (total, media y desviación por corrida); los resúmenes, una vez por técnica (D-44). La revisión manual usa una muestra aleatoria (`experiment.manual_sample_size` = 30, semilla `experiment.sample_seed`) de citas y resúmenes únicos, en `eval/review_sheets/<corrida>_indicator5_sample.csv`.

### D-66. Variante `mut` (`eval/make_variants.py`) — **CONFIRMADA (2026-10-17)**
Se aplica sobre el texto `stripped` (el que recibe el LLM). Cada IoC detectado según D-63 se reemplaza; todo lo demás queda idéntico byte a byte (test que revierte el mapeo y recupera el original).
- Hashes → hexadecimal aleatorio del mismo largo y las mismas mayúsculas/minúsculas.
- IPv4 → direcciones de los rangos de documentación RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), sin repetir.
- Dominios (también el host de una URL y el dominio de un correo) → nombre aleatorio de 10 letras con TLD `.invalid` (RFC 2606). Se conserva la ruta de la URL (salvo los hashes que contenga); la parte local del correo también se reemplaza (ver abajo).
- Se conserva el estilo «defanged» en la misma posición (`45.61.136[.]10` → `198.51.100[.]23`).
- Un mismo IoC recibe siempre el mismo reemplazo dentro del reporte.
- Semilla: `variants.seed` = 20261017, combinada con el nombre del escenario. Por cada escenario se guardan `<reporte>_mut_stripped.txt`, `<reporte>_mut.diff` y `<reporte>_mut_log.json` (semilla, tabla de reemplazos con número de apariciones).
- (2026-10-17, ajustado tras la revisión independiente, `docs/REVISION_EVAL.md` A1, A5–A7) Alcance para que ningún IoC del original sobreviva:
  - Los IoC se detectan con las mismas reglas que el enfoque tradicional (D-63, `variants.require_defang: true`). Además se reemplaza **cada mención** de un IoC detectado aunque esté escrita sin defang (p. ej. `datapub[.]news` en la tabla y `datapub.news` en una oración; también el host de una URL IoC).
  - Los tokens que solo parecen IoC sin defang (nombres de archivo como `backdoor.pl`, servicios como `mega.io`, versiones `5.1.2.3`, enlaces de referencia) **no** se tocan, porque son comportamiento o citas. Se listan en el log (`plain_candidates_kept`) y en la consola para revisarlos en el diff. En Gunra son 4 enlaces de las notas; en Interlock, 8 enlaces y `soc@cisecurity.org`.
  - Los hashes dentro de cualquier URL, incluidas las de referencia (la ruta de VirusTotal en Gunra), se reemplazan por el mismo hash nuevo.
  - En un correo se reemplazan la parte local y el dominio (antes se conservaba la parte local).
  - Qtox → caracteres aleatorios del mismo largo; cuentas → `acct-` + 8 letras.
  - `check_variant` busca en `mut` cada IoC del original, el host de cada URL IoC y toda secuencia de ≥ 32 hexadecimales, en forma original o refanged y sin distinguir mayúsculas. Si queda alguno, `aem make-variants` falla indicando el valor y la línea (`VariantLeak`). Hay un test sobre cada escenario preparado.
  - El log agrupa por (tipo, valor) con todas sus grafías y el número de apariciones. Resultado: Gunra 34 IoC distintos reemplazados (38 apariciones), Interlock 38 (40), es decir, todos los de la sección de IoC de cada boletín.

### D-67. Cálculo de los indicadores 1 y generales — **CONFIRMADA (2026-10-17)**
- Las métricas usan `extracted_raw` tal como lo devolvió el LLM. Un ID repetido cuenta una vez; un ID inexistente, revocado o mal formado cuenta como propuesta errónea.
- Nivel exacto: se compara el ID completo (sub-técnica exacta). Nivel padre: cada ID se reduce a su técnica padre (`T1059.001` → `T1059`) en ambas listas y se comparan los conjuntos.
- Precisión = correctas / propuestas (indefinida si no hubo propuestas); exhaustividad = identificadas / referencia.
- Una corrida cuya respuesta no es utilizable (no es JSON o no cumple el esquema) se registra como fallida (`failed_runs`). Una respuesta vacía es válida (exhaustividad 0, precisión indefinida) y se cuenta aparte en `empty_runs`.
- (2026-10-17) Para no ocultar fallas, la tabla `runs` informa por escenario × versión `runs_total`, `runs_valid`, `failed_runs`, `empty_runs` y `failure_reasons` (`r<k>: <motivo>`, el texto completo queda en `results.json` y en `run_error.json`). Cada media y desviación de los indicadores 1, 3 (modelo) y 5 se calcula dos veces: `_valid`, solo con corridas válidas, y `_fail0`, contando cada corrida fallida como 0 (precisión, exhaustividad y persistencia 0). La columna `failed_runs` aparece en las tablas CSV y Markdown de esos indicadores. **Media principal (confirmada por Sebas, 2026-10-17):** en los indicadores 1 y 3 (modelo), `_fail0`; `_valid` es secundaria. En las tablas, las columnas `_fail0` van primero y el título lo indica. En el indicador 5 se reportan las dos con el mismo peso, y el título de la tabla avisa que contar una falla como 0 violaciones favorece al modelo.
- Media y desviación estándar **muestral** (n−1) sobre las corridas; los porcentajes se redondean a 2 decimales.
- Un error de la API (cuota, modelo inexistente, falta de clave, caché ausente en `--demo`) detiene `aem eval` con un mensaje claro; al repetirlo, la caché evita repetir lo ya obtenido.
- Las tablas quedan en `runs/<corrida>/results/` (o `results_FAKE/`, D-71) (CSV con BOM, `results.md`, `results.json`) y las salidas de cada corrida en `runs/<corrida>/<escenario>/<versión>/r<k>/`.

### D-68. Indicador 4 — chequeo automático — **CONFIRMADA (2026-10-17)**
Hoja de revisión manual: `eval/review_sheets/<corrida>_indicator4_summaries.csv`, una fila por técnica resumida, con la descripción fuente (limpia, D-40), el resumen, el estado y columnas vacías `ok (si/no)` y `observación`. El chequeo automático marca un resumen como no conforme si contiene (a) un identificador de ATT&CK (`T`, `TA`, `M`, `G`, `S`, `C`, `DS`, `DC` + 4 dígitos) o (b) una cifra que no aparece en la descripción fuente, o (c) más oraciones que `summary.max_sentences`. IDs y cifras se comparan como tokens, no como subcadenas (`3` no se da por presente porque la fuente diga `2023`; `1,000` = `1000`), y las abreviaturas `e.g.`, `i.e.`, `etc.`, `vs.`, `U.S.` no cuentan como fin de oración (revisión A3, A4). Es una aproximación; la medida de fidelidad es la revisión manual de Sebas.

### D-70. Tipos de IoC adicionales: qTox y cuentas — **CONFIRMADA (2026-10-17)**
Para que el enfoque tradicional sea una comparación justa, reconoce todo lo que los propios boletines listan como IoC. La auditoría de D-63 mostró que en Gunra se perdían 5 de 34 por tipo no reconocido. Se agregan, configurables en `ioc.extra_types` (ambos activos por defecto; `[]` vuelve al comportamiento anterior):
- `qtox`: ID de qTox, 76 caracteres alfanuméricos aislados con al menos `ioc.qtox_min_hex` (70) hexadecimales. La tolerancia existe porque CISA publicó uno con una errata (`…923AS199…`); se compara en minúsculas.
- `account`: valores de las columnas de tablas cuyo encabezado está en `ioc.account_columns` (`Username`, `User Account`, `Account Name`) y cada mención de ese valor en el texto (palabra completa, sin distinguir mayúsculas).
Se excluyen las cuentas genéricas o integradas (`ioc.generic_accounts`: administrator, admin, root, guest, system, krbtgt, defaultaccount, user), porque describen comportamiento (T1078.001/.003) y no al actor (revisión A2).
Con esto Gunra pasa de 29 a 34 IoC (los 34 de la sección) y la organización «conoce» 17 (antes 15). Interlock no cambia (38; conocidos 19).

### D-71. Resultados con un LLM simulado: siempre «FAKE»
Las pruebas usan transportes simulados en lugar de la API. Para que esos resultados nunca se confundan con los reales:
- cada respuesta guarda en la caché su `source`: `gemini-api` solo si vino del transporte real del SDK (`GenaiTransport`, comprobación de tipo exacta); si no, `fake:<clase>`. Una entrada de caché sin `source` cuenta como `desconocida`, no como real;
- una corrida o un experimento es real solo si **todas** sus respuestas (incluidas las leídas de la caché o en `--demo`) son `gemini-api`;
- si no lo es: las salidas de `aem run` y de cada corrida llevan el prefijo `FAKE_`, las tablas de `aem eval` van a `runs/<corrida>/results_FAKE/` (nunca a `results/`) con prefijo `FAKE_` y un encabezado «FAKE» en `results.md`, y las hojas de revisión llevan el prefijo `FAKE_`; la consola lo avisa;
- toda fila de toda tabla lleva `llm_source`, `model`, `model_version`, `run_date` y `prompt_templates_sha256` (SHA-256 de `extract_v1.txt` y `summary_v1.txt`).

### D-72. Versión `anon` (nombres de la amenaza anonimizados) — **PENDIENTE DE CONFIRMAR**
Pedida por Sebas (2026-10-17) para controlar la limitación C2: `mut` conserva los nombres, y el LLM podría reconocer la amenaza por su nombre.
- `anon` = todo lo de `mut` (D-66) + los nombres propios de la amenaza reemplazados de forma consistente por nombres genéricos, según `data/anon_names.yaml`.
- **Se reemplazan:**
  - el actor o grupo y sus alias;
  - la familia de ransomware;
  - el malware que nombra el reporte (troyanos, loaders, ladrones de información), incluidas las familias relacionadas que permitirían reconocer la amenaza (Conti en Gunra, Rhysida en Interlock).
- **No se reemplazan:**
  - herramientas legítimas o de uso general: PowerShell, RDP, AnyDesk, PsExec, Impacket, RClone, FileZilla y también Cobalt Strike, herramienta comercial de uso amplio;
  - nombres de técnicas (ClickFix);
  - CVE, nombres de archivo (`R3ADM3.txt`, `conhost.exe`) y extensiones (`.ENCRT`);
  - el comportamiento descrito.
- **Cómo se reemplaza:**
  - sin distinguir mayúsculas y en todo el texto (prosa, tablas y enlaces); en un enlace, el espacio del nombre también se busca como guion;
  - nunca dentro de otra palabra: «Conti» no toca «continually»;
  - si dos nombres se solapan, gana el más largo («Interlock RAT» antes que «Interlock»).
- **Listas actuales:**
  - **Gunra:** Gunra → ActorX, Golden Community → ActorY, Conti → RansomwareW. Total: 94 reemplazos.
  - **Interlock:** Interlock → ActorX, Interlock RAT → RatX, NodeSnake (RAT) → RatY, Rhysida → RansomwareW, Lumma (Stealer) → StealerX, Berserk Stealer → StealerY, SystemBC → MalwareX, DarkGate → MalwareY. Total: 82 reemplazos.
  - **Akira:** Akira → ActorX, BumbleBee → LoaderX, AdaptixC2 / Adaptix C2 / Adaptix → C2FrameworkX. Esta lista sale **solo del título**, porque el texto no está en el repositorio: Sebas debe completarla al colocar el texto (RUNBOOK, paso c). Que AdaptixC2 se reemplace y Cobalt Strike no es una decisión de criterio: AdaptixC2 aparece en el título y es poco común, mientras que Cobalt Strike es de uso general.
- **Archivos por escenario:** `<reporte>_anon_stripped.txt`, `<reporte>_anon.diff` (frente al `orig`) y `<reporte>_anon_log.json` (apariciones de cada nombre). Los de Akira quedan ignorados por git (`data/reports/akira_dfir_2026*`).
- **Verificación:** `check_anon` y `check_variant` hacen fallar `aem make-variants`, indicando la línea, si algún nombre o IoC del original sobrevive. Hay un test por escenario preparado.
- **Evaluación:** `aem eval` corre `orig`, `mut` y `anon`. El indicador 1, el indicador 3 (modelo, con `persistence_anon_over_orig`) y el indicador 5 incluyen `anon`. El enfoque tradicional se reporta igual que en `mut`: 0 % por construcción.

### D-69. Material con derechos de autor fuera de git (Akira)
La caché del LLM guarda el prompt completo, que incluye el texto del reporte, y las salidas de cada corrida guardan citas textuales (`evidence_quote`). Como `runs/` se versiona, para el escenario marcado `copyrighted: true` en `data/scenarios.yaml` (Akira, The DFIR Report):
- las llamadas del paso 1 usan una caché aparte, `runs/llm_cache_private/` (ignorada por git); los resúmenes del paso 4 (texto de ATT&CK) siguen en la caché pública;
- las salidas de sus corridas van a `runs/<corrida>/private/akira/…` y su parte de la muestra del indicador 5 a `eval/review_sheets/private/` (ambas ignoradas);
- `aem run` detecta el reporte de Akira y avisa que no se suba la carpeta de salida;
- en `aem eval --demo` sin caché privada (cualquier persona que clone el repositorio), Akira se omite con el aviso «sin caché privada» y el resto se reproduce;
- las tablas de resultados (`runs/<corrida>/results/`) solo contienen IDs, cifras y nombres de ATT&CK, y sí se versionan.
