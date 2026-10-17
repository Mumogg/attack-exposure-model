# Registro de decisiones

Cada decisión tomada sin confirmación explícita de Sebas lleva la etiqueta **PENDIENTE DE CONFIRMAR**. Cuando Sebas la confirme o la cambie, se reemplaza por **CONFIRMADA (fecha)**.

## Entorno y datos

### D-01. Ubicación del repositorio
`/run/media/sebas/8b2a925b-…/Github/attack-exposure-model` (disco `Info`, 1 TB, carpeta `Github` con mayúscula). Era el único volumen con esa etiqueta. Informativa.

### D-02. Archivo de ATT&CK
`enterprise-attack-19.2.json` existe en `mitre-attack/attack-stix-data` con ese nombre exacto. Su SHA-256 se guarda en `data/attack/CHECKSUMS.sha256` y `aem fetch-data` lo verifica. Informativa.

### D-03. Campo `data_sources` del paso 4 — **PENDIENTE DE CONFIRMAR**
En ATT&CK v18+ las técnicas ya no tienen el campo `x_mitre_data_sources`; la detección se modela como *estrategia de detección → analíticas → componentes de datos*. El campo `data_sources` de la salida lista los **nombres de los componentes de datos** (p. ej. `Process Creation`, `Logon Session Creation`) que alcanzan la técnica por esa cadena. Los objetos `x-mitre-data-source` de v19 están todos deprecados.

### D-04. SDK de Gemini
Paquete `google-genai` 2.x. Se usa `client.models.generate_content` con `GenerateContentConfig(temperature=0, response_mime_type="application/json", response_json_schema=…)`, verificado por introspección del SDK instalado (2.31.0). La documentación vigente muestra además una API nueva (`client.interactions`), que no se usa porque `generate_content` sigue disponible y permite fijar `temperature`. La existencia del modelo se verifica con `client.models.get`. Modelos `gemini-3.8-flash` y `gemini-3.5-flash-lite` figuran como estables en https://ai.google.dev/gemini-api/docs/models (consulta del 2026-10-17).

## Paso 1 — Extracción

### D-10. Limpieza de los boletines de CISA antes de dárselos al LLM — **PENDIENTE DE CONFIRMAR**
Los boletines de CISA no solo tienen la sección «MITRE ATT&CK Tactics and Techniques»: también etiquetan cada párrafo en línea (`[T1190]`, `[TA0001]`) y una nota inicial dice qué versión de ATT&CK usan. Si solo se quitara la sección, la extracción copiaría las etiquetas. Por eso el texto `_stripped` elimina: (1) la sección completa «MITRE ATT&CK Tactics and Techniques»; (2) toda etiqueta entre corchetes con un ID de técnica o táctica; (3) la nota que remite a la tabla de ATT&CK. El detalle exacto de cada escenario está en `docs/report_preparation.md`.

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

### D-22. Borrador de la organización ficticia — **PENDIENTE DE CONFIRMAR (Sebas decide las brechas)**
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

## Salida

### D-50. Orden de filas
Por acción (`Act`, `Attend`, `Track*`, `Track`). Dentro de cada acción, por el índice de táctica más temprano en la matriz (si una técnica tiene varias tácticas, cuenta la primera en el orden de la matriz). A igual táctica se ordena por `technique_id` solo para que el orden sea determinístico; no expresa prioridad.

### D-51. Listas en celdas
Las celdas con varios valores (`tactics`, `mitigations`, `data_sources`, `groups`) usan `; ` como separador.

## Evaluación

### D-60. Mapeo de referencia de Akira — **PENDIENTE DE CONFIRMAR**
`CLAUDE.md` dice 32 técnicas, pero la sección «MITRE ATT&CK» del reporte (consultada el 2026-10-17) lista **38 IDs únicos**. Se usan los 38 tal como aparecen; Sebas debe confirmar si el 32 venía de otro conteo.

### D-61. Filas de táctica en las tablas de CISA
Las tablas de CISA incluyen a veces un ID de táctica (p. ej. `TA0009` Collection) en lugar de una técnica. Esas filas no entran en el mapeo de referencia, porque no son técnicas; se listan en `docs/report_preparation.md`.

### D-62. Enfoque tradicional (IoC) — **PENDIENTE DE CONFIRMAR**
`baseline.known_ioc_fraction` (por defecto 0,5) de los IoC del reporte `orig` se toman, con semilla fija, como `known_iocs` de la organización (archivo generado `data/org/known_iocs_generated.yaml`, referenciado desde el YAML). Si hay ≥ `baseline.min_matches` (por defecto 1) coincidencias, se reconocen todas las técnicas del escenario; si no, ninguna.

### D-63. Extracción de IoC y dominios de referencia — **PENDIENTE DE CONFIRMAR**
Se reconocen como IoC: hashes MD5/SHA-1/SHA-256, IPv4 (también con `[.]`), URL y dominios. Para no confundir nombres de archivo (`main.exe`, `secretsdump.py`) con dominios, un dominio sin `[.]` ni esquema `http(s)` solo cuenta si su TLD está en una lista blanca (`data/model_config.yaml`). Los dominios institucionales del propio boletín (`cisa.gov`, `fbi.gov`, `ic3.gov`, `mitre.org`…) se excluyen (lista configurable).

### D-64. Indicador 3 del modelo
Denominador: técnicas de la referencia (válidas en v19.2) cuya cobertura en el YAML es `parcial` o `sin cobertura`. Numerador: las que aparecen con ID exacto en `extracted_raw`. Se reporta el porcentaje en `orig`, en `mut` y la razón mut/orig.

### D-65. Indicador 5
Una violación es (a) un campo extra no previsto por el esquema en la salida del LLM, o (b) un patrón evaluativo en el texto generado que no aparece en el texto fuente correspondiente (el reporte, para las citas; la descripción, para los resúmenes).
