# Preparación de los reportes (D-10, D-60, D-61)

Objetivo: que el texto que recibe el LLM en el paso 1 (`*_stripped.txt`) **no contenga la respuesta**, es decir, ni la tabla del mapeo ATT&CK ni ningún ID de técnica o táctica. Solo se quita el ID; la oración que lo contenía se conserva legible (p. ej. `…internet-facing devices [T1190], including firewall…` → `…internet-facing devices, including firewall…`).

Todo esto lo hace el código (`src/aem/reports.py`, `src/aem/scenarios.py`) con `aem fetch-data` (CISA) y `aem prepare-reports` (Akira). Cada ejecución deja un registro en `data/reports/<reporte>_preparation.json`.

## 1. Conversión HTML → texto (solo CISA)

- Se conserva el título de la página (`h1.c-page-title__title`) y el cuerpo importado del boletín (`div.l-page-section--rich-text.csaf-imported`).
- **No** se conserva: menú y pie del sitio, el recuadro «Actions for Organizations to Take Today…» (fuera del cuerpo importado), etiquetas, «Related Advisories» ni encuestas.
- Encabezados → `#`, `##`, `###`; listas → `- `; tablas → una fila por línea (`| celda | celda |`); el título de tabla (`<caption>`) queda como línea propia. Las listas dentro de una celda se unen en la misma fila.
- El HTML descargado queda en `data/reports/raw/` (no se versiona); el texto convertido y el `stripped` sí se versionan (son documentos del gobierno de EE. UU.).

## 2. Qué se elimina (tipos de sección y patrones)

| Tipo | Patrón | Dónde |
|---|---|---|
| Sección del mapeo | Encabezado `MITRE ATT&CK Tactics and Techniques` hasta el siguiente encabezado del mismo nivel o superior (incluye el párrafo introductorio y **todas** las tablas «Table N. <táctica>») | CISA |
| Nota de versión | Párrafo que empieza por `Note: This advisory uses the MITRE ATT&CK` (remite a la tabla del mapeo) | CISA |
| Sección del mapeo | Línea con el encabezado `MITRE ATT&CK` (configurable en `data/scenarios.yaml`, `attack_heading`) hasta la siguiente línea de `end_headings` o el final del texto | Akira (DFIR) |
| IDs entre corchetes | `[T1190]`, `[T1078.001][T1078.002]`, `[TA0009][T1114]`, `[T1003.003, T1003.001]` (se quita el grupo completo y el espacio previo) | Todos |
| IDs entre paréntesis | `(T1219)` | Todos |
| IDs sueltos | `T####`, `T####.###`, `TA####` en cualquier parte, sin distinguir mayúsculas (cubre etiquetas Sigma como `attack.t1059.001`) | Todos |

Se mantiene la sección «Validate Security Controls», que solo menciona «Table 6 to Table 18» sin IDs.

Garantía: `tests/test_reports.py::test_no_attack_ids_in_any_stripped_report` falla si algún `data/reports/*_stripped.txt` (incluido el de Akira si está en la máquina) contiene `\bT\d{4}(\.\d{3})?\b` o `\bTA\d{4}\b`.

## 3. Resultado por escenario (2026-10-17)

| Escenario | Sección del mapeo (líneas no vacías) | Nota de versión | IDs eliminados del cuerpo (apariciones / distintos) | Técnicas de referencia | Filas de táctica excluidas (D-61) |
|---|---|---|---|---|---|
| Gunra AA26-222A | 65 | sí («…version 19.1…») | 41 / 38 | 36 | TA0009 Collection |
| Interlock AA25-203A | 54 | sí («…version 17…») | 39 / 28 | 25 | TA0005 Defense Evasion, TA0006 Credential Access, TA0011 Command and Control |
| Akira (DFIR) | se registra al ejecutar `aem prepare-reports` | — | — | 38 (D-60) | ninguna |

El título de la tabla de Interlock dice «Defense Escalation» (así aparece en el boletín); se conserva tal cual en la columna `tactic`.

## 4. Mapeos de referencia (`data/reference_mappings/*.csv`)

Columnas: `technique_id, technique_name, tactic, valid_in_v19_2, v19_2_status, v19_2_replacement`.

- **CISA:** filas de las tablas del mapeo; `technique_name` y `tactic` tal como aparecen en el boletín. Si un ID aparece en varias tablas, se une en una fila con las tácticas separadas por `; `.
- **Akira:** solo IDs y nombres de técnica de la sección «MITRE ATT&CK» del reporte (datos de ATT&CK, no texto del reporte), consultada el 2026-10-17. Como esa sección no indica la táctica, `tactic` se toma de ATT&CK v19.2.
- `valid_in_v19_2` se calcula con el código contra `enterprise-attack-19.2.json`. Los tres mapeos son 100 % válidos en v19.2 (también los del boletín de 2025, que usaba ATT&CK v17).
- Las métricas usan solo las filas con `valid_in_v19_2 = si`.

## 5. Cómo colocar el texto de Akira (Sebas)

1. Abra https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3/ .
2. Copie el texto del artículo (desde el título hasta la sección «MITRE ATT&CK» incluida) y guárdelo como **texto plano UTF-8** en `data/reports/akira_dfir_2026.txt`.
3. Verifique que el encabezado `MITRE ATT&CK` quede **solo en una línea**, seguido del listado `Nombre - T####`.
4. Ejecute `aem prepare-reports`. El comando genera `akira_dfir_2026_stripped.txt` e indica si los IDs de la sección coinciden con `data/reference_mappings/akira.csv` («coincide» / «NO coincide: …»).
5. Si después del listado de técnicas hay más texto que deba conservarse, agregue su encabezado a `end_headings` en `data/scenarios.yaml`.

Todos los archivos `data/reports/akira_dfir_2026*` están en `.gitignore` (texto, versión `stripped`, variante y su diff).

## 6. Texto de Akira colocado (2026-10-18)

El texto se extrajo del HTML del artículo, tomando solo su contenedor: quedan fuera el menú, la barra lateral, los botones para compartir, los comentarios, los artículos relacionados y el pie del sitio. Se guardó en texto plano UTF-8, con el encabezado `MITRE ATT&CK` en una línea propia. Antes de `aem prepare-reports` se quitaron a mano los bloques de la tabla, porque no describen la intrusión sino al editor o al sitio. Las posiciones son aproximadas y corresponden al texto como estaba antes de cada corte. No se copia su contenido.

| Bloque quitado | Dónde | Tamaño aprox. | Motivo |
|---|---|---|---|
| Etiqueta de categoría del sitio | Línea 1, antes del título | 1 línea, 1 palabra | Navegación del sitio, no texto del artículo |
| Frase que invita a suscribirse a los informes del editor (la quitó Sebas) | Al inicio del artículo, hacia la línea 26 | 1 línea, 17 palabras | Promoción del editor |
| Última frase del párrafo final de «Key Takeaways»: anuncia un caso de DFIR Labs basado en esta intrusión | Línea 12 | 1 frase, 15 palabras | Promoción del editor. Las dos frases anteriores del párrafo se conservan |
| Sección «The DFIR Report Offerings»: encabezado y su párrafo | Líneas 26–28, entre «Case Summary» e «Initial Access» | 3 líneas | Oferta comercial y contacto del editor |
| Sección «Analysts»: encabezado y su párrafo | Líneas 30–32, justo antes de «Initial Access» | 3 líneas | Créditos de autores y revisores: nombres de personas, no de la amenaza |

Las dos secciones del editor ocupan 8 líneas, contando las líneas en blanco, y suman 52 palabras. Después de los cortes, el texto tiene 789 líneas y 6855 palabras, y el encabezado `MITRE ATT&CK` está en la línea 748. `aem prepare-reports` sigue indicando «coincide» con `data/reference_mappings/akira.csv`. El editor queda mencionado una sola vez, como autor de una regla de detección en la sección «Detections» (ver D-76).

**Defang de tres IPv4 (2026-10-18, D-76, opción A de Sebas).** El texto escribía tres IPv4 públicas sin defang, y ninguna aparecía con defang en otro lugar. Por la regla de D-63 no contaban como IoC, así que quedaban intactas en `mut` y `anon`. A cada una se le cambiaron sus tres puntos por `[.]` y no se tocó nada más (18 bytes en total):

| Posición (texto ya cortado) | Sección | Forma |
|---|---|---|
| Línea 58 | «Initial Access» | Elemento de lista |
| Línea 638 | «Indicators» | Bloque de IoC |
| Línea 642 | «Indicators» | Bloque de IoC |

El texto sigue con 789 líneas y 6855 palabras. Ahora `mut` reemplaza 43 IoC distintos en lugar de 40, y ninguna de las tres IP aparece en `mut` ni en `anon`.

**Limitación de la copia local: direcciones `usuario@IP` ocultas por el sitio.** La protección de correo del sitio reemplaza en el HTML, antes de que corra JavaScript, todo lo que tiene forma de dirección de correo. Así, en 2 comandos ssh, la parte `usuario@IP` quedó como un marcador genérico de «correo protegido», y la extracción no la recupera. Son 3 apariciones, en el texto ya cortado: hacia las líneas 381 y 383 de «Lateral Movement» (el comando y su explicación línea por línea) y hacia la línea 520 de «Command and Control» (el comando del incidente de Swisscom). En los dos casos se pierden el usuario y casi toda la IP de destino; solo queda visible su último octeto. En el primer caso, la sección «Exfiltration» nombra con defang un servidor con el mismo último octeto, y ese sí cuenta como IoC. En el segundo, la IP completa no se puede recuperar de la copia local: si no aparece en otro lugar, no es IoC ni para el enfoque tradicional ni para `mut`. No se reconstruyó a mano para no agregar datos que no están en la copia local.
