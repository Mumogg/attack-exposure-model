# Revisión independiente de `eval/` (2026-10-17)

**Cómo se hizo.**
- **Revisor:** un subagente con contexto nuevo, sin el razonamiento previo de esta sesión.
- **Alcance:** solo `eval/metrics.py`, `eval/baseline_ioc.py` y `eval/make_variants.py`. Podía leer el código que importan, la especificación (`CLAUDE.md` §8), las pruebas y `eval/run_experiments.py`. No podía leer `docs/` ni modificar archivos.
- **Encargo:** buscar errores en las fórmulas de precisión y exhaustividad (sub-técnica y padre), en la definición del indicador 3, sesgos a favor del modelo, casos borde y confusión entre resultados con un LLM falso y reales.
- **Verificación:** el revisor comprobó cada hallazgo con fragmentos de código sobre la configuración, la organización y los textos reales.

**Resultado general.**
- Las fórmulas de precisión, exhaustividad y persistencia son aritméticamente correctas.
- Los casos borde (listas vacías, división por cero, una sola corrida) están cubiertos.
- No encontró confusión posible entre resultados falsos y reales.
- Encontró 7 errores concretos (sección A), todos corregidos con pruebas, y 10 cuestiones de diseño (sección C), que quedan abiertas para Sebas.
- Ningún hallazgo invalida el diseño de un indicador tal como lo define la especificación. Sí hay dos que conviene declarar en la tesis: C1 y C2.

## A. Errores corregidos

Cada corrección tiene una prueba que falló antes del cambio y pasa después.

| # | Archivo | Hallazgo | Corrección | Prueba |
|---|---|---|---|---|
| A1 | `make_variants.py` | **Importante.** Con `variants.require_defang: false`, la variante reemplazaba cualquier `nombre.tld` con TLD de la lista y cualquier `d.d.d.d`. Por ejemplo, `backdoor.pl` (script Perl), `mega.io` (exfiltración a la nube) y `Version 5.1.2.3` se convertían en `.invalid` o en IP de documentación. Así `mut` perdía evidencia de comportamiento y la persistencia del modelo bajaba por una razón ajena a los IoC (sesgo **en contra** del modelo). En Gunra e Interlock no ocurría; en Akira podía ocurrir. | `variants.require_defang: true` por defecto: se detectan los mismos IoC que en el enfoque tradicional. Se reemplazan también todas sus menciones sin defang y los hashes dentro de cualquier URL. Lo demás que parece IoC sin defang se deja intacto y se lista para revisión manual (`plain_candidates_kept`). | `test_review_a1_plain_tokens_that_are_not_iocs_stay_in_mut`, `test_review_a1_hash_in_plain_reference_url_is_still_replaced` |
| A2 | `baseline_ioc.py` | **Importante.** Cualquier valor de una columna `Username` contaba como IoC «cuenta», incluido `Administrator`. En `mut` eso borraba la evidencia de T1078.001/.003 (en contra del modelo). Además convertía `administrator` en IoC conocido, de modo que cualquier otro reporte con esa cuenta habría sido «reconocido» (a favor del enfoque tradicional). | Lista configurable `ioc.generic_accounts` (administrator, admin, root, guest, system, krbtgt, defaultaccount, user), que se excluyen. | `test_review_a2_generic_accounts_are_not_iocs` |
| A3 | `metrics.py` | Menor (indicador 4, chequeo automático). Las abreviaturas contaban como fin de oración: «Uses e.g. PowerShell. Stops U.S. hosts. Done v1.2 ok.» daba 5 oraciones en vez de 3. | Fin de oración solo antes de mayúscula o del final, y no después de `e.g.`, `i.e.`, `etc.`, `vs.` ni `U.S.` | `test_review_a3_abbreviations_are_not_sentence_ends` |
| A4 | `metrics.py` | Menor (chequeo automático). Cifras e IDs se buscaban como subcadenas: «3» se daba por presente porque la fuente decía «2023», y «T1059» porque decía «T1059.001». A la inversa, «1,000» contra «1000» se marcaba como ausente. | Se comparan como tokens y se quita el separador de miles. | `test_review_a4_numbers_and_ids_are_compared_as_tokens` |
| A5 | `baseline_ioc.py`, `make_variants.py` | Menor (sin casos en los reportes actuales). Un SHA-512 (128 hexadecimales) no se reconocía ni se reemplazaba, y la verificación no lo detectaba. | Tipo `sha512`. `check_variant` marca además cualquier secuencia de ≥ 32 hexadecimales que sobreviva. | `test_review_a5_sha512_is_an_ioc_and_is_replaced`, `test_review_a5_check_flags_any_long_hex_run` |
| A6 | `make_variants.py` | Menor. En un correo solo se cambiaba el dominio, así que la parte local elegida por el actor (`ilovemycubscout`) seguía en `mut`. | Se reemplaza también la parte local (10 letras aleatorias, el mismo reemplazo en todo el reporte). Cambia D-66 (confirmada por Sebas el 2026-10-17). | `test_review_a6_email_local_part_is_replaced` |
| A7 | `make_variants.py` | Menor (solo el registro). El mapeo se indexaba por grafía: `datapub.news` y `Datapub[.]news` contaban como dos IoC, y un hash dentro de una URL aparecía mezclado con otro tipo. | El registro se indexa por (tipo, valor normalizado), con la lista de grafías y el número de apariciones. | `test_review_a7_mapping_is_keyed_by_type_and_value` |

Efecto en los datos versionados:
- Variantes regeneradas: Gunra, 34 IoC distintos reemplazados (38 apariciones); Interlock, 38 (40). Son exactamente los IoC de la sección de IoC de cada boletín.
- Los enlaces de referencia de las notas ya no cambian (Gunra 4; Interlock 8 más `soc@cisecurity.org`).
- IoC conocidos: Gunra 17, Interlock 19 (sin cambios).

## B. Verificado como correcto (sin cambios)

- **Nivel exacto:** conjuntos, precisión = correctas / propuestas y exhaustividad = correctas / referencia, con «indefinida» si el denominador es 0. Los repetidos cuentan una vez.
- **Nivel padre:** `T1059.001 → T1059` en ambas listas antes de comparar. Ejemplos comprobados:
  - Proponer `T1059.001`, `.003` y `.005` contra una referencia con solo `T1059.001` da precisión exacta 1/3 y precisión padre 1/1.
  - Proponer `T1059` contra `T1059.001` y `.003` da exacta 0/0 y padre 1/1.
  - Una referencia con `T1003` y `T1003.003` (Gunra) se colapsa en un solo padre.
- **Persistencia:** `model_persistence` y `traditional_persistence` son correctas, con «indefinida» si el denominador es 0. `aggregate` usa la desviación muestral y devuelve «indefinida» si n < 2.
- **Indicador 2:** exactitud 100 % en los tres escenarios con los datos actuales, así que las brechas del paso 2 coinciden con las del YAML (Gunra 28/36, Interlock 18/25, Akira 25/38).
- **Resultados con un LLM falso:** ninguno de los tres archivos llama al LLM. El etiquetado FAKE (D-71) está en `run_experiments.py` y también marca como FAKE las filas que no dependen del LLM, lo que es conservador.

## C. Cuestiones de diseño abiertas (decide Sebas)

| # | Cuestión | Efecto | Recomendación | Estado |
|---|---|---|---|---|
| C1 | **El enfoque tradicional del indicador 3 está fijado por construcción.** Los IoC conocidos son el 50 % de los del propio reporte, basta 1 coincidencia y `check_variant` garantiza que ninguno sobrevive en `mut`. | Con los datos reales, la fila tradicional da siempre orig 100 %, mut 0 %, razón 0 (Gunra 17 coincidencias → 0; Interlock 19 → 0). Daría lo mismo con cualquier fracción > 0. Es un punto de referencia analítico, no un resultado empírico. | Decirlo así en la tesis (ya figura como limitación 5 en `RESUMEN_PARA_TESIS.md`). Opcional: barrido de sensibilidad de `known_ioc_fraction` y `min_matches`, o una variante con mutación parcial de IoC. | Abierta (D-62, PENDIENTE) |
| C2 | **Información asimétrica a favor del modelo.** `mut` conserva los nombres del actor y del malware (Gunra, Interlock), herramientas y CVE. El LLM puede reconocer la amenaza por su nombre y recordar técnicas de su entrenamiento (los boletines son públicos). | Parte de la «persistencia» del modelo puede deberse a reconocer el nombre, no a extraer el comportamiento. | Declararlo como limitación. Opcional: una variante de control con los nombres de familia y actor anonimizados. | Abierta |
| C3 | La razón mut/orig oculta los niveles absolutos: orig 30 % y mut 30 % da 1,0, y el ruido del LLM puede dar > 1. | Interpretación | Presentar primero las medias absolutas, que ya se informan. | Abierta |
| C4 | La persistencia del modelo usa el ID exacto: `T1078` frente a la brecha `T1078.001` cuenta como no reconocida. | Conservador para el modelo | Opcional: informar también a nivel padre. | Abierta |
| C5 | Las brechas del indicador 3 salen del paso 2; la especificación dice «brecha según el YAML». | Equivalente mientras el indicador 2 sea 100 % (hoy lo es) | Opcional: usar `coverage_design` directamente. | Abierta |
| C6 | Los IoC conocidos se juntan entre escenarios (`baseline_recognizes` no filtra por `scenario`). | Realista, pero puede dar reconocimiento cruzado. Hoy no ocurre: Gunra e Interlock no comparten IoC. | Decidirlo y documentarlo. | Abierta (D-62) |
| C7 | Una corrida «vacía» (sin propuestas) tiene precisión indefinida y no entra en ninguna media de precisión. Una corrida fallida cuenta como 0 en `_fail0`. | Asimetría pequeña | Documentarla, o contar la vacía como 0 en `_fail0`. | Abierta (D-67) |
| C8 | Los IDs revocados de `extracted_raw` cuentan como erróneos (más la omisión). Las filas de referencia no válidas se descartan en lugar de mapearse. No se normalizan mayúsculas. | Hoy ninguna referencia tiene IDs no válidos | Documentarlo. | Abierta |
| C9 | Indicador 5: cada patrón cuenta como máximo una vez por campo, y un patrón presente en el reporte suprime sus apariciones en la salida (D-65). | Ambas cosas subcuentan, a favor del modelo | Documentarlo en la tesis. | Abierta (D-65) |
| C10 | En `mut`, `.onion`, `proton.me` y `gmail.com` pasan a `.invalid`, así que se pierde la palabra «Tor» o el proveedor de correo en las tablas de IoC. | Despreciable: Tor sigue en la prosa. Si acaso, va en contra del modelo. | Ninguna | Aceptada |
