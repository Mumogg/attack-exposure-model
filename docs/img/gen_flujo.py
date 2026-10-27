#!/usr/bin/env python3
"""Genera la Figura 1 (flujo del modelo) en ES y EN. Uso: python3 gen_flujo.py docs/img"""
import sys, os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams['font.family'] = ['Liberation Sans', 'DejaVu Sans']
OUT = sys.argv[1] if len(sys.argv) > 1 else 'docs/img'
os.makedirs(OUT, exist_ok=True)

T = {
 'es': dict(
  L=[('Reporte de amenaza', 'Texto, sin el mapeo ATT&CK'),
     ('Paso 1: extracción y mapeo', 'Inteligencia artificial'),
     ('Validación por código', 'ID existente y vigente; inválidos pasan a revisión'),
     ('Revisión del analista', 'Resolver, aceptar, quitar o agregar técnicas'),
     ('Paso 2: cobertura', 'Script contra el YAML'),
     ('Paso 3: priorización', 'Analista con árbol SSVC'),
     ('Revisión global', 'Analista sobre la cadena; genera global_review.json'),
     ('Agrupación y ordenamiento', 'Script, por acción y orden de ataque'),
     ('Salida: informe CSV', 'Una fila por técnica de la lista validada')],
  attack=('Datos de ATT&CK v19.2', 'y prevalencia de Red Canary (2026)'), only='solo ATT&CK',
  p4=('Paso 4: datos de referencia', 'Script con IA solo en el resumen'),
  yaml=('Archivo YAML', 'Detecciones, activos y contexto'),
  who='Quién actúa', leg=['Inteligencia artificial', 'Script (código)', 'Analista', 'Entrada o salida']),
 'en': dict(
  L=[('Threat report', 'Text, without the ATT&CK mapping'),
     ('Step 1: extraction and mapping', 'Artificial intelligence'),
     ('Validation by code', 'ID exists and is current; invalid ones go to review'),
     ('Analyst review', 'Resolve, accept, remove or add techniques'),
     ('Step 2: coverage', 'Script against the YAML'),
     ('Step 3: prioritization', 'Analyst with SSVC tree'),
     ('Global review', 'Analyst over the chain; writes global_review.json'),
     ('Grouping and ordering', 'Script, by action and attack order'),
     ('Output: CSV report', 'One row per technique in the validated list')],
  attack=('ATT&CK v19.2 data', 'and Red Canary prevalence (2026)'), only='ATT&CK only',
  p4=('Step 4: reference data', 'Script with AI only for the summary'),
  yaml=('YAML file', 'Detections, assets and context'),
  who='Who acts', leg=['Artificial intelligence', 'Script (code)', 'Analyst', 'Input or output']),
}
# (relleno, borde, color título, color subtítulo)
C = {'ia': ('#FAEDE8', '#A8472A', '#7A2A12', '#A8472A'), 'sc': ('#F1EEE8', '#6B6B66', '#3B3B38', '#5A5A56'),
     'an': ('#E1F3EC', '#1D7A5F', '#0B4D3A', '#1D7A5F'), 'io': ('#FBFBFA', '#B5B5B0', '#111111', '#555555')}
H = 7.0
LX, LW, RX, RW = 27, 40, 77, 36
GRIS = '#8A8A85'


def build(lang):
    t = T[lang]
    fig = plt.figure(figsize=(10, 10), dpi=272)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 100); ax.set_ylim(0, 100); ax.axis('off')

    def node(cx, cy, w, title, sub, k, h=H):
        f, e, tc, sc = C[k]
        ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h, boxstyle='round,pad=0,rounding_size=1.2',
                                    fc=f, ec=e, lw=1.0, ls='--' if k == 'io' else '-'))
        ax.text(cx, cy + 1.2, title, ha='center', va='center', fontsize=12.5, color=tc)
        ax.text(cx, cy - 1.5, sub, ha='center', va='center', fontsize=9.4, color=sc)

    def arrow(p, q):
        ax.add_patch(FancyArrowPatch(p, q, arrowstyle='->', mutation_scale=14, lw=1.6, color=GRIS, shrinkA=0, shrinkB=0))

    def line(xs, ys):
        ax.plot(xs, ys, color=GRIS, lw=1.6, solid_capstyle='butt')

    ys = [94.0 - i * 10.3 for i in range(9)]
    kinds = ['io', 'ia', 'sc', 'an', 'sc', 'an', 'an', 'sc', 'io']
    for (title, sub), k, y in zip(t['L'], kinds, ys):
        node(LX, y, LW, title, sub, k)
    # flechas de la columna izquierda (Paso 3 -> Revisión global; Revisión global no continúa)
    for i in (0, 1, 2, 3, 4, 5, 7):
        arrow((LX, ys[i] - H / 2), (LX, ys[i + 1] + H / 2))
    # Paso 3 -> Agrupación (codo por la izquierda)
    xl = 3.2
    line([LX - LW / 2, xl, xl], [ys[5], ys[5], ys[7]]); arrow((xl, ys[7]), (LX - LW / 2, ys[7]))
    # columna derecha
    node(RX, ys[2], RW, *t['attack'], 'io')
    node(RX, ys[3], RW, *t['p4'], 'ia')
    node(RX, (ys[4] + ys[5]) / 2, RW, *t['yaml'], 'io', h=ys[4] - ys[5] + H)
    arrow((RX, ys[2] - H / 2), (RX, ys[3] + H / 2))                       # ATT&CK -> Paso 4
    arrow((RX - RW / 2, ys[2]), (LX + LW / 2, ys[2]))                     # ATT&CK -> Validación
    ax.text((LX + LW / 2 + RX - RW / 2) / 2, ys[2] + 1.3, t['only'], ha='center', va='bottom', fontsize=8.5, color='#555555')
    arrow((LX + LW / 2, ys[3]), (RX - RW / 2, ys[3]))                     # Revisión analista -> Paso 4
    arrow((RX - RW / 2, ys[4]), (LX + LW / 2, ys[4]))                     # YAML -> Paso 2
    arrow((RX - RW / 2, ys[5]), (LX + LW / 2, ys[5]))                     # YAML -> Paso 3
    xr = RX + RW / 2 + 2.4
    line([RX + RW / 2, xr, xr], [ys[3], ys[3], ys[7]]); arrow((xr, ys[7]), (LX + LW / 2, ys[7]))  # Paso 4 -> Agrupación
    # leyenda
    ly = 15.5
    ax.text(RX - RW / 2, ly, t['who'], fontsize=13, va='center', color='#111111')
    for i, (k, lab) in enumerate(zip(['ia', 'sc', 'an', 'io'], t['leg'])):
        f, e, _, _ = C[k]; col, row = i % 2, i // 2
        x0 = RX - RW / 2 + col * 19; yy = ly - 4.8 - row * 4.4
        ax.add_patch(FancyBboxPatch((x0, yy - 1.2), 3.6, 2.4, boxstyle='round,pad=0,rounding_size=0.6',
                                    fc=f, ec=e, lw=1, ls='--' if k == 'io' else '-'))
        ax.text(x0 + 5, yy, lab, fontsize=10, va='center', color='#444444')
    path = os.path.join(OUT, f'flujo_modelo_{lang}.png')
    fig.savefig(path, dpi=272, facecolor='white'); plt.close(fig); print('ok', path)


for lg in ('es', 'en'):
    build(lg)
