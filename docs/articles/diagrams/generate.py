"""Generates the article diagrams as standalone SVG files next to this script.

    python3 generate.py

The palette is fixed and light because the diagrams are exported to PNG for
Medium, which takes no SVG. To export, open each SVG at twice its size in a
browser and take a screenshot, for example with headless Firefox:

    firefox --headless --window-size=2400,1040 --screenshot 1-trust-chain.png wrapper.html

where wrapper.html is a page holding only <img src="1-trust-chain.svg" width="2400">.
"""
import os, html
OUT = os.path.dirname(os.path.abspath(__file__))
INK, MUTED, LINE, PAPER = '#1f2933', '#5f6c7b', '#9aa5b1', '#ffffff'
SOFT, GOOD, GOODBG, BAD, BADBG = '#f3f5f7', '#1a7f5a', '#e6f4ed', '#c0362c', '#fdecea'
FONT = "Inter, 'Helvetica Neue', Helvetica, Arial, 'Liberation Sans', sans-serif"
MONO = "'JetBrains Mono', 'DejaVu Sans Mono', Menlo, Consolas, monospace"

class Svg:
    def __init__(self, w, h, label):
        self.w, self.h, self.label, self.parts = w, h, label, []
    def add(self, s): self.parts.append(s)
    def text(self, x, y, s, size=14, fill=INK, anchor='middle', weight=400, mono=False, italic=False):
        fam = MONO if mono else FONT
        st = ' font-style="italic"' if italic else ''
        self.add(f'<text x="{x}" y="{y}" font-family="{fam}" font-size="{size}" fill="{fill}" text-anchor="{anchor}" font-weight="{weight}"{st}>{html.escape(s)}</text>')
    def box(self, x, y, w, h, fill=SOFT, stroke=LINE, sw=1.5, dash=None, r=8):
        d = f' stroke-dasharray="{dash}"' if dash else ''
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')
    def line(self, x1, y1, x2, y2, stroke=INK, sw=1.6, dash=None, arrow=True):
        d = f' stroke-dasharray="{dash}"' if dash else ''
        m = {INK: 'a-ink', GOOD: 'a-good', BAD: 'a-bad', LINE: 'a-line', MUTED: 'a-muted'}[stroke]
        e = f' marker-end="url(#{m})"' if arrow else ''
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" stroke-width="{sw}"{d}{e}/>')
    def cross(self, cx, cy, r=9, stroke=BAD, sw=2.6):
        self.add(f'<path d="M{cx-r} {cy-r} L{cx+r} {cy+r} M{cx+r} {cy-r} L{cx-r} {cy+r}" stroke="{stroke}" stroke-width="{sw}" stroke-linecap="round" fill="none"/>')
    def tick(self, cx, cy, r=9, stroke=GOOD, sw=2.6):
        self.add(f'<path d="M{cx-r} {cy} L{cx-r/3} {cy+r*0.7} L{cx+r} {cy-r*0.7}" stroke="{stroke}" stroke-width="{sw}" stroke-linecap="round" stroke-linejoin="round" fill="none"/>')
    def save(self, name):
        markers = ''.join(
            f'<marker id="{i}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z" fill="{c}"/></marker>'
            for i, c in (('a-ink', INK), ('a-good', GOOD), ('a-bad', BAD), ('a-line', LINE), ('a-muted', MUTED)))
        body = '\n'.join(self.parts)
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" width="{self.w}" height="{self.h}" role="img" aria-label="{html.escape(self.label)}">\n'
               f'<title>{html.escape(self.label)}</title>\n<defs>{markers}</defs>\n'
               f'<rect width="{self.w}" height="{self.h}" fill="{PAPER}"/>\n{body}\n</svg>\n')
        open(os.path.join(OUT, name), 'w').write(svg)

# ───────────────────────── 1. the trust chain ─────────────────────────
def trust_chain():
    s = Svg(1200, 520, 'A signing identity exists only while RBAC allows the build ServiceAccount: cut the first link and no certificate can be issued.')
    bw, bh, gap, x0 = 170, 92, 76, 22
    xs = [x0 + i * (bw + gap) for i in range(5)]
    def row(y, title, ok):
        col, bg = (GOOD, GOODBG) if ok else (BAD, BADBG)
        s.text(x0, y - 22, title, size=16, anchor='start', weight=600, fill=col)
        names = ['Kubernetes RBAC', 'The operator', 'SPIRE', 'Fulcio', 'The image']
        if ok:
            sub = [['RoleBinding grants', 'the three permissions'], ['3 access reviews:', 'all allowed'],
                   ['identity is', 'registered'], ['issues a 10-minute', 'certificate'], ['signed by', 'the build']]
            labels = ['allowed', 'registers', 'token', 'certificate']
        else:
            sub = [['RoleBinding', 'deleted'], ['3 access reviews:', 'denied'],
                   ['registration', 'removed'], ['nothing to', 'certify'], ['cannot be', 'signed']]
            labels = ['denied', 'removes', 'refused', 'none']
        for i, x in enumerate(xs):
            first = i == 0
            s.box(x, y, bw, bh, fill=bg if (first or not ok) else SOFT, stroke=col if (first or not ok) else LINE,
                  dash=None if (ok or first) else '5 4')
            s.text(x + bw / 2, y + 30, names[i], size=15, weight=600)
            s.text(x + bw / 2, y + 54, sub[i][0], size=13, fill=MUTED)
            s.text(x + bw / 2, y + 72, sub[i][1], size=13, fill=MUTED)
        for i in range(4):
            xa, xb = xs[i] + bw + 6, xs[i + 1] - 6
            ym = y + bh / 2
            if ok:
                s.line(xa, ym, xb, ym, stroke=GOOD)
            else:
                s.line(xa, ym, xb, ym, stroke=BAD, dash='5 4', arrow=False)
                s.cross((xa + xb) / 2, ym, r=7)
            s.text((xa + xb) / 2, ym - 12, labels[i], size=12.5, fill=col, weight=600)
    row(70, 'Authorized', True)
    s.add(f'<line x1="22" y1="232" x2="1178" y2="232" stroke="{LINE}" stroke-width="1" stroke-dasharray="2 5"/>')
    row(300, 'One permission revoked', False)
    s.text(22, 452, 'The three permissions: read the SupplyChain (scope), create builds (intent), record signatures (output).',
           size=13.5, anchor='start', fill=MUTED)
    s.text(22, 476, 'The operator re-runs the reviews whenever RBAC changes, so the second row follows the first within a second.',
           size=13.5, anchor='start', fill=MUTED)
    s.text(22, 500, 'spiffe://<your-domain>/ns/<namespace>/sa/supply-chain-runner', size=12.5, anchor='start', fill=MUTED, mono=True)
    s.save('1-trust-chain.svg')

# ───────────────────────── 2. the signature race ─────────────────────────
def race():
    s = Svg(1200, 640, 'Two signers read an empty signature list at the same moment, so the second write replaces the first; making the build wait for Tekton Chains keeps both.')
    lanes = ['Tekton Chains', "The build's sign step", 'Signature tag in the registry']
    def panel(y, title, ok):
        col = GOOD if ok else BAD
        s.text(22, y, title, size=16, anchor='start', weight=600, fill=col)
        ly = [y + 46, y + 116, y + 196]
        for i, name in enumerate(lanes):
            s.text(22, ly[i] + 5, name, size=13.5, anchor='start', weight=600 if i < 2 else 600, fill=INK)
            s.add(f'<line x1="250" y1="{ly[i]}" x2="1170" y2="{ly[i]}" stroke="{LINE}" stroke-width="1.2"/>')
        s.text(1170, y + 232, 'time →', size=12, anchor='end', fill=MUTED)
        def ev(lane, x, label, c=INK, above=True):
            s.add(f'<circle cx="{x}" cy="{ly[lane]}" r="6" fill="{c}"/>')
            s.text(x, ly[lane] + (-14 if above else 24), label, size=12.5, fill=c, weight=600)
        def state(x, w, label, c=INK, bg=SOFT):
            s.box(x - w / 2, ly[2] - 15, w, 30, fill=bg, stroke=c, sw=1.4, r=6)
            s.text(x, ly[2] + 5, label, size=12.5, fill=c, mono=True)
        def drop(lane, x, c):
            s.line(x, ly[lane] + 8, x, ly[2] - 19, stroke=c, sw=1.4, dash='4 3')
        return ly, ev, state, drop
    # before
    ly, ev, state, drop = panel(40, 'Before: both sign as soon as the push finishes', False)
    state(330, 70, '[ ]')
    ev(0, 430, 'reads [ ]'); ev(1, 470, 'reads [ ]', above=False)
    ev(1, 640, 'writes [build]'); drop(1, 640, INK)
    state(720, 110, '[build]')
    ev(0, 860, 'writes [chains]'); drop(0, 860, BAD)
    state(1020, 120, '[chains]', c=BAD, bg=BADBG)
    s.text(1020, ly[2] + 40, "the build's signature is gone", size=12.5, fill=BAD, weight=600)
    s.add(f'<line x1="22" y1="316" x2="1178" y2="316" stroke="{LINE}" stroke-width="1" stroke-dasharray="2 5"/>')
    # after
    ly, ev, state, drop = panel(356, "After: the build waits until Chains' signature is there", True)
    state(330, 70, '[ ]')
    ev(0, 430, 'reads [ ]')
    ev(0, 560, 'writes [chains]'); drop(0, 560, INK)
    state(640, 120, '[chains]')
    s.add(f'<line x1="300" y1="{ly[1]}" x2="700" y2="{ly[1]}" stroke="{GOOD}" stroke-width="5" stroke-linecap="round" stroke-dasharray="1 9"/>')
    s.text(420, ly[1] + 24, 'waits, polling the tag', size=12.5, fill=GOOD, weight=600)
    ev(1, 760, 'reads [chains]', above=False)
    ev(1, 900, 'writes [chains, build]'); drop(1, 900, GOOD)
    state(1040, 190, '[chains, build]', c=GOOD, bg=GOODBG)
    s.text(22, 620, 'cosign keeps every signature of an image in one registry tag, changed by reading the list, adding to it and writing it back.',
           size=13.5, anchor='start', fill=MUTED)
    s.save('2-signature-race.svg')

# ───────────────────────── 3. four policies ─────────────────────────
def policies():
    s = Svg(1200, 560, 'Admission requires four separate proofs, two from the build and two from Tekton Chains; an image missing any one is refused.')
    cx = [470, 640, 810, 980]
    s.text(22, 34, 'One SupplyChainPolicy renders four policies. An image must pass all of them.', size=16, anchor='start', weight=600)
    # identity brackets
    for x1, x2, name in ((cx[0] - 78, cx[1] + 78, "trusts the build's identity"), (cx[2] - 78, cx[3] + 78, "trusts Tekton Chains' identity")):
        s.add(f'<path d="M{x1} 78 L{x1} 68 L{x2} 68 L{x2} 78" fill="none" stroke="{LINE}" stroke-width="1.4"/>')
        s.text((x1 + x2) / 2, 60, name, size=13, fill=MUTED)
    heads = [('signature', 'the image, signed'), ('authorization', 'attests the 3 reviews'), ('signature', 'the image, signed'), ('provenance', 'attests SLSA v1.0')]
    for x, (h, d) in zip(cx, heads):
        s.box(x - 78, 88, 156, 62, fill=SOFT)
        s.text(x, 113, h, size=14.5, weight=600)
        s.text(x, 134, d, size=12, fill=MUTED)
    s.text(1108, 113, 'admission', size=14.5, weight=600)
    s.text(1108, 134, 'all four?', size=12, fill=MUTED)
    rows = [('Built by the pipeline', 'signed by the build and by Chains', [1, 1, 1, 1]),
            ('Signed by Chains only', "the build's signature is missing", [0, 1, 1, 1]),
            ('Pushed by hand', 'nobody signed it', [0, 0, 0, 0])]
    y = 190
    for name, sub, marks in rows:
        ok = all(marks)
        s.box(22, y, 1156, 84, fill=PAPER, stroke=LINE, sw=1.2)
        s.text(44, y + 36, name, size=15, anchor='start', weight=600)
        s.text(44, y + 58, sub, size=12.5, anchor='start', fill=MUTED)
        for x, m in zip(cx, marks):
            s.add(f'<circle cx="{x}" cy="{y + 42}" r="19" fill="{GOODBG if m else BADBG}" stroke="{GOOD if m else BAD}" stroke-width="1.4"/>')
            (s.tick if m else s.cross)(x, y + 42, r=8)
        s.box(1050, y + 22, 116, 40, fill=GOODBG if ok else BADBG, stroke=GOOD if ok else BAD, r=20)
        s.text(1108, y + 47, 'admitted' if ok else 'refused', size=14, weight=600, fill=GOOD if ok else BAD)
        y += 100
    s.text(22, 512, 'Within one policy the listed signers are alternatives; across policies every one must pass.',
           size=13.5, anchor='start', fill=MUTED)
    s.text(22, 536, 'That is why "signed by the build and by Chains" has to be more than one policy.',
           size=13.5, anchor='start', fill=MUTED)
    s.save('3-four-policies.svg')

# ───────────────────────── 4. the replaced log ─────────────────────────
def replaced_log():
    s = Svg(1200, 600, 'Re-running the installer erased the Rekor tree ID and created a new empty tree, so signatures that were still valid could no longer be found and their images were refused.')
    def panel(x, title, ok):
        col = GOOD if ok else BAD
        s.text(x, 36, title, size=16, anchor='start', weight=600, fill=col)
        # registry
        s.box(x, 60, 250, 128, fill=SOFT)
        s.text(x + 125, 86, 'Registry', size=14.5, weight=600)
        s.box(x + 20, 100, 210, 30, fill=PAPER, r=5); s.text(x + 125, 120, 'image', size=12.5, mono=True)
        s.box(x + 20, 140, 210, 30, fill=PAPER, r=5); s.text(x + 125, 160, 'signature' if ok else 'signature (unchanged)', size=12.5, mono=True)
        # rekor
        s.box(x + 300, 60, 250, 300, fill=SOFT)
        s.text(x + 425, 86, 'Rekor', size=14.5, weight=600)
        s.box(x + 320, 100, 210, 34, fill=PAPER, stroke=col, r=5)
        s.text(x + 425, 122, 'serves tree: ' + ('A' if ok else 'B'), size=12.5, mono=True, fill=col, weight=600)
        # tree A
        ay = 152
        s.box(x + 320, ay, 210, 92, fill=PAPER if ok else SOFT, stroke=GOOD if ok else LINE, dash=None if ok else '5 4', r=5)
        s.text(x + 425, ay + 22, 'tree A', size=12.5, weight=600, fill=INK if ok else MUTED)
        s.text(x + 425, ay + 44, 'entry 106: this signature', size=12, mono=True, fill=INK if ok else MUTED)
        s.text(x + 425, ay + 66, '… 112 more entries', size=12, mono=True, fill=MUTED)
        if not ok:
            s.text(x + 425, ay + 84, 'still stored, no longer served', size=11.5, fill=MUTED, italic=True)
            by = 258
            s.box(x + 320, by, 210, 84, fill=BADBG, stroke=BAD, r=5)
            s.text(x + 425, by + 24, 'tree B', size=12.5, weight=600, fill=BAD)
            s.text(x + 425, by + 48, 'new, empty', size=12, mono=True, fill=BAD)
            s.text(x + 425, by + 68, 'made by the re-run', size=11.5, fill=BAD, italic=True)
        # admission
        s.box(x, 250, 250, 110, fill=GOODBG if ok else BADBG, stroke=col)
        s.text(x + 125, 278, 'Admission', size=14.5, weight=600)
        s.text(x + 125, 302, 'looks the signature up', size=12.5, fill=MUTED)
        s.text(x + 125, 320, 'in the log', size=12.5, fill=MUTED)
        s.text(x + 125, 346, 'found: admitted' if ok else 'not found: refused', size=13.5, weight=600, fill=col)
        s.line(x + 125, 190, x + 125, 246, stroke=INK)
        s.text(x + 135, 224, 'reads', size=12, anchor='start', fill=MUTED)
        ty = (ay + 46) if ok else (258 + 42)
        if ok:
            s.add(f'<path d="M{x + 252} 305 L{x + 276} 305 L{x + 276} {ty} L{x + 314} {ty}" fill="none" stroke="{col}" stroke-width="1.6" marker-end="url(#a-good)"/>')
        else:
            s.line(x + 252, 305, x + 316, 305, stroke=col)
    panel(22, 'Before the re-run', True)
    panel(628, 'After the re-run', False)
    s.add(f'<line x1="600" y1="50" x2="600" y2="372" stroke="{LINE}" stroke-width="1" stroke-dasharray="2 5"/>')
    # cause strip
    s.box(22, 400, 1156, 118, fill=PAPER, stroke=LINE, sw=1.2)
    s.text(44, 428, 'What the installer did', size=14.5, anchor='start', weight=600)
    steps = ['re-applied the ConfigMap that holds the tree ID,', 'replacing it with the placeholder from the manifest', 'the setup Job, already cleaned up, ran again', 'and created tree B; Rekor started serving it']
    bx = [44, 44, 620, 620]
    by = [456, 478, 456, 478]
    for t, x, y in zip(steps, bx, by):
        s.text(x, y, t, size=13, anchor='start', fill=MUTED)
    s.add(f'<circle cx="34" cy="452" r="0" fill="{INK}"/>')
    s.line(520, 466, 604, 466, stroke=MUTED)
    s.text(44, 504, 'Nothing in the registry changed. Every signature was still valid, and every image carrying one was refused.',
           size=13, anchor='start', fill=INK, weight=600)
    s.text(22, 552, 'The fix: signing keys and log trees are made exactly once. The installer checks for the result before running the step',
           size=13.5, anchor='start', fill=MUTED)
    s.text(22, 576, 'that makes them, and never overwrites the place the result is kept.', size=13.5, anchor='start', fill=MUTED)
    s.save('4-replaced-log.svg')

trust_chain(); race(); policies(); replaced_log()
print(sorted(os.listdir(OUT)))
