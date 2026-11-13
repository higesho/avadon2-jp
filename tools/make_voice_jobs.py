"""Split voice_candidates.json (speakers not yet in voices.json) into voice_in/<job>.json.

usage:
    python -I make_voice_jobs.py TRANS_DIR ORIG_SCRIPTS N_JOBS
"""
import json
import os
import re
import sys


def main(argv):
    tdir, scripts, n = argv[0], argv[1], int(argv[2])
    cands = json.load(open(os.path.join(tdir, 'voice_candidates.json'), encoding='utf-8'))
    voices = json.load(open(os.path.join(tdir, 'voices.json'), encoding='utf-8'))
    have = {re.search(r'（(.+?)）', k).group(1) for k in voices if '（' in k}
    gloss = {t['en']: t['ja'] for t in json.load(open(os.path.join(tdir, 'glossary.json'), encoding='utf-8'))}
    text = ''
    for fn in os.listdir(scripts):
        text += open(os.path.join(scripts, fn), encoding='mac_roman').read()
    todo = []
    for c in cands:
        if c['en'] in have:
            continue
        he = len(re.findall(re.escape(c['en']) + r"[^._]{0,60}\b(?:he|his|him)\b", text, re.I))
        she = len(re.findall(re.escape(c['en']) + r"[^._]{0,60}\b(?:she|her)\b", text, re.I))
        g = 'm' if he > 2 * she and he >= 2 else 'f' if she > 2 * he and she >= 2 else '?'
        r = {'en': c['en'], 'ja': gloss.get(c['en'], ''), 'gender': g, 'files': c['files'], 'samples': c['samples']}
        if 'a1' in c:
            r['a1'] = c['a1']
        todo.append(r)
    os.makedirs(os.path.join(tdir, 'voice_in'), exist_ok=True)
    size = (len(todo) + n - 1) // n
    for i in range(n):
        part = todo[i * size:(i + 1) * size]
        json.dump(part, open(os.path.join(tdir, 'voice_in', 'v%d.json' % (i + 1)), 'w', encoding='utf-8'),
                  ensure_ascii=False, indent=1)
        print('v%d' % (i + 1), len(part))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
