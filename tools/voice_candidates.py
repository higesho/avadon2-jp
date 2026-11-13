"""Find speaking characters and samples of their lines, for the voice table (口調表).

usage:
    python -I voice_candidates.py TRANS_DIR A1_VOICES OUT_JSON

A speaker is the last capitalised name (from the glossary candidates' person/creature
names, titles stripped) that appears in the narration before an _underscored_ quote in
the same text unit. Writes [{"en", "files", "count", "samples": [...], "a1": note?}],
most frequent first.
"""
import collections
import json
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8')
TITLES = ('Eye', 'Hand', 'Heart', 'Commander', 'Watcher', 'Monitor', 'Envoy', 'Councilor', 'Councillor', 'Chosen',
          'Lawcarver', 'Seeker', 'Defender', 'Protector', 'Kennelmaster', 'Captain', 'Smith', 'Duke', 'King', 'Queen',
          'Lord', 'Lady', 'Shaman', 'Sorceress', 'Sorcerer', 'Craftmaster', 'Keeper', 'Master', 'Mistress', 'Priest',
          'Priestess', 'Chief', 'Elder', 'Sentinel', 'Guide', 'Scout')
SKIP = {'Avadon', 'Pact', 'Corruption', 'Tawon', 'Kva', 'Wyldrylm', 'God', 'Gods', 'Goddess', 'Sovereign', 'You', 'Your',
        'Hand', 'Hands', 'Keeper', 'Watcher', 'Lore', 'Serdica', 'Troezen', 'Kellem', 'Eye', 'Eyes', 'Heart', 'Hearts'}


def main(argv):
    tdir, a1path, out = argv
    cands = json.load(open(os.path.join(tdir, 'glossary_candidates.json'), encoding='utf-8'))
    names = set()
    for c in cands:
        if 'person' in c['cat'] or c['cat'] in ('creature', 'term in text'):
            en = c['en']
            w = en.split()
            if w[0] in TITLES and len(w) > 1:
                en = ' '.join(w[1:])
            if re.fullmatch(r"[A-Z][a-z'-]+(?: [A-Z][a-z'-]+)?", en) and en not in SKIP:
                names.add(en)
    a1 = json.load(open(a1path, encoding='utf-8'))
    a1_by_en = {}
    for k, v in a1.items():
        m = re.search(r'（(.+?)）', k)
        if m:
            a1_by_en[m.group(1)] = (k, v)
    rx = re.compile(r"\b(" + '|'.join(sorted((re.escape(n) for n in names), key=len, reverse=True)) + r")\b")
    samples = collections.defaultdict(list)
    files = collections.defaultdict(collections.Counter)
    for fn in sorted(os.listdir(os.path.join(tdir, 'units'))):
        last = None  # speaker of the previous quote in this file (lines of one talk node follow each other)
        for u in json.load(open(os.path.join(tdir, 'units', fn), encoding='utf-8')):
            if u['kind'] not in ('text', 'lib'):
                last = None if u['kind'] == 'question' else last
                continue
            en = u['en']
            for m in re.finditer(r'_([^_]{8,})_', en):
                before = en[max(0, m.start() - 140):m.start()]
                hits = list(rx.finditer(before))
                if hits:
                    sp = hits[-1].group(1)
                elif last and m.start() < 3:
                    sp = last  # the unit starts with a quote: same speaker continues
                else:
                    continue
                last = sp
                files[sp][fn[:-5]] += 1
                if len(samples[sp]) < 400:
                    samples[sp].append(m.group(1).strip())
    res = []
    for sp, ss in samples.items():
        if len(ss) < 3:
            continue
        # spread the samples over the whole list (early and late lines)
        step = max(1, len(ss) // 10)
        pick = [s[:220] for s in ss[::step][:10]]
        r = {'en': sp, 'count': len(ss), 'files': [f for f, _ in files[sp].most_common(6)], 'samples': pick}
        if sp in a1_by_en:
            r['a1'] = '%s: %s' % a1_by_en[sp]
        res.append(r)
    res.sort(key=lambda r: -r['count'])
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(res, f, ensure_ascii=False, indent=1)
    print(len(res), 'speakers;', sum(1 for r in res if 'a1' in r), 'with an Avadon 1 note')
    print(', '.join('%s(%d)' % (r['en'], r['count']) for r in res[:80]))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
