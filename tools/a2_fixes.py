"""Apply the term fixes collected in trans/FIX_LATER.md to every translation.

usage:
    python -I a2_fixes.py TRANS_DIR [--dry-run]

Each rule replaces a Japanese term, optionally only in units whose English text matches
a pattern (so e.g. 領主 is changed only where the English is about Xenophon). Prints a
count per rule. Chunks are read from TRANS_DIR/chunks for the English text.
"""
import json
import os
import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

# (name, english regex or None, [(japanese regex, replacement), ...])
RULES = [
    ('turret', None, [('タレット', '砲塔')]),
    ('mines', r'(?i)\bmines?\b', [('鉱山', '地雷')]),
    ('armor items', r'(?i)\barmor\b', [('防具（防御力のある装備）', '防具'), ('重い防御力のある装備', '重い防具'),
                                       ('防御力のある装備', '防具')]),
    ('wretch', r'(?i)\bwretch(es)?\b', [('ウレッチ', '蛮人'), ('哀れなやつら', '蛮人たち'), ('哀れな部族', '蛮人の部族'),
                                        ('哀れな者たち', '蛮人たち'), ('哀れな者', '蛮人')]),
    ('stalker', None, [('ストーカー', '追跡獣')]),
    ('kennelmaster', None, [('獣舎頭', '犬舎長')]),
    ('construct', r'(?i)\bconstructs?\b', [('ゴーレム', '魔造兵')]),
    ('infernal', r'(?i)\binfernals?\b', [('インファーナル', '魔性'), ('高位の悪魔', '魔性')]),
    ('wind lord', None, [('風の君主', '風卿')]),
    ('dharamite', None, [('ダマール人', 'ダーラム人')]),
    ('geert', None, [('ヘールト', 'ゲールト')]),
    ('foresight qm', None, [('先見の補給係', '先見砦の補給係')]),
    ('troezen arms', None, [('トロイゼン武具店', 'トロイゼン亭')]),
    ('xenophon', r'Xenophon|[Mm]ayor', [('クセノフォン領主', 'クセノフォン町長'), ('トロイゼンの領主', 'トロイゼンの町長'),
                                         ('領主', '町長')]),
    ('duman', r'Duman|Dumas', [('ダマス', 'ドゥマン')]),
    ('portal', r'(?i)\bportals?\b', [('転移門', 'ポータル'), ('転送門', 'ポータル')]),
    # [P] = he/she, [O] = his/her are replaced by English words in the game
    ('pronouns', None, [(r'\[O\]の', '[C]の'), (r'\[O\]', '[C]の'), (r'\[P\]', '[C]')]),
]


def main(argv):
    tdir = argv[0]
    dry = '--dry-run' in argv
    jdir = os.path.join(tdir, 'ja')
    counts = {r[0]: 0 for r in RULES}
    for fn in sorted(os.listdir(jdir)):
        if not fn.endswith('.json'):
            continue
        cpath = os.path.join(tdir, 'chunks', fn)
        if not os.path.exists(cpath):
            continue
        en = {str(u['id']): u['en'] for u in json.load(open(cpath, encoding='utf-8'))['units']}
        path = os.path.join(jdir, fn)
        d = json.load(open(path, encoding='utf-8'))
        changed = False
        for k, v in list(d.items()):
            if k.startswith('_') or not isinstance(v, str):
                continue
            new = v
            for name, enrx, subs in RULES:
                if enrx and not re.search(enrx, en.get(k, '')):
                    continue
                for a, b in subs:
                    t = re.sub(a, b, new)
                    if t != new:
                        counts[name] += 1
                        new = t
            new = new.replace('[C]の[C]の', '[C]の')
            if new != v:
                d[k] = new
                changed = True
        if changed and not dry:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(d, f, ensure_ascii=False, indent=0)
    for k, v in counts.items():
        print(f'{k}: {v}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
