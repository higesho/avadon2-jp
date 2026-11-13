"""Prepare the named jobs (from jobs.json) with prep_job.py.

usage: python -I prep_batch.py TRANS_DIR JOB [JOB ...]
"""
import json
import os
import subprocess
import sys

tdir, names = sys.argv[1], sys.argv[2:]
jobs = {j['name']: j for j in json.load(open(os.path.join(tdir, 'jobs.json'), encoding='utf-8'))}
here = os.path.dirname(os.path.abspath(__file__))
for n in names:
    subprocess.run([sys.executable, '-I', os.path.join(here, 'prep_job.py'), tdir, n] + jobs[n]['chunks'], check=True)
