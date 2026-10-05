"""Trusted supervisor test fixture: owned child processes, no network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

mode, pid_path = sys.argv[1:3]
if mode == 'echo':
    job = json.load(sys.stdin)
    print(json.dumps({'job': job, 'secretInherited': 'WAKEIO_TEST_SECRET' in os.environ}))
else:
    child = subprocess.Popen([sys.executable, '-I', '-c', 'import time; time.sleep(60)'])
    Path(pid_path).write_text(json.dumps({'parent': os.getpid(), 'child': child.pid}))
    if mode == 'exit':
        print('{}', flush=True)
    elif mode == 'overflow':
        sys.stdout.write('x' * 65537)
        sys.stdout.flush()
        time.sleep(60)
    else:
        time.sleep(60)
