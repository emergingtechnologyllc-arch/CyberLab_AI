#!/usr/bin/env python3
"""Create a sample in the configured projects folder, preserving existing files."""
import os
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cyberlab import projects

base=Path(os.getenv('CYBERLAB_PROJECTS_DIR',str(Path.home()/'CyberLab-Projects')))
base.mkdir(mode=0o700,parents=True,exist_ok=True)
root=base/'demo'
if root.exists() or root.is_symlink():
    print('Existing demo preserved:',root)
else:
    root=projects.create(base,'demo',sample=True)
    print('Sample project created:',root)
