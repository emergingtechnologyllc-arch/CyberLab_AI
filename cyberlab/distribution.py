"""Shared release allowlist and vendored dependency verification."""
import hashlib
from pathlib import Path
import re

DOCUMENTS=('README.md','CHANGELOG.md','ANALYSIS.md','TEST_RESULTS.md','HOW_TO_USE.md',
           'PRODUCTION.md','THIRD_PARTY.md','requirements.txt','start.sh','start-cyberlab-v4.sh')


def source_files(root):
    root=Path(root).resolve()
    files=[root/name for name in DOCUMENTS]
    for folder in ('cyberlab','scripts','tests'):
        files.extend(p for p in (root/folder).rglob('*.py') if '__pycache__' not in p.parts)
    files.extend((root/'cyberlab/assets').glob('*.css'))
    for name in ('overview.png','intelligence.png','CyberLab-How-To-Use.pdf'):
        if (root/'docs'/name).is_file(): files.append(root/'docs'/name)
    hashes=set(re.findall(r'--hash=sha256:([a-f0-9]{64})',(root/'requirements.txt').read_text()))
    wheels=list((root/'vendor').glob('*.whl'))
    if not wheels: raise ValueError('The verified production runtime wheel is missing')
    for wheel in wheels:
        if hashlib.sha256(wheel.read_bytes()).hexdigest() not in hashes:
            raise ValueError('Vendored dependency checksum does not match the requirements lock')
    files.extend(wheels)
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(root) or not path.is_file():
            raise ValueError('Missing or unsafe release file: '+path.name)
    return sorted(files)
