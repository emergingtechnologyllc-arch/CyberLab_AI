#!/usr/bin/env python3
"""Reproducibly package source; allowlist excludes secrets and runtime data."""
import argparse
import hashlib
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
DOCS = ('README.md','CHANGELOG.md','ANALYSIS.md','TEST_RESULTS.md','start-cyberlab-v4.sh')


def build(destination):
    files = [ROOT/name for name in DOCS]
    for folder in ('cyberlab','scripts','tests'):
        files.extend(p for p in (ROOT/folder).rglob('*.py') if '__pycache__' not in p.parts)
    with ZipFile(destination,'w',compression=ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(files):
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
                raise ValueError('Refusing symlink or source outside release')
            entry = ZipInfo('cyberlab_v4_11/'+path.relative_to(ROOT).as_posix(),date_time=(2026,11,7,0,0,0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if path.name == 'start-cyberlab-v4.sh' else 0o100644) << 16
            entry.compress_type = ZIP_DEFLATED
            archive.writestr(entry,path.read_bytes(),compresslevel=9)
    with ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP integrity verification failed')
    print(destination)
    print('SHA256:',hashlib.sha256(Path(destination).read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT.parent/'cyberlab_v4_11.zip')
    args = parser.parse_args()
    if args.output.resolve().is_relative_to(ROOT):
        parser.error('Output must be outside the source tree')
    build(args.output)


if __name__ == '__main__': main()
