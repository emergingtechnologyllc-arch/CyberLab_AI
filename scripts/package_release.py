#!/usr/bin/env python3
"""Reproducibly package source; allowlist excludes secrets and runtime data."""
import argparse
import hashlib
import sys
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from cyberlab import __version__
from cyberlab.distribution import source_files


def build(destination):
    files = source_files(ROOT)
    with ZipFile(destination,'w',compression=ZIP_DEFLATED,compresslevel=9) as archive:
        for path in sorted(files):
            if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
                raise ValueError('Refusing symlink or source outside release')
            entry = ZipInfo('cyberlab-ai/'+path.relative_to(ROOT).as_posix(),date_time=(2026,11,7,0,0,0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if path.name in ('start.sh','start-cyberlab-v4.sh') else 0o100644) << 16
            entry.compress_type = ZIP_DEFLATED
            archive.writestr(entry,path.read_bytes(),compresslevel=9)
    with ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError('ZIP integrity verification failed')
    print('CyberLab',__version__)
    print(destination)
    print('SHA256:',hashlib.sha256(Path(destination).read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'cyberlab-ai.zip')
    args = parser.parse_args()
    if args.output.suffix != '.zip' or args.output.is_symlink() or (args.output.resolve().is_relative_to(ROOT) and args.output.resolve().parent != ROOT):
        parser.error('Output must be a ZIP at the repository root or outside the source tree')
    build(args.output)


if __name__ == '__main__': main()
