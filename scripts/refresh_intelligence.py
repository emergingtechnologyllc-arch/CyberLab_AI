#!/usr/bin/env python3
"""Refresh fixed public reference sources; never uploads project data."""
import argparse
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cyberlab import knowledge


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-dir',type=Path,default=Path(os.getenv('CYBERLAB_DATA_DIR',str(Path.home()/'.cyberlab-v4'))))
    parser.add_argument('--source',choices=['all',*knowledge.SOURCES],default='all')
    parser.add_argument('--status',action='store_true',help='Report cache status without network requests')
    args=parser.parse_args(); args.data_dir.mkdir(mode=0o700,parents=True,exist_ok=True)
    path=args.data_dir/'investigations.sqlite3'
    result=0
    if not args.status:
        for source in knowledge.SOURCES if args.source=='all' else [args.source]:
            status=knowledge.refresh(str(path),source,manual=True)
            print(source,status,flush=True)
            if status not in ('updated','unchanged'): result=1
    for source in knowledge.status(str(path)):
        print(source['source'],source['record_count'],'records; success:',source['succeeded'] or 'never',
              '; stale:',source['stale'],'; error:',source['error_code'] or 'none',flush=True)
        if source['coverage']: print(source['coverage'],flush=True)
    return result


if __name__=='__main__': raise SystemExit(main())
