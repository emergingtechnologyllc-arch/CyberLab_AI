#!/usr/bin/env python3
"""Stage, test and activate a private local CyberLab installation. No sudo needed."""
import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import venv

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
from cyberlab import __version__
from cyberlab.distribution import source_files
from cyberlab.runtime import backup


def atomic_text(path,text,mode=0o600):
    path=Path(path)
    if path.is_symlink(): raise ValueError('Refusing to replace a configuration symlink')
    fd,tmp=tempfile.mkstemp(prefix='.cyberlab-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as file: file.write(text)
        os.chmod(tmp,mode); os.replace(tmp,path)
    finally:
        if Path(tmp).exists(): Path(tmp).unlink()


def systemd_quote(value):
    if any(ord(c)<32 for c in str(value)): raise ValueError('Control characters in deployment path')
    return '"'+str(value).replace('\\','\\\\').replace('"','\\"').replace('%','%%')+'"'


def service_unit(prefix):
    return ('# Managed by CyberLab installer.\n[Unit]\nDescription=CyberLab local security workspace\n'
        'After=network.target\n\n[Service]\nType=simple\n'
        'WorkingDirectory='+str(prefix/'current').replace('%','%%')+'\n'
        'ExecStart='+systemd_quote(prefix/'current/.venv/bin/python')+' '+systemd_quote(prefix/'run.py')+'\n'
        'Environment=PYTHONUNBUFFERED=1\nUMask=0077\nNoNewPrivileges=true\n'
        'Restart=on-failure\nRestartSec=5\nTimeoutStopSec=120\n\n[Install]\nWantedBy=default.target\n')


def activate(prefix,release,config):
    current=prefix/'current'
    if current.exists() and not current.is_symlink(): raise ValueError('Existing current path is not a managed symlink')
    if current.is_symlink():
        old=current.resolve()
        if not old.is_relative_to(prefix/'releases'): raise ValueError('Existing current link is outside managed releases')
        temporary=prefix/'.previous-next'
        if temporary.exists() or temporary.is_symlink(): raise ValueError('Previous activation was interrupted; inspect .previous-next')
        temporary.symlink_to(old); os.replace(temporary,prefix/'previous')
    atomic_text(release/'deployment.json',json.dumps(config,indent=2)+'\n')
    atomic_text(prefix/'run.py','''import json,os
from pathlib import Path
root=Path(__file__).resolve().parent
app=(root/'current').resolve()
config_path=app/'deployment.json'
config=json.loads((config_path if config_path.exists() else root/'config.json').read_text())
for key,value in [('CYBERLAB_DATA_DIR',config['data_dir']),('CYBERLAB_PROJECTS_DIR',config['projects_dir']),
                  ('CYBERLAB_MODEL',config['model']),('CYBERLAB_V4_PORT',str(config['port'])),
                  ('CYBERLAB_AUTO_INTELLIGENCE','1' if config['auto_intelligence'] else '0')]:
    os.environ.setdefault(key,value)
os.chdir(app); os.umask(0o077)
os.execv(str(app/'.venv/bin/python'),[str(app/'.venv/bin/python'),'-m','cyberlab.server'])
''')
    launcher='#!/usr/bin/env bash\nset -euo pipefail\nexec '+shlex.quote(str(prefix/'current/.venv/bin/python'))+' '+shlex.quote(str(prefix/'run.py'))+'\n'
    atomic_text(prefix/'start.sh',launcher,0o700)
    atomic_text(prefix/'cyberlab.service',service_unit(prefix))
    temporary=prefix/'.current-next'
    if temporary.exists() or temporary.is_symlink(): raise ValueError('Previous activation was interrupted; inspect .current-next')
    temporary.symlink_to(release); os.replace(temporary,current)
    atomic_text(prefix/'config.json',json.dumps(config,indent=2)+'\n')


def claim_prefix(prefix):
    marker=prefix/'.cyberlab-installation'
    if marker.is_symlink(): raise ValueError('Installation marker must not be a symlink')
    if marker.exists():
        if marker.read_text()!='cyberlab-managed-install-v1\n': raise ValueError('Unrecognized installation marker')
        return
    managed=('current','previous','config.json','run.py','start.sh','cyberlab.service')
    if any((prefix/name).exists() or (prefix/name).is_symlink() for name in managed):
        raise ValueError('Prefix contains unmanaged files; choose a new --prefix and preserve the existing directory')
    atomic_text(marker,'cyberlab-managed-install-v1\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix',type=Path,default=Path.home()/'.local/share/cyberlab')
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--projects-dir',type=Path)
    parser.add_argument('--model')
    parser.add_argument('--port',type=int)
    parser.add_argument('--auto-intelligence',action=argparse.BooleanOptionalAction,default=None)
    parser.add_argument('--enable-service',action='store_true',help='Install and start/restart a systemd user service')
    args=parser.parse_args()
    if os.geteuid()==0: parser.error('Install as your normal user, not root')
    os.umask(0o077)
    prefix=args.prefix.expanduser().resolve()
    prefix.mkdir(mode=0o700,parents=True,exist_ok=True)
    lock=(prefix/'.install.lock').open('a')
    try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: parser.error('Another CyberLab installer is running for this prefix')
    claim_prefix(prefix)
    config_path=prefix/'config.json'
    if config_path.is_symlink(): parser.error('Configuration must not be a symlink')
    existing=json.loads(config_path.read_text()) if config_path.exists() else {}
    data=(args.data_dir or Path(existing.get('data_dir',os.getenv('CYBERLAB_DATA_DIR',str(Path.home()/'.cyberlab-v4'))))).expanduser().resolve()
    projects=(args.projects_dir or Path(existing.get('projects_dir',os.getenv('CYBERLAB_PROJECTS_DIR',str(Path.home()/'CyberLab-Projects'))))).expanduser().resolve()
    port=args.port if args.port is not None else int(existing.get('port',8780))
    if not 1024<=port<=65535: parser.error('Port must be 1024–65535')
    model=args.model or existing.get('model') or os.getenv('CYBERLAB_MODEL','llama3.2:latest')
    if len(model)>200 or any(ord(c)<32 for c in model): parser.error('Invalid model name')
    config=dict(release=__version__,data_dir=str(data),projects_dir=str(projects),port=port,model=model,
                auto_intelligence=args.auto_intelligence if args.auto_intelligence is not None else existing.get('auto_intelligence',True))
    # Validate all distribution inputs before touching an existing deployment.
    files=source_files(SOURCE)
    unit_path=Path.home()/'.config/systemd/user/cyberlab.service'
    if args.enable_service:
        if not shutil.which('systemctl'): parser.error('systemctl is unavailable; install without --enable-service and use the stable launcher')
        if unit_path.is_symlink() or (unit_path.exists() and not unit_path.read_text().startswith('# Managed by CyberLab installer.')):
            parser.error('An unmanaged service unit exists; preserve it and review the generated unit manually')
        check=subprocess.run(['systemctl','--user','show','--property=Version'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        if check.returncode: parser.error('The user service manager is unavailable; install without --enable-service')
        active=subprocess.run(['systemctl','--user','is-active','--quiet','cyberlab.service']).returncode==0
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1',port))==0 and not active:
                parser.error('Another application is using this port. Stop the old CyberLab terminal first.')
    for path in (data,projects): path.mkdir(mode=0o700,parents=True,exist_ok=True)
    database=data/'investigations.sqlite3'
    if database.exists():
        stamp=dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        target=data/'backups'/f'before-install-{__version__}-{stamp}.sqlite3'
        print('Database backup:',backup(database,target),flush=True)
    releases=prefix/'releases'; releases.mkdir(mode=0o700,exist_ok=True)
    release=Path(tempfile.mkdtemp(prefix=__version__+'-',dir=releases))
    activated=False
    try:
        for path in files:
            destination=release/path.relative_to(SOURCE)
            destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            shutil.copy2(path,destination)
        print('Preparing verified production runtime:',release,flush=True)
        try: venv.EnvBuilder(with_pip=True).create(release/'.venv')
        except Exception as exc:
            raise RuntimeError('Python venv support is required. On Ubuntu install python3-venv, then rerun.') from exc
        python=release/'.venv/bin/python'
        subprocess.run([str(python),'-m','pip','install','--disable-pip-version-check','--no-cache-dir','--no-index',
                        '--find-links',str(release/'vendor'),'--require-hashes','-r',str(release/'requirements.txt')],check=True)
        subprocess.run([str(python),'scripts/smoke_test.py'],cwd=release,check=True)
        activate(prefix,release,config); activated=True
        if args.enable_service:
            unit_path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            atomic_text(unit_path,service_unit(prefix))
            subprocess.run(['systemctl','--user','daemon-reload'],check=True)
            subprocess.run(['systemctl','--user','enable','cyberlab.service'],check=True)
            subprocess.run(['systemctl','--user','restart','cyberlab.service'],check=True)
            print('User service started. Check: systemctl --user status cyberlab.service',flush=True)
        print('\nInstalled CyberLab',__version__,flush=True)
        print('Stable start command:',shlex.quote(str(prefix/'start.sh')),flush=True)
        print('Data:',data,'\nProjects:',projects,flush=True)
        print('Open: http://127.0.0.1:'+str(port),flush=True)
        print('Public intelligence auto-refresh:',config['auto_intelligence'],flush=True)
        if not args.enable_service: print('No system service was started. Run the stable start command above.',flush=True)
    finally:
        if not activated and not ((prefix/'current').is_symlink() and (prefix/'current').resolve()==release):
            shutil.rmtree(release)
        lock.close()


if __name__=='__main__':
    try: main()
    except (OSError,ValueError,RuntimeError,subprocess.CalledProcessError) as exc:
        print('Installation failed:',str(exc),file=sys.stderr); raise SystemExit(1)
