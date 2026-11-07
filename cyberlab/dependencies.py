"""Read bounded npm lockfiles without executing packages or exposing registry URLs."""
import hashlib
import json
from pathlib import Path
import re

MAX_BYTES=4_000_000
MAX_COMPONENTS=3000
NAME=re.compile(r'(?:@[-a-zA-Z0-9_.]+/)?[-a-zA-Z0-9_.]+')
VERSION=re.compile(r'(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?')


def read_json(root,name,cap):
    path=root/name
    if path.is_symlink(): raise ValueError('Symlinked '+name+' is not supported')
    if not path.exists(): return None,None
    if path.is_symlink() or not path.is_file() or path.stat().st_size>cap: raise ValueError('Missing, symlinked or oversized '+name)
    raw=path.read_bytes()
    if len(raw)>cap: raise ValueError(name+' exceeds input budget')
    data=json.loads(raw)
    if not isinstance(data,dict): raise ValueError(name+' must be a JSON object')
    return data,hashlib.sha256(raw).hexdigest()


def fingerprint(snapshot):
    return hashlib.sha256((snapshot['manifest_hash']+':'+(snapshot['lock_hash'] or '')).encode()).hexdigest()


def inventory(project,base):
    root=Path(project).resolve(strict=True); approved=Path(base).resolve(strict=True)
    if root==approved or not root.is_dir() or not root.is_relative_to(approved): raise ValueError('Select a project inside the approved root')
    manifest,manifest_hash=read_json(root,'package.json',128000)
    if manifest is None: raise ValueError('Regular package.json is required')
    declared={}
    for group in ('dependencies','devDependencies','optionalDependencies'):
        values=manifest.get(group,{})
        if not isinstance(values,dict): raise ValueError('Dependency groups must be JSON objects')
        for name,spec in values.items():
            if isinstance(name,str) and NAME.fullmatch(name) and isinstance(spec,str): declared[name]=spec[:100]
    if len(declared)>MAX_COMPONENTS: raise ValueError('Manifest exceeds component budget')
    lock=None; lock_hash=None; lock_name=''
    # npm gives shrinkwrap precedence over package-lock.
    for filename in ('npm-shrinkwrap.json','package-lock.json'):
        candidate,digest=read_json(root,filename,MAX_BYTES)
        if candidate is not None: lock=candidate; lock_hash=digest; lock_name=filename; break
    components=[]; unresolved=[]
    def add(name,version,path,direct=False):
        if len(components)>=MAX_COMPONENTS: raise ValueError('Lockfile exceeds component budget')
        if not NAME.fullmatch(name) or not isinstance(version,str) or not VERSION.fullmatch(version):
            unresolved.append('unresolved lock entry'); return
        components.append(dict(name=name,version=version,path=path[:400],direct=bool(direct),provenance='lockfile_resolved'))
    consistent=True; stale_names=[]
    if lock is not None:
        version=lock.get('lockfileVersion')
        if type(version) is not int or version not in (1,2,3): raise ValueError('Supported npm lockfile versions are 1, 2 and 3')
        if version in (2,3):
            packages=lock.get('packages')
            if not isinstance(packages,dict) or len(packages)>MAX_COMPONENTS+1: raise ValueError('Invalid or oversized lockfile package map')
            for path,item in packages.items():
                if not isinstance(path,str) or not isinstance(item,dict): raise ValueError('Invalid lockfile entry')
                if not path: continue
                if '..' in Path(path).parts or path.startswith('/') or '\\' in path: raise ValueError('Invalid lockfile package path')
                if item.get('link'):
                    unresolved.append('workspace/link entry'); continue
                if 'node_modules/' not in path:
                    unresolved.append('non-registry workspace entry'); continue
                inferred=path.rsplit('node_modules/',1)[1]
                # npm aliases identify the actual registry package in its name field.
                name=item.get('name',inferred)
                if not isinstance(name,str): raise ValueError('Invalid package name')
                direct=path=='node_modules/'+inferred and inferred in declared
                add(name,item.get('version'),path,direct)
            root_entry=packages.get('',{})
            if not isinstance(root_entry,dict): raise ValueError('Invalid root lock entry')
            locked_declared={}
            for group in ('dependencies','devDependencies','optionalDependencies'):
                values=root_entry.get(group,{})
                if not isinstance(values,dict): raise ValueError('Invalid root dependency declarations')
                locked_declared.update(values)
            stale_names=[name for name,spec in declared.items() if locked_declared.get(name)!=spec]
            if any(name not in declared for name in locked_declared): stale_names.append('removed manifest dependency')
        else:
            entries=lock.get('dependencies',{})
            def walk(items,prefix='',depth=0):
                if not isinstance(items,dict) or depth>30: raise ValueError('Invalid lockfile dependency tree')
                for name,item in items.items():
                    if not isinstance(name,str) or not isinstance(item,dict): raise ValueError('Invalid lockfile package')
                    path=prefix+'node_modules/'+name
                    add(name,item.get('version'),path,not prefix and name in declared)
                    walk(item.get('dependencies',{}),path+'/',depth+1)
            walk(entries)
            # v1 has no root manifest declarations to establish consistency.
            unresolved.append('v1 manifest consistency cannot be established')
        resolved_top={c['path'].split('/')[1] if not c['path'].startswith('node_modules/@') else '/'.join(c['path'].split('/')[1:3]) for c in components if c['direct']}
        for name in declared:
            if name not in resolved_top: unresolved.append('missing direct dependency: '+name)
        consistent=not stale_names and not unresolved
        if stale_names: unresolved.append('manifest/lock mismatch: '+', '.join(stale_names[:10]))
    else:
        for name,spec in declared.items():
            safe_spec=spec if re.fullmatch(r'[0-9a-zA-Z.*^~<>=|+ -]{1,100}',spec) else '(unresolved)'
            components.append(dict(name=name,version=safe_spec,path='package.json',direct=True,
                                   provenance='manifest_exact' if VERSION.fullmatch(spec) else 'manifest_range'))
        unresolved.append('No supported npm lockfile; declared versions are not installation evidence')
        consistent=False
    # No resolved URL, integrity token, auth settings, scripts or source contents are returned.
    pairs=[]; seen=set()
    for component in components:
        key=(component['name'],component['version'])
        if key not in seen:
            seen.add(key); pairs.append(dict(component,locations_count=1))
        else:
            existing=next(c for c in pairs if (c['name'],c['version'])==key)
            existing['locations_count']+=1
            if component['direct']: existing['direct']=True; existing['path']=component['path']
    return dict(project=root.name,root=str(root),manifest_hash=manifest_hash,lockfile=lock_name,
        lock_hash=lock_hash,components=pairs,occurrences=len(components),resolved_from_lock=lock is not None,
        consistency_verified=consistent,coverage_notes=unresolved[:25],
        limitation='Lockfiles describe a resolved dependency tree; the deployed installation and reachability are not verified.')
