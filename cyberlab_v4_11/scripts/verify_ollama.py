#!/usr/bin/env python3
"""Read-only live Ollama compatibility check; no target scans."""
import json, os, sys, urllib.request, urllib.error
BASE='http://127.0.0.1:11434'
MODEL=os.getenv('CYBERLAB_MODEL','llama3.2:latest')
def request(path,payload=None,timeout=45):
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(BASE+path,data=data,headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req,timeout=timeout) as res:
        raw=res.read(65537)
    if len(raw)>65536: raise ValueError('Ollama response too large')
    return json.loads(raw)
def main():
    try:
        models=request('/api/tags',timeout=5).get('models',[])
        names=[m.get('name','') for m in models]
        print('Ollama reachable; models:',', '.join(names) or '(none)')
        if MODEL not in names:
            print(f'ERROR: model {MODEL!r} not installed. Run: ollama pull {MODEL}')
            return 2
        response=request('/api/chat',{'model':MODEL,'stream':False,'format':'json',
            'options':{'temperature':0,'num_predict':96},'messages':[
                {'role':'system','content':'Return a JSON object with action and route. action must be inspect_route, route must be /api/orders/[id].'},
                {'role':'user','content':'Choose the route /api/orders/[id].'}]},timeout=90)
        content=response.get('message',{}).get('content','')
        parsed=json.loads(content)
        print('Structured Ollama response:',json.dumps(parsed,ensure_ascii=False)[:400])
        if parsed.get('action')!='inspect_route' or parsed.get('route')!='/api/orders/[id]':
            print('WARNING: Model responded, but did not follow requested structure/values.')
            return 3
        print('PASS: Live Ollama JSON response verified.')
        return 0
    except (OSError,ValueError,KeyError,urllib.error.URLError) as exc:
        print(f'FAIL: {type(exc).__name__}: {exc}')
        return 1
if __name__=='__main__':sys.exit(main())
