#!/usr/bin/env python3
"""Create local synthetic demo in CyberLab-Projects."""
from pathlib import Path
import json
root=Path.home()/'CyberLab-Projects'/'demo'
route=root/'app'/'api'/'orders'/'[id]'/'route.ts'
route.parent.mkdir(parents=True,exist_ok=True)
if not route.exists():route.write_text('export async function GET() {}\n')
plan=root/'cyberlab-live-plan.json'
if plan.exists():
    print('Existing plan preserved:',plan)
else:
    plan.write_text(json.dumps({'schema_version':1,'base_url':'http://127.0.0.1:3999','cases':[
        {'route':'/api/orders/[id]','path':'/api/orders/1002','requester':'customer_a','owner':'customer_b','expected_status':403},
        {'route':'/api/orders/[id]','path':'/api/orders/1001','requester':'customer_a','owner':'customer_a','expected_status':200}]},indent=2)+'\n')
    print('Created:',plan)
print('Demo ready:',root)
