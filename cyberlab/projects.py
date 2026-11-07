"""Project discovery and non-destructive sample workspace creation."""
import json
from pathlib import Path
import re


def discover(base):
    base = Path(base).resolve(strict=True)
    return sorted(p.name for p in base.iterdir()
                  if not p.name.startswith('.') and not p.is_symlink() and p.is_dir())[:100]


def create(base, name, sample=False):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', name):
        raise ValueError('Use 1–64 letters, numbers, underscores or hyphens for the project name')
    root = Path(base).resolve(strict=True)/name
    root.mkdir(mode=0o700, exist_ok=False)
    if sample:
        route = root/'app/api/orders/[id]/route.ts'
        route.parent.mkdir(parents=True)
        route.write_text('export async function GET() {}\n', encoding='utf-8')
        (root/'cyberlab-test-fixture.json').write_text(json.dumps({
            'schema_version': 1, 'cases':[
                {'route':'/api/orders/[id]', 'requester':'customer_a', 'owner':'customer_b',
                 'observed_status':200, 'expected_status':403}]}, indent=2)+'\n', encoding='utf-8')
        (root/'cyberlab-live-plan.json').write_text(json.dumps({
            'schema_version': 1, 'base_url':'http://127.0.0.1:3999', 'cases':[
                {'route':'/api/orders/[id]', 'path':'/api/orders/1002', 'requester':'customer_a',
                 'owner':'customer_b', 'expected_status':403},
                {'route':'/api/orders/[id]', 'path':'/api/orders/1001', 'requester':'customer_a',
                 'owner':'customer_a', 'expected_status':200}]}, indent=2)+'\n', encoding='utf-8')
    return root
