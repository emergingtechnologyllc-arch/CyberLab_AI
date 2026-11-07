#!/usr/bin/env python3
"""Optional Playwright development check; runs its own isolated CyberLab instance."""
import argparse
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    from playwright.sync_api import sync_playwright
    if args.screenshots: args.screenshots.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='cyberlab-browser-') as tmp:
        base = Path(tmp); (base/'projects').mkdir()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0)); port=sock.getsockname()[1]
        address=f'http://127.0.0.1:{port}'
        env=dict(os.environ,CYBERLAB_AUTO_INTELLIGENCE="0",CYBERLAB_DATA_DIR=str(base/'data'),CYBERLAB_PROJECTS_DIR=str(base/'projects'),CYBERLAB_V4_PORT=str(port))
        with (base/'server.log').open('w+') as log:
            process=subprocess.Popen(['bash','./start.sh'],cwd=ROOT,env=env,stdout=log,stderr=log)
            try:
                for _ in range(100):
                    if process.poll() is not None: raise AssertionError('Isolated server exited')
                    try:
                        with urllib.request.urlopen(address,timeout=1): break
                    except OSError: time.sleep(.05)
                else: raise AssertionError('Isolated server not ready')
                with sync_playwright() as pw:
                    executable=shutil.which('chromium') or shutil.which('google-chrome')
                    browser=pw.chromium.launch(headless=True,**({'executable_path':executable} if executable else {}))
                    page=browser.new_page(viewport={'width':1440,'height':1000})
                    errors=[]
                    page.on('pageerror',lambda error: errors.append(str(error)))
                    page.goto(address)
                    assert page.get_by_role('heading',name='A clearer view of your projects.').is_visible()
                    assert page.locator('main form').count()==0
                    if args.screenshots: page.screenshot(path=str(args.screenshots/'overview-empty.png'),full_page=True)
                    page.get_by_role('link',name='Add a project',exact=True).click()
                    page.get_by_label('Project name',exact=True).fill('sample-workspace')
                    page.get_by_label('Include a sample project').check()
                    page.get_by_label('I authorize creating this local project folder.').check()
                    page.get_by_role('button',name='Create project',exact=True).click()
                    assert page.get_by_role('status').inner_text().startswith('Project created')
                    page.get_by_role('link',name='Open workspace',exact=True).click()
                    assert page.locator('#workspace-project').input_value()=='sample-workspace'
                    page.get_by_label('I own this project or local target').check()
                    page.get_by_role('button',name='Start investigation',exact=True).click()
                    assert '/monitoring?' in page.url
                    assert page.get_by_text('Baseline established',exact=True).is_visible()
                    # Create a genuine filename change in the isolated project and compare via UI.
                    route=base/'projects/sample-workspace/app/api/reviews/route.ts'
                    route.parent.mkdir(parents=True); route.touch()
                    form=page.locator('form[action="/continuous/assess"]')
                    form.get_by_role('checkbox').check(); form.get_by_role('button',name='Compare routes now').click()
                    page.get_by_role('link',name='Change review #1',exact=True).click()
                    assert page.get_by_text('/api/reviews',exact=True).is_visible()
                    assert page.get_by_role('link',name='assessment:2',exact=True).is_visible()
                    if args.screenshots: page.screenshot(path=str(args.screenshots/'change-review.png'),full_page=True)
                    page.goto(address+'/verification?project=sample-workspace')
                    page.get_by_label('I own this local test application').check()
                    page.get_by_role('button',name='Run approved test',exact=True).click()
                    for _ in range(50):
                        page.reload()
                        if page.get_by_text('Completed',exact=True).count(): break
                        time.sleep(.05)
                    assert page.get_by_text('Completed',exact=True).is_visible()
                    page.goto(address+'/monitoring?project=sample-workspace')
                    page.get_by_role('checkbox',name='Enable monitoring').check()
                    form=page.locator('form[action="/monitor/configure"]')
                    assert not form.locator('input[name="use_ai"]').is_checked()
                    form.locator('input[name="authorized"]').check()
                    form.get_by_role('button',name='Save preferences').click()
                    assert page.get_by_role('checkbox',name='Enable monitoring').is_checked()
                    # Pause before leaving so no background work affects screenshot counts.
                    form=page.locator('form[action="/monitor/configure"]')
                    form.locator('input[name="enabled"]').uncheck(); form.locator('input[name="authorized"]').check()
                    form.get_by_role('button',name='Save preferences').click()
                    page.goto(address+'/')
                    if args.screenshots: page.screenshot(path=str(args.screenshots/'overview-desktop.png'),full_page=True)
                    for width,height in [(1440,1000),(768,1024),(390,844)]:
                        page.set_viewport_size({'width':width,'height':height})
                        for path in ['/','/projects','/investigations','/monitoring','/intelligence','/evidence','/verification','/settings','/help']:
                            response=page.goto(address+path+'?project=sample-workspace')
                            assert response.status==200,(path,response.status)
                            assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'),(width,path,'horizontal overflow')
                    if args.screenshots:
                        page.goto(address+'/'); page.screenshot(path=str(args.screenshots/'overview-mobile.png'),full_page=True)
                    assert not errors,errors
                    browser.close()
                print('PASS: browser project creation, investigation, change review, evidence, monitoring, and 27 responsive page checks')
            finally:
                process.terminate(); process.wait(timeout=25)


if __name__ == '__main__': main()
