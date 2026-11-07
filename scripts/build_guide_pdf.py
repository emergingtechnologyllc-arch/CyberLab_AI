#!/usr/bin/env python3
"""Optional release tool: print the running app's bundled guide using Chromium."""
import argparse
from pathlib import Path
import shutil
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',help='Optionally print a running local /help page; default uses the bundled source document')
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'docs/CyberLab-How-To-Use.pdf')
    args=parser.parse_args()
    from urllib.parse import urlsplit
    parsed=urlsplit(args.url) if args.url else None
    if parsed and (parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or parsed.path!='/help' or parsed.username):
        parser.error('Use the local /help page only')
    from playwright.sync_api import sync_playwright
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with sync_playwright() as pw:
        browser=pw.chromium.launch(headless=True,executable_path=shutil.which('chromium') or shutil.which('google-chrome'))
        page=browser.new_page()
        if args.url:
            response=page.goto(args.url)
            if response.status!=200: raise ValueError('Guide endpoint unavailable')
        else:
            root=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(root))
            from cyberlab import guide,__version__
            css=(root/'cyberlab/assets/app.css').read_text()
            page.set_content('<!doctype html><html lang="en"><head><meta charset="utf-8"><title>How to Use · CyberLab '+__version__+'</title><style>'+css+'</style></head><body><main class="content">'+guide.render()+'</main></body></html>')
        page.locator('.guide-toc').evaluate('(element) => element.open = true')
        page.pdf(path=str(args.output),format='A4',print_background=True,
                 margin={'top':'16mm','bottom':'18mm','left':'16mm','right':'16mm'},display_header_footer=True,
                 header_template='<span></span>',
                 footer_template='<div style="font-size:9px;width:100%;text-align:center;color:#607780">CyberLab · How to Use · <span class="pageNumber"></span> / <span class="totalPages"></span></div>')
        browser.close()
    print(args.output)


if __name__=='__main__': main()
