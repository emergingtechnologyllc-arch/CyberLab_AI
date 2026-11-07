"""Render the bundled, trusted how-to document without scripts or raw HTML."""
import html
from pathlib import Path
import re

DOCUMENT=Path(__file__).resolve().parents[1]/'HOW_TO_USE.md'


def inline(text):
    text=html.escape(text,quote=True)
    text=re.sub(r'`([^`]+)`',r'<code>\1</code>',text)
    return re.sub(r'\*\*([^*]+)\*\*',r'<strong>\1</strong>',text)


def render():
    output=[]; paragraph=[]; code=[]; headings=[]; in_code=False; listing=None
    def flush():
        if paragraph: output.append('<p>'+inline(' '.join(paragraph))+'</p>'); paragraph.clear()
    def close_list():
        nonlocal listing
        if listing: output.append(f'</{listing}>'); listing=None
    for line in DOCUMENT.read_text(encoding='utf-8').splitlines():
        if line.startswith('```'):
            flush(); close_list()
            if in_code: output.append('<pre>'+html.escape('\n'.join(code))+'</pre>'); code=[]
            in_code=not in_code; continue
        if in_code: code.append(line); continue
        if not line.strip(): flush(); close_list(); continue
        if line.startswith('#'):
            flush(); close_list()
            level=min(len(line)-len(line.lstrip('#')),4)
            title=line.lstrip('# ').strip(); anchor=re.sub(r'[^a-z0-9]+','-',title.lower()).strip('-')
            if level==2: headings.append((anchor,title))
            output.append(f'<h{level} id="{anchor}">{inline(title)}</h{level}>'); continue
        match=re.match(r'^(?:([-*]) |(\d+)\. )(.*)',line)
        if match:
            flush(); kind='ul' if match[1] else 'ol'
            if listing!=kind:
                close_list(); output.append('<ol start="'+str(int(match[2]))+'">' if kind=='ol' else '<ul>'); listing=kind
            output.append('<li>'+inline(match[3])+'</li>'); continue
        if listing and line.startswith('  ') and output and output[-1].endswith('</li>'):
            output[-1]=output[-1][:-5]+' '+inline(line.strip())+'</li>'; continue
        close_list(); paragraph.append(line)
    flush(); close_list()
    if code: output.append('<pre>'+html.escape('\n'.join(code))+'</pre>')
    toc='<details class="guide-toc"><summary>Jump to a section ('+str(len(headings))+' topics)</summary><ul>'+''.join('<li><a href="#'+anchor+'">'+inline(title)+'</a></li>' for anchor,title in headings)+'</ul></details>'
    output.insert(2,toc)
    return '<article class="panel how-to">'+''.join(output)+'</article>'
