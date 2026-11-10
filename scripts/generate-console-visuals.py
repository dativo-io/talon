#!/usr/bin/env python3
"""Build an accurate, screenshot-derived Talon UI showcase and docs crops.

Usage: python3 scripts/generate-console-visuals.py <playwright-capture-dir> <output-dir>
Requires Pillow; input from CONSOLE_SCREENSHOTS Playwright fixture, never mocked UI.
"""
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

SRC = Path(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)

# Meaningful, full-width above-the-fold crops; preserve original UI pixels.
SHOTS = {
    'overview-attention': ('light-13-overview-case-g.png', 0, 800),
    'use-case-summary': ('light-03-use-case.png', 0, 925),
    'session-investigation': ('light-18-session-proof.png', 0, 1120),
    'evidence-verification': ('light-16-evidence-export-denied.png', 0, 1180),
    'costs': ('light-17-costs-all-tenants.png', 0, 750),
    'configuration': ('light-09-configuration.png', 0, 920),
    'system-diagnostics': ('light-14-system-case-g.png', 0, 1100),
    'tamper-detection': ('light-07-evidence-tampered.png', 0, 960),
    'overview-mobile': ('light-12-overview-mobile.png', 0, 1400),
}
for name, (filename, y0, y1) in SHOTS.items():
    original = Image.open(SRC / filename).convert('RGB')
    cropped = original.crop((0, y0, original.width, min(y1, original.height)))
    cropped.save(OUT / f'{name}.webp', format='WEBP', quality=84, method=6)

W, H = 1920, 1550
BG = (245, 248, 255)
canvas = Image.new('RGB', (W, H), BG)
draw = ImageDraw.Draw(canvas)
NAVY = '#101d35'; MUTED = '#56657e'; BLUE = '#2459db'
font_path = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'
bold_path = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'
def font(sz, bold=False): return ImageFont.truetype(bold_path if bold else font_path, sz)

draw.rounded_rectangle((54, 54, 112, 112), radius=16, fill=BLUE)
draw.text((133, 42), 'Talon Operations Console', fill=NAVY, font=font(62, True))
draw.text((57, 135), 'Operational readiness · Governed AI use cases · Investigations · Costs · Verifiable evidence', fill=MUTED, font=font(25))

def frame(x, y, w, h, slug, title, subtitle):
    # The image inside the frame is a crop of an actual Playwright screenshot.
    # Keep native page labels; don't manufacture UI controls or statuses.
    screen = Image.open(OUT / (slug + '.webp')).convert('RGB')
    pad, top, bottom = 16, 16, 100
    area_w, area_h = w - 2*pad, h - top - bottom
    ratio = max(area_w/screen.width, area_h/screen.height)
    # Prefer fitting to width, allowing a natural vertical crop at the bottom.
    ratio = area_w/screen.width
    screen = screen.resize((area_w, round(screen.height*ratio)), Image.Resampling.LANCZOS)
    viewport = Image.new('RGB', (area_w, area_h), 'white')
    viewport.paste(screen.crop((0, 0, area_w, min(area_h, screen.height))), (0, 0))
    shadow = Image.new('RGBA', (w+30, h+30), (0,0,0,0))
    sd = ImageDraw.Draw(shadow)
    sd.rounded_rectangle((15, 12, w+15, h+12), radius=20, fill=(30, 51, 85, 33))
    shadow=shadow.filter(ImageFilter.GaussianBlur(12))
    canvas.paste(shadow, (x-15,y-15), shadow)
    draw.rounded_rectangle((x,y,x+w,y+h), radius=17, fill='white', outline='#d8e2f2', width=2)
    canvas.paste(viewport, (x+pad,y+top))
    draw.rectangle((x+pad,y+top+area_h-1,x+w-pad,y+top+area_h+1), fill='#e7edf8')
    draw.text((x+24, y+h-82), title, fill=NAVY, font=font(27, True))
    draw.text((x+24, y+h-42), subtitle, fill=MUTED, font=font(17))

left=55; gap=32; half=(W-2*left-gap)//2
frame(left, 218, half, 448, 'overview-attention', 'Overview', 'Problem-first operational readiness and findings')
frame(left+half+gap, 218, half, 448, 'use-case-summary', 'AI Use Case', 'Summary, activity, policy and runtime, costs')
frame(left, 699, half, 448, 'session-investigation', 'Session Investigation', 'A recorded request timeline with distinct outcomes')
frame(left+half+gap, 699, half, 448, 'evidence-verification', 'Evidence Verification', 'Signed decision, dispatch facts and proof limits')
third=(W-2*left-2*gap)//3
frame(left, 1180, third, 280, 'costs', 'Costs', 'Spend and caps; currency-aware')
frame(left+third+gap, 1180, third, 280, 'configuration', 'Configuration', 'Shared policy and use-case declarations')
frame(left+2*(third+gap), 1180, third, 280, 'system-diagnostics', 'System', 'Process state and startup-failure diagnostics')
draw.text((58, 1495), 'Real console screenshots · Synthetic Playwright fixture · Some runtime failures are intentionally induced', fill=MUTED, font=font(17))
canvas.save(OUT / 'showcase.webp', format='WEBP', quality=83, method=6)
print('Generated:', ', '.join(f.name for f in OUT.iterdir() if f.suffix=='.webp'))