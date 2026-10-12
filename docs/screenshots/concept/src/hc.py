from hc_common import *
def page(body,css=''):return HEAD.format(CSS+css,body)
# 1 chat list / overview
conv='''<div class="main"><div style="padding:18px 24px;border-bottom:1px solid #1d1b15;display:flex;align-items:center;gap:12px">
<div class="av" style="background:#FFD24A">A</div><div><div class="cn">Alice</div><div class="cs mono">onion · …x7q4d.onion</div></div><span class="sp"></span>
<span class="pill ok">✓ Verified (SAS)</span><span class="pill" style="border:1px solid #2a2820;color:#a59e80">⏱ disappear 1h</span></div>
<div style="flex:1;display:flex;flex-direction:column;padding:20px 24px">
<div style="align-self:center;font-size:12px;color:#6d6a5e;margin:6px 0 14px" class="mono">— session ratchet established · via Tor v3 —</div>
<div class="b in">Are we still on for Thursday? I rotated my onion yesterday.<div class="meta mono">09:12 · via Tor v3 · Double Ratchet</div></div>
<div class="b out">Yes. Got your new signed contact link, signature checks out.<div class="meta mono">09:13 · delivered</div></div>
<div class="b in">Perfect. Sending the draft as a binary, accept with :binary-accept.<div class="meta mono">09:14 · via Tor v3</div></div>
<div class="b in" style="display:flex;gap:12px;align-items:center"><div style="width:36px;height:36px;border-radius:10px;background:#1f1d17;display:grid;place-items:center">📄</div><div>notes.pdf · 214 KB<div class="meta mono">waiting for :binary-accept</div></div></div>
<div class="b out">🎙 Voice note · 0:18<div class="meta mono">09:16 · chunk wiped after playback</div></div></div>
<div class="input">Message Alice over Tor…<span class="sp"></span><span class="kbd">Enter</span></div></div>'''
open('hc1.html','w').write(page(f'<div class="win app">{TOP}{side(0)}{conv}{FOOT}</div>'))
# 2 safety / verification
ver='''<div class="main" style="align-items:center;justify-content:center">
<div style="width:620px;background:#0f0f11;border:1px solid #2a2618;border-radius:20px;padding:34px">
<div style="display:flex;align-items:center;gap:12px"><div class="av" style="background:#C4A8FF">M</div><div><div class="cn" style="font-size:20px">Verify Marek</div><div class="cs">Compare this short authentication string over another channel</div></div></div>
<div class="mono" style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:28px 0">'''+''.join(f'<div style="background:#151410;border:1px solid #3a321a;border-radius:12px;padding:16px;text-align:center;font-size:24px;color:#FFD24A;letter-spacing:.1em">{w}</div>' for w in ['4821','0937','5164','2290','7713','3058','6402','1185'])+'''</div>
<div style="background:rgba(224,82,82,.07);border:1px solid rgba(224,82,82,.3);border-radius:12px;padding:14px;font-size:14px;color:#ffb1b1">Unverified: messages are blocked until you verify, or you explicitly use <span class="mono">:send-unverified</span>.</div>
<div style="display:flex;gap:12px;margin-top:22px"><div style="flex:1;text-align:center;padding:14px;border-radius:12px;background:linear-gradient(135deg,#FFD24A,#E8B400);color:#111;font-weight:700">✓ Numbers match · :verify</div><div style="flex:1;text-align:center;padding:14px;border-radius:12px;border:1px solid #3a2020;color:#ff8a8a;font-weight:600">They don't match · :block</div></div>
<div class="mono cs" style="margin-top:18px;text-align:center">fingerprint 9F3A · 22C1 · 7B0E · D41F · 6A90 · 18E3</div></div></div>'''
open('hc2.html','w').write(page(f'<div class="win app">{TOP}{side(1)}{ver}{FOOT}</div>'))
# 3 contact link / QR add
import random;random.seed(7)
cells=''.join(f'<i style="background:{"#FFD24A" if (random.random()<.5 or (r<7 and c<7) or (r<7 and c>17) or (r>17 and c<7)) and not ((1<r<5 and 1<c<5)) else "transparent"}"></i>' for r in range(25) for c in range(25))
add=f'''<div class="main" style="flex-direction:row;align-items:center;justify-content:center;gap:40px">
<div style="width:420px;background:#0f0f11;border:1px solid #2a2618;border-radius:20px;padding:30px;text-align:center">
<div class="cn" style="font-size:19px">My contact · <span class="mono gold">:my-contact</span></div><div class="cs" style="margin:6px 0 20px">Signed contact link. No phone, no account.</div>
<div style="background:#0a0a0a;border:1px solid #3a321a;border-radius:16px;padding:20px;display:inline-block"><div style="display:grid;grid-template-columns:repeat(25,10px);gap:0">{cells}</div></div>
<div class="mono" style="margin-top:18px;font-size:12px;color:#a59e80;word-break:break-all;background:#121214;border-radius:10px;padding:10px">hashchat://v1/qw7…x7q4d.onion#sig=ed25519:Kp9…</div>
<div class="cs" style="margin-top:10px">QR rendering is a concept · link format is real (Contact Link v1)</div></div>
<div style="width:460px;background:#0f0f11;border:1px solid #2a2618;border-radius:20px;padding:30px">
<div class="cn" style="font-size:19px">Add contact · <span class="mono gold">:add-contact</span></div>
<div class="search mono" style="margin:18px 0;color:#d6d0b6">hashchat://v1/m3k…a9pz.onion#sig=…</div>
<div style="display:flex;flex-direction:column;gap:10px;font-size:14px">
<div><span class="pill ok">✓</span> Signature valid (Ed25519)</div><div><span class="pill ok">✓</span> v3 onion address well-formed</div><div><span class="pill tor">◎</span> Will connect only through Tor</div><div><span class="pill bad">!</span> Not yet verified, compare SAS next</div></div>
<div style="margin-top:22px;text-align:center;padding:14px;border-radius:12px;background:linear-gradient(135deg,#FFD24A,#E8B400);color:#111;font-weight:700">Add as “Ines”</div></div></div>'''
open('hc3.html','w').write(page(f'<div class="win app">{TOP}{side(2)}{add}{FOOT}</div>','.main i{width:10px;height:10px;display:block}'))
# 4 android
phone=lambda inner:f'<div style="width:390px;height:820px;border-radius:48px;background:#050505;border:10px solid #1a1a1c;box-shadow:0 40px 120px rgba(0,0,0,.8),0 0 0 1px #333;overflow:hidden;display:flex;flex-direction:column">{inner}</div>'
sb='<div class="mono" style="display:flex;justify-content:space-between;padding:14px 26px 6px;font-size:12px;color:#aaa"><span>09:41</span><span>◉ ▮▮▮</span></div>'
p1=sb+'''<div style="padding:10px 20px;display:flex;align-items:center"><div class="brand" style="font-size:22px">#<b>Hash</b>Chat</div><span class="sp"></span><span class="pill tor" style="font-size:11px"><span class="dot"></span>Tor</span></div>
<div style="margin:6px 16px 10px;padding:10px 14px;border-radius:12px;background:rgba(255,210,74,.08);border:1px solid rgba(255,210,74,.25);font-size:12px;color:#FFD24A">Fail-closed · nothing leaves without Tor</div>'''+''.join(f'<div class="c" style="margin:0 10px"><div class="av" style="background:{AVC[i]}">{n[0]}</div><div><div class="cn">{n}</div><div class="cs">{s}</div></div></div>' for i,(n,s) in enumerate([('Alice','✓ verified · 2m'),('Marek','unverified'),('Ines','disappearing 1h'),('Atelier','3 members'),('Night relay','muted')]))+'<span class="sp"></span><div style="margin:16px;padding:16px;border-radius:16px;background:linear-gradient(135deg,#FFD24A,#E8B400);color:#111;font-weight:700;text-align:center">＋ Add contact link</div>'
p2=sb+'''<div style="padding:10px 18px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #1d1b15"><div class="av" style="background:#FFD24A;width:36px;height:36px">A</div><div><div class="cn">Alice</div><div class="cs" style="font-size:11px">✓ verified · via Tor</div></div></div>
<div style="flex:1;display:flex;flex-direction:column;padding:14px">
<div class="b in" style="font-size:14px">Rotated my onion yesterday.<div class="meta mono">via Tor v3</div></div>
<div class="b out" style="font-size:14px">Signed link checks out ✓<div class="meta mono">delivered</div></div>
<div class="b in" style="font-size:14px">Thursday then. ⏱ this chat disappears in 1h.<div class="meta mono">via Tor v3</div></div></div>
<div class="input" style="margin:12px;padding:12px">Message…<span class="sp"></span><span class="gold">➤</span></div>'''
txt='<div style="width:480px"><div class="brand" style="font-size:40px">#<b>Hash</b>Chat for Android</div><p style="color:#a59e80;font-size:18px;line-height:1.6;margin-top:18px">Same Rust core as the desktop: crypto, Tor, storage. A thin native layer on top, moving to a Rust UI step by step.</p><div style="margin-top:22px;display:flex;gap:10px;flex-wrap:wrap"><span class="pill tor">Tor only</span><span class="pill ok">Signed contacts</span><span class="pill ok">No phone number</span></div></div>'
open('hc4.html','w').write(page(txt+phone(p1)+phone(p2)))
