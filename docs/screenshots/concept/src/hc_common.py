HEAD='<html><head><meta charset="utf-8"><link rel="stylesheet" href="base.css"><style>{}</style></head><body>{}<div class="tag">Design concept · in progress</div></body></html>'
CSS='''
.app{width:1440px;height:860px;display:grid;grid-template-columns:340px 1fr;grid-template-rows:56px 1fr 34px}
.top{grid-column:1/3;display:flex;align-items:center;gap:14px;padding:0 20px;border-bottom:1px solid #1d1b15;background:#08080a}
.brand{font-weight:800;font-size:18px;letter-spacing:.04em}.brand b{color:#FFD24A}
.sp{flex:1}
.side{border-right:1px solid #1d1b15;padding:14px 12px;background:#09090b}
.search{background:#121214;border:1px solid #1f1d17;border-radius:10px;padding:10px 12px;color:#6d6a5e;font-size:14px;margin-bottom:12px}
.c{display:flex;gap:12px;align-items:center;padding:12px;border-radius:12px;margin-bottom:4px}
.c.act{background:linear-gradient(90deg,rgba(255,210,74,.10),rgba(255,210,74,.02));border:1px solid rgba(255,210,74,.18)}
.av{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;font-weight:700;color:#0b0b0b}
.cn{font-weight:600;font-size:15px}.cs{font-size:13px;color:#7d7a6d;margin-top:3px}
.main{display:flex;flex-direction:column;background:#0B0B0D}
.foot{grid-column:1/3;display:flex;align-items:center;gap:18px;padding:0 18px;font-size:12px;color:#7d7a6d;border-top:1px solid #1d1b15;background:#060607}
.b{max-width:560px;padding:12px 16px;border-radius:16px;font-size:15px;line-height:1.45;margin:6px 0}
.in{background:#151517;border:1px solid #222;align-self:flex-start;border-bottom-left-radius:4px}
.out{background:linear-gradient(135deg,#FFD24A,#E8B400);color:#121006;align-self:flex-end;border-bottom-right-radius:4px}
.meta{font-size:11px;opacity:.6;margin-top:4px}
.input{margin:16px 24px 20px;display:flex;align-items:center;gap:12px;background:#121214;border:1px solid #24211a;border-radius:14px;padding:14px 16px;color:#6d6a5e}
.kbd{border:1px solid #2c2a22;border-radius:6px;padding:1px 6px;font-size:12px;color:#a59e80}
'''
AVC=['#FFD24A','#C4A8FF','#7EE0C6','#FF9F6B','#9DB7FF']
def side(active=0):
    cs=[('Alice','✓ verified · 2m','A'),('Marek','unverified — compare SAS','M'),('Ines','disappearing 1h','I'),('Group · Atelier','3 members','G'),('Night relay','muted','N')]
    h='<div class="side"><div class="search">Search contacts…</div>'
    for i,(n,s,a) in enumerate(cs):
        h+=f'<div class="c {"act" if i==active else ""}"><div class="av" style="background:{AVC[i]}">{a}</div><div><div class="cn">{n}</div><div class="cs">{s}</div></div></div>'
    return h+'</div>'
TOP='''<div class="top"><div class="brand">#<b>Hash</b>Chat</div><span class="sp"></span>
<span class="pill tor"><span class="dot"></span>Tor · onion listening</span>
<span class="pill ok"><span class="dot"></span>Fail-closed · no clearnet</span>
<span class="pill ok">Posture: Paranoid</span><span class="pill" style="border:1px solid #2a2820;color:#a59e80">🔒 :lock</span></div>'''
FOOT='<div class="foot mono"><span class="gold">●</span> SOCKS isolated per contact<span>Double Ratchet</span><span>Argon2id store</span><span class="sp"></span><span>:help · :verify · :disappear · :wipe</span></div>'
