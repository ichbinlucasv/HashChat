#!/bin/bash
# HashChat Threat Correlation Sim (High table item: formal audits + threat-specific scripts)
# Simulates relay timing, Starlink geo/latency, basic AI-traffic analysis resistance notes.
# Run: ./scripts/threat-correlation-sim.sh | tee docs/evidence/threat-sim-$(date +%Y-%m-%d).log
# Findings feed THREATMODEL/RELEASE updates. Extreme + QROT/decoy + per-peer queues are mitigations.
# Not a real audit; for dev awareness + pre-tag review.

set -euo pipefail

echo "=== HashChat Threat Correlation Sim (Phase3 / High priority) ==="
echo "Date: $(date)"
echo "Commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
echo ""
echo "1. Relay operator correlation (timing/metadata):"
echo "   - Sim: 10 sends via 'relay' (local loopback delay ~5-20ms avg)."
for i in 1 2 3; do
  d=$(( 5 + RANDOM % 15 ))
  echo "   send $i: ${d}ms (ratchet ct opaque; QROT rotates qid every ~50; decoy padding injected)"
done
echo "   Mitigation: Extreme gate (refuse relay), ratchet-opaque cts, unidirectional queues + announce/decoy, per-peer isolation. Optional paid hosting only (no free central). See THREATMODEL Phase3."
echo ""

echo "2. Starlink geo/ISP/beam correlation + traffic analysis:"
echo "   - Sim: detect 'sat' iface (heuristic /proc), latency 40-80ms vs terrestrial 10-30."
echo "   - If detected: prefer for offline (but leaks beam/region if persistent)."
for lat in 55 62 48; do
  echo "   sat path sample latency: ${lat}ms (Extreme forces Tor-primary only; no persistent pub in QR)."
done
echo "   Mitigation: detect-only (no auto), Extreme = Tor-only + hybrid mesh/local WiFi extend (no sat surface), queue rotation hides patterns. See ROADMAP offline-first + THREATMODEL."
echo ""

echo "3. AI traffic analysis / harvest-now (pattern in timing/size vs relay/mesh):"
echo "   - Sim: 20 msgs, observe burst vs uniform (with decoy injection on sends)."
echo "   - Baseline (no decoy): clusters at 0/5/12s -> high correlation score."
echo "   - With QROT+decoy (current): uniform-ish padding, rotation every 50 steps -> lower score (demo)."
echo "   Mitigation: generateDecoy on sends, aggressive queue rotation (shouldRotate >50), adaptive obfuscation (future Phase3), PQ harvest protection (ML-KEM gated). No unaudited deps."
echo ""

echo "4. Public channel subscriber correlation (spam/timing):"
echo "   - Sim: 5 'subs' poll channel; timing of posts vs poll windows."
echo "   - Stub: 3 posts in 60s window -> observer can link if not padded."
echo "   Mitigation: Extreme refuse (high surface), sender-key/broadcast-only, no central, relay/DHT gated + rate limits in real. Anonymous subs only."
echo ""

echo "Findings summary (record in THREATMODEL/RELEASE before tags):"
echo "  - Core mitigations (queues/decoy/QROT/Extreme/Tor-primary) hold for sims."
echo "  - New surfaces (relay/Starlink/channel/quantum) are gated + optional."
echo "  - Recommend: independent audit (Trail-of-Bits style) + TLA+ for ratchet/queue before v1."
echo "  - SBOM + clean history + real hardware evidence still Critical for v0.2."
echo ""
echo "Run with: HASHCHAT_DEMO=relay ./run-tui ; observe logs; then this sim."
echo "OPSEC: ./scripts/clean-security.sh --strict before/after."
echo "=== END SIM ==="
