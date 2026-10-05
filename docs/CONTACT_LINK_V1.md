# Contact link v1 (signed static-DH + SAS)

Audit finding **H1**: contact bootstrap must not be unauthenticated static DH.

## Format

```
hashchat://contact/v1/<onion>/<x25519-hex>/<ed25519-hex>/<sig-hex>
```

- `<onion>`: Tor v3 hostname **without** `.onion` (lowercase)
- `<x25519-hex>`: 64 hex chars — static DH public (32 bytes)
- `<ed25519-hex>`: 64 hex chars — long-term identity verifying key (32 bytes)
- `<sig-hex>`: 128 hex chars — Ed25519 signature (64 bytes)

The Rust TUI also writes and requires a fifth field (audit I-6):

```
hashchat://contact/v1/<onion>/<x25519-hex>/<ed25519-hex>/<sig-hex>/<onion-sig-hex>
```

`<onion-sig-hex>` (128 hex chars) is the onion service key's Ed25519 signature over
`"HashChat-onion-binding-v1" || onion public key || identity ed25519 || x25519`. The onion
public key is the 32 bytes inside the onion hostname, so the receiver needs nothing else
to check it. A link whose author does not control the onion cannot carry a valid fifth
field. Four-field links still parse (the Haskell tools and the FFI write them) but are
marked unbound, and the TUI refuses to add a contact from one.

## Canonical signed payload (exact bytes)

```
ASCII "v1" || ASCII onion-without-.onion || 32 raw x25519 public bytes
```

No length prefixes. Signature = Ed25519.Sign(long-term sk, payload) (detached).

Implemented in:
- `src/rust/contact_link.rs` (encode / verify / SAS / bootstrap-before-DH)
- `src/haskell/HashChat/Contact.hs` (TUI/CLI parse + generate)

## Bootstrap rule

**Verify signature before computing DH / `init_symmetric`.**  
`bootstrap_ratchet_from_signed_link` / `rust_contact_bootstrap` enforce this.

## SAS

`SHA-256(ed25519_pub || x25519_pub || onion_full)` → first 4 bytes as `XXXX-XXXX` (uppercase hex).  
Shown by `:my-contact`, `:add-contact`, and `:sas <link>`.

## Unsigned links

Default parsers **reject** legacy unsigned `…/v1/<onion>/<len:hex>` links (TOFU-insecure).  
Escape hatch: `:add-contact-insecure` / `parseContactAddressInsecure` (loud warning).

## Not X3DH

This is **signed static-DH + SAS**, not Signal X3DH (no SPK/OPK). Comments that said X3DH were corrected.
