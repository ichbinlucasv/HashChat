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
