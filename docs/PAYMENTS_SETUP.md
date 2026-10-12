# Payments setup (maintainer guide)

Goal: accept Monero (preferred), Bitcoin and Lightning without a payment
company, a bank account, user accounts or a license server.

## Option A: BTCPay Server + Monero plugin

1. A small VPS or home server (2 vCPU, 4 GB RAM, ~200 GB SSD with a pruned
   Bitcoin node; Monero pruned ~100 GB). Ideally reachable as a Tor onion
   service as well as clearnet.
2. Install BTCPay with the official docker deployment
   (<https://docs.btcpayserver.org/Docker/>), enabling Bitcoin, Lightning
   (LND or Core Lightning) and Monero (`BTCPAYGEN_CRYPTO2=xmr`).
3. Monero runs as `monerod` plus `monero-wallet-rpc`. Create the wallet on an
   **offline** machine, then give the server only a **view-only wallet**
   (primary address + private view key). The server can see incoming
   payments but can never spend them. The spend key and seed never leave
   the offline machine.
4. For Bitcoin, give BTCPay only an **xpub** (watch-only) from a hardware or
   offline wallet. Never a seed or private key.
5. Create one store per product (or one for the bundle) and set the prices
   from [SUPPORT.md](SUPPORT.md). Turn off email/name collection on invoices.

## Option B: MoneroPay (Monero only, lighter)

MoneroPay (<https://gitlab.com/moneropay/moneropay>) is a small daemon in
front of `monero-wallet-rpc` (view-only wallet again). It creates a payment
request with a fresh subaddress and calls a webhook when paid.

## Fresh address per invoice

Each invoice must use a **new subaddress** (Monero) or a new derived address
(BTC). BTCPay and MoneroPay do this automatically. Never reuse or publish a
single address for paid plans; a static address is fine only for
pay-what-you-want donations.

## Issuing the offline license

1. Generate an Ed25519 signing key once on the offline machine. Put only the
   32-byte **public** key into `MAINTAINER_PUBKEY` in the license module and
   release. Until then every license is rejected and the app is in free
   mode, which loses nothing important.
2. When an invoice is paid, sign this text (fields in this order, `\n`
   line endings) and give the buyer the file:

   ```text
   license-v1
   product=hashchat
   plan=monthly|yearly|lifetime|bundle-monthly|bundle-lifetime|pack-3m|pack-6m|pack-12m
   expires=YYYY-MM-DD   (or "never" for lifetime plans)
   order=<random hex, 16-64 chars>
   sig=<hex Ed25519 signature over the five lines above>
   ```
3. The app verifies the signature and the expiry locally. No network call,
   no telemetry, no buyer data. A bundle license uses `product=bundle`.
4. The license unlocks comfort features only. Privacy and security features
   are not in the gated list and cannot be gated.

## Receiving addresses

- **XMR** and **Lightning** are published in `SUPPORT.md` and in the app
  constants (receiving addresses / Lightning address only).
- **BTC on-chain** is paid via BTCPay invoices: a fresh address per payment,
  derived from an xpub that must **never** be committed to the repository
  (it would reveal every past and future address). Keep the xpub only on the
  BTCPay host / offline config. Docs may still show `<BTC_ADDRESS_TBD>` until
  the server is live.
- Never commit a seed, spend key, private key or xpub.
