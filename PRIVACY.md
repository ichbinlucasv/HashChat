# Privacy

HashChat does not collect personal data. There is no account, no phone number, no email address, no real name, no identity check and no server run by this project that your client talks to. The project cannot see who uses HashChat or what they send, because it has no place to receive that information.

## What is not collected

The program has no telemetry, crash reporting, update check or analytics. It makes network connections only to your own local Tor daemon (SOCKS and ControlPort on loopback), and through Tor to the onion addresses of contacts you added yourself. If Tor is not available it does not fall back to a direct connection.

Contact links contain an onion address and public keys. They are generated on your machine and shared by you.

## What is stored on your machine

Everything lives in `hashchat_data/` next to the program and in the Tor hidden service directory you configured. The main file, `state.enc`, holds your identity keys, contacts, message transcript and ratchet state, encrypted with a key derived from your passphrase (Argon2id, AES-256-GCM). Two optional small files exist if you turn those features on: `duress.enc` (a verifier for the duress passphrase) and `deadman` (a day count and the time of the last unlock, unencrypted). Nothing is sent anywhere.

## What other parties can see

A contact you message learns your onion address and your public keys, and can see message content and timing. Tor relays carry encrypted traffic and do not see content, but a network observer may see that you use Tor. Message contents are padded to fixed size classes (512 B up to 8 KiB), so a frame shows only which class a message falls in, but timing and the fact that you sent something are still visible to a contact and to anyone watching your connection. Send-time jitter and cover traffic are on the roadmap. Messages you send cannot be deleted from your contact's device.

## Your rights under GDPR and LGPD

Because the project holds no data about you, there is nothing for it to export, correct or erase on request. Your data is on your device: `:wipe` erases it, with the usual caveat that overwriting does not reliably reach data on SSDs or copy-on-write filesystems. An export of your own data in plain text is planned.

If a self-hosted relay or a payment flow is added, this document and a separate data-processing statement will say exactly what that component sees before it ships. A relay is meant to hold only ciphertext and padded sizes. Licence payments (Monero or Bitcoin by default, Lightning also welcome) are meant to need no account and no personal details: the only record is what the blockchain itself shows, and no name, email, country or ID is asked for. The same applies to donations.

## Contact

Questions about this document can be raised as an issue in the Codeberg repository. Do not send personal data there.
