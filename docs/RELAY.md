# Self-hosted relay

`hashchat-relay` is a store-and-forward process you run yourself. It holds
fixed-size slots of ciphertext for peers who are offline. HashChat the
project does not run this process and has no account on it.

This page is the data-processing statement for that process. Read it before
you run one or point a profile at someone else's.

## What the operator can see

The person who runs the relay, and anyone who can read that machine, can see:

- mailbox ids (32 random bytes, also the file name)
- SHA-256 hashes of the pull token and the push token, domain-separated
- the ciphertext slots (16 KiB each, opaque to the relay)
- when a frame was accepted and when it expires
- the timing of deposits and fetches, including Tor circuit timing on the
  onion

The program does not write a request log. The operator can still watch the
process, the files, and their own Tor daemon. A relay can drop frames, refuse
a full mailbox, or record that timing. Delivery is best-effort.

## What the operator cannot see

- plaintext
- contact names, passphrases, or ratchet keys
- the raw pull and push tokens (those stay with the clients; disk stores
  hashes)
- an account, an email address, a phone number, or a real name (none is asked)

Creating a mailbox, deleting one, and wiping the queue are commands on the
process's own stdin. They are not messages on the onion, so a Tor client
cannot create a mailbox or learn a control token.

## How a profile uses it

One command publishes the listener as a v3 onion when Tor's ControlPort on
`127.0.0.1:9051` accepts SAFECOOKIE:

```bash
cargo build --release --locked --bin hashchat-relay
./target/release/hashchat-relay
```

The listener binds `127.0.0.1` only. Tor is told `Port=80` to that port.
Without `--loopback-only`, startup fails if that ControlPort refuses.
`--loopback-only` skips Tor and prints the loopback address; that mode is
for a local check, not for a peer. `--memory` keeps the queue and the onion
only until the process exits and refuses `--dir`. `--ttl-hours` is 1 to 168
(default 72). The default directory is `hashchat_relay` in the current
working directory.

On stdin, `create` prints two lines, once:

- `inbox <hex>` stays with the recipient
- `card <hex>` is what a sender is given

The onion address is printed separately as `onion <name>.onion`. The card
does not bind that onion. Check it out of band. Do not paste the inbox line,
the card line, or the onion into an issue or a chat log.

In the desktop TUI, after unlock:

- `:relay inbox ONION HEX` adds your inbox, or replaces the pull token when
  that onion is already stored. A profile holds up to four inboxes.
- `:relay for CONTACT ONION HEX` adds a contact's card (the contact token
  may contain spaces; the onion and the hex are the last two words). The
  same onion replaces that card and keeps its place in the order. A different
  onion is added and is tried later. Up to four cards per contact. Adding a
  card does not remove the others: `:relay forget` the old onion to stop
  sending there.
- `:relay forget CONTACT` removes every card for that contact.
  `:relay forget CONTACT ONION` removes one card.
- `:relay status` prints how many inboxes and how many cards, not the secrets.
- `:relay send` deposits the local pending queue.
- `:relay fetch` pulls up to eight frames in total, walking the inboxes in
  order, then stops.
- `:relay clear` forgets every inbox. `:relay clear ONION` forgets one.

A direct Tor send that fails can also deposit one copy when a card is set.
The same deposit runs when a jitter-held frame is released and the direct
send fails, and when `:retry` fails. The frame stays in the local pending
queue until a later direct send works, so a relay that drops it does not
lose the only copy. There is no background poll. Fetch when you choose to.
`:bridges require on` holds deposit and fetch the same way it holds a direct
send.

## Failover

Cards for one contact are tried in the order they were added. The first
relay that accepts the slot keeps the only copy this attempt sends on. The
later relays are not contacted for that frame. A relay that does not answer,
answers FULL, or answers REFUSED is skipped and the next card is tried.

That is failover, not a copy on every relay. The first relay, while it is
up, is the one that sees the ciphertext. A backup sees a frame only when
every earlier relay missed this attempt.

A FULL or REFUSED answer means that relay already received the slot. There
is no separate probe: the protocol has no way to test a token without
sending a valid frame, and an invalid frame is refused for the same status
as a bad token. If the relay stored the frame and the reply was lost, the
next card may store a second copy. After a restart the in-memory deposit id
is gone, so a later retry can deposit the frame again.

An onion that does not answer is remembered for the rest of that send,
retry, or fetch, and is not dialed again during it. The list is not written
down. The next command tries the onion again.

`:relay send` and a failed `:retry` look up cards by the contact whose own
onion is on the queued frame. The relay onion and the contact onion are
different hosts. A profile that cannot parse its stored cards refuses the
command and leaves the bytes in place.

Extreme posture refuses every relay command except a status line that says
the relay is off, and the next save writes the tokens empty. A backup file
omits them for the same reason it omits ratchet state: a restored copy must
not share the live mailbox.

Android does not deposit or fetch. This is the desktop client and the relay
process.

## Caps

| Limit | Value |
|---|---|
| Mailboxes | 128 |
| Frames in one mailbox | 32 |
| Slot size | 16 KiB (length, frame, zero padding) |
| Frame inside a slot | at most the hidden-service inbound cap, and at most slot size minus 2 |
| Time to live | 1 to 168 hours, default 72 |
| Live connections | 16, each with a 20 second read and write timeout |
| Deposit targets in one profile | 64 |
| Relays for one contact | 4, tried in stored order |
| Inboxes in one profile | 4, fetched in stored order |

A full mailbox answers FULL and leaves the oldest frame in place. Expired
frames (`expiry <= now`) are dropped on put, get, and ack. Get peeks the
oldest live frame. Ack deletes it only when the SHA-256 of that exact slot
(`HashChat-relay-slot-v1`) matches. A wrong ack does not delete.

Unknown mailbox and a bad token both answer REFUSED. The compare is
constant-time over the hash. The code still branches on whether the id was
present. Ids are 256-bit, so guessing one is not a useful attack. A missing
mailbox is hashed against a fixed dummy token so the hash step still runs.

The public request is a fixed size (`HCRL`, version 1, op, 32-byte id,
32-byte token, 16 KiB slot). Any other length closes the connection without
a body. Ops other than put (1), get (2), and ack (3) are refused. Get
requires a zero slot. Ack requires zeros after the 32-byte hash.

## Disk

Mailbox files are `m-` plus 64 lowercase hex characters, magic `HCMB`, mode
`0600`, owner only. A name the process does not expect (other than
`onion.key` and its own temporary files) makes startup refuse the directory.
`wipe confirm` overwrites and unlinks mailbox files and leaves `onion.key`.
Deleting the directory deletes the onion key as well. `--memory` writes
neither.

Overwrite is a best-effort random pass then unlink. It does not reliably
reach data on SSDs or copy-on-write filesystems. The same limit is in
THREATMODEL.md for `:wipe`.

## What a fetch does to a slot

Fetch walks each inbox until eight frames have been taken in total, or the
inboxes are exhausted. An inbox that does not answer, or that refuses, does
not stop the walk. The eight-frame cap is for the whole command, not for
each inbox.

A slot that is not a well-formed frame is acked immediately so it cannot
block the head. A well-formed frame is acked after one local decrypt
attempt, including an attempt that fails. A frame this profile cannot open
is therefore removed from the relay. The sender still has it in the local
queue until a direct send succeeds. Add the contact before you fetch if you
need that copy. An inbox whose ack fails is left alone for the rest of that
command; the other inboxes are still fetched.

The client remembers a deposit id (SHA-256 of the frame, label
`HashChat-relay-deposit-v1`) in process memory, up to 128, so a retry does
not fill the mailbox with the same ciphertext. Lock and quit clear that
list. It is not written to disk. After a restart a retry may deposit the
frame again.

## What this is not

- A copy of each frame on every relay. Failover stops at the first accept.
- Cover traffic, or a claim that deposit timing is hidden from the operator
- A background poll (the 30 second bridge re-check is a Tor control query,
  not a relay fetch)
- I2P (still refused)
- An Android client (the shell does not deposit or fetch)
- A promise that the operator is honest
