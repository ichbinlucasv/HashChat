# Decentralized Discovery (Medium item)

**Status**: Stub (TUI :discover command added). Future: concrete protocol + message formats for finding contacts without leaking metadata (no central servers, no phone numbers).

**Goal**: Allow users to find each other without central discovery service that could log metadata.

**Current**: Manual :my-contact / :add-contact for QR-style (ContactAddress with long-term key).

**Next**:
- Protocol for discovery (e.g., using Tor or I2P for announcements without linking).
- Message formats for "hello" or introduction.
- Integration with Extreme (refuse in extreme for minimal surface).
- Security review (side-channel, metadata).

See THREATMODEL for current gaps.

