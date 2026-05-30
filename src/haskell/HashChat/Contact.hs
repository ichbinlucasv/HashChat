module HashChat.Contact
  ( Contact(..)
  , ContactId
  , addContact
  , getContactOnion
  , contactPubHint
  , defaultContact
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)

type ContactId = String

-- Real per-contact identity for metadata-resistant addressing.
-- onionAddress: the v3 .onion the contact listens on (for sending to them)
-- pubHint: short public identity (first bytes of their ratchet public or ed25519) used in wire framing
data Contact = Contact
  { contactId      :: ContactId
  , displayName    :: String
  , onionAddress   :: String          -- full .onion for Tor send
  , pubHint        :: ByteString      -- used for sender identification in framed messages
  , ratchetId      :: Maybe Word32    -- local ratchet for this contact
  }

-- Simple constructor
defaultContact :: ContactId -> String -> String -> Contact
defaultContact cid name onion = Contact
  { contactId    = cid
  , displayName  = name
  , onionAddress = onion
  , pubHint      = BS.take 8 (BS.pack (map (fromIntegral . fromEnum) cid))  -- deterministic hint for framing
  , ratchetId    = Nothing
  }

addContact :: Contact -> [Contact] -> [Contact]
addContact c cs = c : filter ((/= contactId c) . contactId) cs

getContactOnion :: ContactId -> [Contact] -> Maybe String
getContactOnion cid = fmap onionAddress . Prelude.lookup cid . map (\c -> (contactId c, c))

contactPubHint :: Contact -> ByteString
contactPubHint = pubHint

-- In the real app these would be persisted encrypted per profile (like ratchets)
-- and exchanged via QR / link (X3DH-style) over Tor.