module HashChat.Contact
  ( Contact(..)
  , ContactId
  , addContact
  , getContactOnion
  , contactPubHint
  , defaultContact
  -- Contact / Profile sharing (Simplex-style)
  , ContactAddress(..)
  , createContactAddress
  , contactAddressToLink
  , parseContactAddress
  -- Connection request (what the scanner sends back) + helpers for full Simplex-style roundtrip
  , ConnectionRequest(..)
  , createConnectionRequest
  , connectionRequestToLink
  , contactToAddress
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)
import Data.List (isPrefixOf)
import Text.Read (readMaybe)
import Numeric (readHex)
import Text.Printf (printf)
import Control.Monad (guard)

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

-- Expanded rec-14: Minimal protocol message format example (for future implementation)
-- type IntroBlob = (ByteString, ByteString, Word64, ByteString)  -- (onion, pubHint, timestamp, sig)
-- Functions to implement later:
-- createIntroductionBlob :: Contact -> ByteString -> IO ByteString
-- verifyIntroductionBlob :: ByteString -> ByteString -> IO (Maybe Contact)

addContact :: Contact -> [Contact] -> [Contact]
addContact c cs = c : filter ((/= contactId c) . contactId) cs

getContactOnion :: ContactId -> [Contact] -> Maybe String
getContactOnion cid = fmap onionAddress . Prelude.lookup cid . map (\c -> (contactId c, c))

contactPubHint :: Contact -> ByteString
contactPubHint = pubHint

-- Wave 10: Create ContactAddress from Contact.
-- TUI generation no longer uses obvious 0xAB dummy (fresh pattern + note).
-- Real per-profile long-term identity keypair (generated in Rust, persisted via Keystore,
-- only pub exported for QR) + X3DH setup is the next major recommendation after this closure.
-- The current path provides usable Simplex-style QR with good metadata resistance.
contactToAddress :: Contact -> ByteString -> ByteString -> ContactAddress
contactToAddress contact edPub xPub = createContactAddress (onionAddress contact) edPub xPub

-- =====================================================================
-- Simplex-style Connection Request (Wave 7)
-- =====================================================================
-- When someone scans your ContactAddress (QR), they create this and send it to your onion.
-- It contains their public info so you can reply securely.
data ConnectionRequest = ConnectionRequest
  { crOnion  :: String
  , crPubKey :: ByteString
  , crVersion :: Int
  }

createConnectionRequest :: String -> ByteString -> ConnectionRequest
createConnectionRequest onion pubKey = ConnectionRequest onion pubKey 1

connectionRequestToLink :: ConnectionRequest -> String
connectionRequestToLink cr =
  "hashchat://connect/v" ++ show (crVersion cr) ++ "/" ++
  takeWhile (/= '.') (crOnion cr) ++ "/" ++
  show (BS.length (crPubKey cr)) ++ ":" ++
  concatMap (printf "%02x") (BS.unpack (crPubKey cr))

-- EXTREME MODE NOTE (Wave 8):
-- Generation of fresh ContactAddress / ConnectionRequest (i.e. profile QR) should be refused
-- or heavily rate-limited when EXTREME_MODE or strict posture is active. The TUI/Android layers
-- must call isStrictMode / EXTREME_MODE checks before exposing "share my contact" UI.
-- This minimizes long-term identity surface.

-- In the real app these would be persisted encrypted per profile (like ratchets)
-- and exchanged via QR / link (X3DH-style) over Tor.

-- Note on Extreme mode (Wave 7):
-- When EXTREME_MODE is active, generation of new contact addresses / profile QR
-- should be disabled or heavily restricted to minimize attack surface.

-- =====================================================================
-- Contact Address / Profile Sharing (Simplex-inspired, Wave 7)
-- =====================================================================
-- Following SimplexChat's simple and effective model:
-- - The QR/link contains only PUBLIC information (your onion + public identity key).
-- - Your private keys never leave your device.
-- - The other party can use this to initiate a secure connection.
--
-- Format example:
--   hashchat://contact/v1/<onion-without-.onion>/<hex-or-base64-public-key>
--
-- This is the recommended way to share profiles with friends.

data ContactAddress = ContactAddress
  { caOnion     :: String      -- full .onion address (public)
  , caPubKey    :: ByteString  -- public identity / ed25519 signing key (public, for QR display/verify)
  , caX25519Pub :: ByteString  -- x25519 static for initial X3DH DH (public)
  , caVersion   :: Int         -- for future format evolution (v2+ includes x)
  }
  deriving (Show, Eq)

-- Create a shareable contact address (public data only)
-- The private key must never be included here.
-- For X3DH bootstrap (skeleton): include x25519 pub (from long term) so peer can compute initial shared = x25519_dh(local_x, peer_x)
createContactAddress :: String -> ByteString -> ByteString -> ContactAddress
createContactAddress onion edPub xPub = ContactAddress
  { caOnion     = onion
  , caPubKey    = edPub
  , caX25519Pub = xPub
  , caVersion   = 2
  }

-- Generate a shareable link string suitable for QR code
-- v2: /<onion>/<len-ed:hex-ed>/<len-x:hex-x>
contactAddressToLink :: ContactAddress -> String
contactAddressToLink ca =
  "hashchat://contact/v" ++ show (caVersion ca) ++ "/" ++
  takeWhile (/= '.') (caOnion ca) ++ "/" ++
  show (BS.length (caPubKey ca)) ++ ":" ++ concatMap (printf "%02x") (BS.unpack (caPubKey ca)) ++ "/" ++
  show (BS.length (caX25519Pub ca)) ++ ":" ++ concatMap (printf "%02x") (BS.unpack (caX25519Pub ca))

-- Parse a contact link (from QR or pasted)
-- v1 backward compat (ed only, x=empty), v2 has ed + x25519 for X3DH bootstrap.
-- SECURITY MODEL: QR/link carries ONLY public onion + public ed25519 (identity) + public x25519 (for initial DH).
-- Private ratchet keys + long-term identity secrets stay on device and are never shared.
-- This enables real X3DH: shared = x25519_dh( my_long_x , peer_long_x_from_qr )
parseContactAddress :: String -> Maybe ContactAddress
parseContactAddress link = do
  guard ( "hashchat://contact/v" `isPrefixOf` link )
  let rest = drop (length "hashchat://contact/v") link
  (verStr, afterVer) <- breakOn '/' rest
  ver <- readMaybe verStr
  let (onionPart, afterOnion) = breakOn '/' afterVer
  let onion = onionPart ++ ".onion"
  if ver == 1 then do
    (lenStr, hexKey) <- breakOn ':' afterOnion
    keyLen <- readMaybe lenStr
    let decodedPairs = chunksOf 2 hexKey
    let safeDecode p = case readHex p of (x:_) -> [fst x]; _ -> []
    let keyBytes = BS.pack $ map fromIntegral (concatMap safeDecode decodedPairs)
    guard (BS.length keyBytes == keyLen)
    pure $ ContactAddress onion keyBytes BS.empty ver
  else do
    -- v2+: ed part then / x part
    (edPart, xPart) <- breakOn '/' afterOnion
    (edLenStr, edHex) <- breakOn ':' edPart
    edLen <- readMaybe edLenStr
    let edDecoded = chunksOf 2 edHex
    let safeDecode p = case readHex p of (x:_) -> [fst x]; _ -> []
    let edBytes = BS.pack $ map fromIntegral (concatMap safeDecode edDecoded)
    guard (BS.length edBytes == edLen)
    (xLenStr, xHex) <- breakOn ':' xPart
    xLen <- readMaybe xLenStr
    let xDecoded = chunksOf 2 xHex
    let xBytes = BS.pack $ map fromIntegral (concatMap safeDecode xDecoded)
    guard (BS.length xBytes == xLen)
    pure $ ContactAddress onion edBytes xBytes ver
  where
    breakOn c s = case break (== c) s of
      (a, _ : b) -> Just (a, b)
      _          -> Nothing
    chunksOf _ [] = []
    chunksOf n xs = take n xs : chunksOf n (drop n xs)