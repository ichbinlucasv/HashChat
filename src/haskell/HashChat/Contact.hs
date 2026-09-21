{-# LANGUAGE OverloadedStrings #-}
module HashChat.Contact
  ( Contact(..)
  , ContactId
  , addContact
  , getContactOnion
  , contactPubHint
  , defaultContact
  -- Signed contact bootstrap (audit H1)
  , ContactAddress(..)
  , createContactAddress
  , generateContactAddress
  , contactAddressToLink
  , parseContactAddress
  , parseContactAddressInsecure
  , contactSas
  , canonicalContactPayload
  , contactToAddress
  -- Connection request helpers
  , ConnectionRequest(..)
  , createConnectionRequest
  , connectionRequestToLink
  ) where

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32, Word8)
import Data.List (isPrefixOf)
import Text.Read (readMaybe)
import Numeric (readHex)
import Text.Printf (printf)
import Control.Monad (guard)
import Crypto.Error (eitherCryptoError)
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Curve25519 as X25519
import Crypto.Random (getSystemDRG, randomBytesGenerate)
import Crypto.Hash (hash, Digest, SHA256)
import Data.ByteArray (convert)

type ContactId = String

data Contact = Contact
  { contactId      :: ContactId
  , displayName    :: String
  , onionAddress   :: String
  , pubHint        :: ByteString
  , ratchetId      :: Maybe Word32
  }

defaultContact :: ContactId -> String -> String -> Contact
defaultContact cid name onion = Contact
  { contactId    = cid
  , displayName  = name
  , onionAddress = onion
  , pubHint      = BS.take 8 (BS.pack (map (fromIntegral . fromEnum) cid))
  , ratchetId    = Nothing
  }

addContact :: Contact -> [Contact] -> [Contact]
addContact c cs = c : filter ((/= contactId c) . contactId) cs

getContactOnion :: ContactId -> [Contact] -> Maybe String
getContactOnion cid = fmap onionAddress . Prelude.lookup cid . map (\c -> (contactId c, c))

contactPubHint :: Contact -> ByteString
contactPubHint = pubHint

--------------------------------------------------------------------------------
-- Signed contact bootstrap (audit H1)
--
-- NOT X3DH. Bootstrap is: Ed25519-signed static-DH x25519 + onion, then
-- verify-before-DH, then init_symmetric. Show SAS for manual compare.
--
-- Link format (signed v1 — required by default):
--   hashchat://contact/v1/<onion>/<x25519-hex>/<ed25519-hex>/<sig-hex>
--
-- Canonical signed payload (exact bytes; must match src/rust/contact_link.rs):
--   ASCII "v1" || ASCII onion-without-.onion || 32 raw x25519 public bytes
-- Sig = Ed25519.Sign(long-term sk, payload) (detached, 64 bytes).
--
-- Unsigned legacy links are REJECTED by parseContactAddress.
-- parseContactAddressInsecure / :add-contact-insecure = explicit TOFU escape hatch.
--------------------------------------------------------------------------------

data ContactAddress = ContactAddress
  { caOnion   :: String      -- full .onion
  , caX25519  :: ByteString  -- 32 bytes (static DH public)
  , caEd25519 :: ByteString  -- 32 bytes (identity verifying key)
  , caSig     :: ByteString  -- 64 bytes
  , caVersion :: Int
  }
  deriving (Show, Eq)

canonicalContactPayload :: String -> ByteString -> ByteString
canonicalContactPayload onionNoSuffix x25519 =
  BS.pack (map (fromIntegral . fromEnum) "v1")
  <> BS.pack (map (fromIntegral . fromEnum) onionNoSuffix)
  <> x25519

onionBare :: String -> String
onionBare = takeWhile (/= '.')

onionFull :: String -> String
onionFull o
  | ".onion" `isPrefixOf` dropWhile (/= '.') o = o
  | otherwise = onionBare o ++ ".onion"

toHex :: ByteString -> String
toHex = concatMap (printf "%02x") . BS.unpack

fromHex8 :: String -> Maybe ByteString
fromHex8 s
  | null s || odd (length s) = Nothing
  | otherwise = fmap BS.pack (mapM dec (chunksOf 2 s))
  where
    dec p = case readHex p of
      (x, ""):_ -> Just (fromIntegral x :: Word8)
      _         -> Nothing
    chunksOf _ [] = []
    chunksOf n xs = take n xs : chunksOf n (drop n xs)

contactSas :: ContactAddress -> String
contactSas ca =
  let material = caEd25519 ca <> caX25519 ca
                 <> BS.pack (map (fromIntegral . fromEnum) (caOnion ca))
      digest = hash material :: Digest SHA256
      bs = BS.take 4 (convert digest)
  in case BS.unpack bs of
       [a,b,c,d] -> printf "%02X%02X-%02X%02X" a b c d
       _         -> "????-????"

verifySig :: ByteString -> ByteString -> ByteString -> Bool
verifySig pub msg sig =
  case (eitherCryptoError (Ed25519.publicKey pub),
        eitherCryptoError (Ed25519.signature sig)) of
    (Right pk, Right sg) -> Ed25519.verify pk msg sg
    _                    -> False

-- | Sign onion+x25519 under ed25519 secret seed (32 bytes).
createContactAddress :: String -> ByteString -> ByteString -> Maybe ContactAddress
createContactAddress onion edSeed x25519Pub = do
  guard (BS.length edSeed == 32 && BS.length x25519Pub == 32)
  sk <- case eitherCryptoError (Ed25519.secretKey edSeed) of
          Right s -> Just s
          Left _  -> Nothing
  let pk      = Ed25519.toPublic sk
      bare    = onionBare onion
      full    = onionFull onion
      payload = canonicalContactPayload bare x25519Pub
      sg      = Ed25519.sign sk pk payload
  pure ContactAddress
    { caOnion   = full
    , caX25519  = x25519Pub
    , caEd25519 = convert pk
    , caSig     = convert sg
    , caVersion = 1
    }

-- | Demo/TUI helper: fresh random ed25519 seed + x25519 pub, return signed address.
-- Production persists the seed via Argon2id envelope (session_persist / longterm_identity.rs, audit H2).
generateContactAddress :: String -> IO ContactAddress
generateContactAddress onion = do
  drg0 <- getSystemDRG
  let (edSeed, drg1) = randomBytesGenerate 32 drg0
      (xSecBytes, _) = randomBytesGenerate 32 drg1
  case eitherCryptoError (X25519.secretKey xSecBytes) of
    Left _ -> error "generateContactAddress: x25519 seed rejected"
    Right xsk -> do
      let x25519Pub = convert (X25519.toPublic xsk)
      case createContactAddress onion edSeed x25519Pub of
        Just ca -> pure ca
        Nothing -> error "generateContactAddress: ed25519 seed rejected"

contactAddressToLink :: ContactAddress -> String
contactAddressToLink ca =
  "hashchat://contact/v" ++ show (caVersion ca) ++ "/" ++
  onionBare (caOnion ca) ++ "/" ++
  toHex (caX25519 ca) ++ "/" ++
  toHex (caEd25519 ca) ++ "/" ++
  toHex (caSig ca)

-- | Paranoid default: require signed v1 and verify Ed25519.
parseContactAddress :: String -> Maybe ContactAddress
parseContactAddress link = do
  guard ("hashchat://contact/v" `isPrefixOf` link)
  let rest = drop (length "hashchat://contact/v") link
  (verStr, afterVer) <- breakOn '/' rest
  ver <- readMaybe verStr
  guard (ver == 1)
  let segs = splitOn '/' afterVer
  guard (length segs == 4)
  let [onionPart, xHex, edHex, sigHex] = segs
  x25519  <- fromHex8 xHex
  ed25519 <- fromHex8 edHex
  sig     <- fromHex8 sigHex
  guard (BS.length x25519 == 32 && BS.length ed25519 == 32 && BS.length sig == 64)
  let bare    = onionPart
      full    = onionFull onionPart
      payload = canonicalContactPayload bare x25519
  guard (verifySig ed25519 payload sig)
  pure ContactAddress
    { caOnion   = full
    , caX25519  = x25519
    , caEd25519 = ed25519
    , caSig     = sig
    , caVersion = ver
    }
  where
    breakOn c s = case break (== c) s of
      (a, _ : b) -> Just (a, b)
      _          -> Nothing
    splitOn _ [] = []
    splitOn c xs =
      let (a, rest) = break (== c) xs
      in a : case rest of
               []     -> []
               (_:ys) -> splitOn c ys

-- | Explicit TOFU-insecure parser for unsigned legacy links.
-- WARNING: no signature — MITM/QR-swap silent. Prefer parseContactAddress.
parseContactAddressInsecure :: String -> Maybe ContactAddress
parseContactAddressInsecure link = do
  guard ("hashchat://contact/v" `isPrefixOf` link)
  let rest = drop (length "hashchat://contact/v") link
  (verStr, afterVer) <- breakOn '/' rest
  ver <- readMaybe verStr
  guard (ver == 1)
  (onionPart, keyPart) <- breakOn '/' afterVer
  guard ('/' `notElem` keyPart)
  let hexKey = case break (== ':') keyPart of
        (_, ':':h) -> h
        _          -> keyPart
  keyBytes <- fromHex8 hexKey
  guard (BS.length keyBytes == 32)
  pure ContactAddress
    { caOnion   = onionFull onionPart
    , caX25519  = keyBytes
    , caEd25519 = BS.replicate 32 0
    , caSig     = BS.replicate 64 0
    , caVersion = ver
    }
  where
    breakOn c s = case break (== c) s of
      (a, _ : b) -> Just (a, b)
      _          -> Nothing

-- Legacy helper: unsigned placeholder (do not share — use generateContactAddress).
contactToAddress :: Contact -> ByteString -> ContactAddress
contactToAddress contact pubKey = ContactAddress
  { caOnion   = onionAddress contact
  , caX25519  = pubKey
  , caEd25519 = BS.replicate 32 0
  , caSig     = BS.replicate 64 0
  , caVersion = 1
  }

--------------------------------------------------------------------------------
data ConnectionRequest = ConnectionRequest
  { crOnion   :: String
  , crPubKey  :: ByteString
  , crVersion :: Int
  }

createConnectionRequest :: String -> ByteString -> ConnectionRequest
createConnectionRequest onion pubKey = ConnectionRequest onion pubKey 1

connectionRequestToLink :: ConnectionRequest -> String
connectionRequestToLink cr =
  "hashchat://connect/v" ++ show (crVersion cr) ++ "/" ++
  onionBare (crOnion cr) ++ "/" ++
  show (BS.length (crPubKey cr)) ++ ":" ++
  toHex (crPubKey cr)
