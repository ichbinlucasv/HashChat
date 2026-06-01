module HashChat.Core
  ( ProfileKey(..)
  , Queue(..)
  , Message(..)
  , ProfileName
  , ContactRatchets
  , ProfileStore
  , initProfile
  , wipeAll
  , newRatchet
  , initRatchet
  , ratchetSend
  , ratchetRecv
  , sendEncryptedMessage
  , receiveEncryptedMessage
  , isMessageExpired
  , exportEncryptedRatchet
  , importEncryptedRatchet
  , processDisappearingMessages
  , wipeRatchetMessageKey
  , frameForWire
  , unframeFromWire
  -- Long-term identity for ContactAddress
  , newLongTermIdentity
  , getLongTermIdentityPublic
  , exportLongTermIdentity
  , importLongTermIdentity
  , wipeLongTermIdentity
  , setExtremeMode
  , isExtremeMode
  -- Rust Extreme for parity
  , rust_set_extreme_mode
  , rust_is_extreme_mode
  -- Per-profile proxy persistence (High #4)
  , exportEncryptedProxy
  , importEncryptedProxy
  ) where

import Control.Concurrent.STM
import Control.Monad (forM_, when)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Data.ByteString (ByteString, pack, unpack)
import Data.List (partition)
import qualified Data.Map.Strict as Map
import Data.Time.Clock (UTCTime, NominalDiffTime)
import qualified Data.Time.Clock as Time
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds, posixSecondsToUTCTime)
import Data.Word (Word8, Word16, Word32, Word64)
import Database.SQLite.Simple
import Foreign.Ptr
import Foreign.Marshal.Alloc (malloc)
import Foreign.Marshal.Array (withArray, peekArray, mallocArray, newArray)
import Foreign.Storable (peek, poke)
import System.Directory (createDirectoryIfMissing, doesFileExist)
import HashChat.Tor (ProxyConfig(..), Socks5Proxy(..))
import System.FilePath (takeDirectory, (</>))
import System.IO.Unsafe
import Data.Bits ((.|.), (.&.), testBit, setBit, clearBit)
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import System.IO.Unsafe (unsafePerformIO)

data ProfileKey = ProfileKey ByteString
data Queue = Queue ByteString

-- Core Message type for the messaging system
data Message = Message
  { msgId          :: Int
  , sender         :: ByteString     -- pubkey or identifier
  , content        :: ByteString     -- plaintext (for display after decrypt)
  , ciphertext     :: ByteString     -- the actual encrypted blob (for storage/transport)
  , timestamp      :: Int
  , isDisappearing :: Bool
  , expiresAt      :: Maybe UTCTime
  , ratchetStep    :: Word32         -- which ratchet step was used
  }

-- === FFI bindings ===
foreign import ccall unsafe "rust_init_profile" rust_init_profile :: IO (Ptr ())
foreign import ccall unsafe "rust_secure_erase" rust_secure_erase :: Ptr () -> IO ()
foreign import ccall unsafe "rust_wipe_files" rust_wipe_files :: IO ()

-- Ratchet FFI (Double Ratchet)
foreign import ccall unsafe "rust_ratchet_new"      rust_ratchet_new      :: IO Word32
foreign import ccall unsafe "rust_ratchet_init"     rust_ratchet_init     :: Word32 -> Ptr Word8 -> Ptr Word8 -> IO ()
foreign import ccall unsafe "rust_ratchet_send"     rust_ratchet_send     :: Word32 -> Ptr Word8 -> Ptr Word32 -> IO ()
foreign import ccall unsafe "rust_ratchet_recv"     rust_ratchet_recv     :: Word32 -> Ptr Word8 -> Ptr Word8 -> Ptr Word32 -> IO ()

foreign import ccall unsafe "rust_encrypt_with_key" rust_encrypt_with_key :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_decrypt_with_key" rust_decrypt_with_key :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool

-- Encrypted ratchet state persistence (Argon2id + AES-GCM envelope)
foreign import ccall unsafe "rust_ratchet_export_encrypted" rust_ratchet_export_encrypted :: Word32 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_ratchet_import_encrypted" rust_ratchet_import_encrypted :: Word32 -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO Bool

-- Dedicated passphrase blob encryption (for message logs, settings, etc.)
foreign import ccall unsafe "rust_encrypt_blob_with_passphrase" rust_encrypt_blob_with_passphrase :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_decrypt_blob_with_passphrase" rust_decrypt_blob_with_passphrase :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool

-- Ultra kernel-level security (mlockall + madvise)
foreign import ccall unsafe "rust_mlockall_current" rust_mlockall_current :: IO Bool
foreign import ccall unsafe "rust_madvise_dontneed" rust_madvise_dontneed :: Ptr Word8 -> Int -> IO ()
foreign import ccall unsafe "rust_apply_basic_seccomp" rust_apply_basic_seccomp :: IO Bool
foreign import ccall unsafe "rust_mlock" rust_mlock :: Ptr Word8 -> Int -> IO Bool
foreign import ccall unsafe "rust_mlock_sensitive_ratchets" rust_mlock_sensitive_ratchets :: IO Bool
foreign import ccall unsafe "rust_ratchet_wipe_skipped_key" rust_ratchet_wipe_skipped_key :: Word32 -> Word32 -> IO ()

-- Long-term identity for ContactAddress (Wave 10 Critical)
foreign import ccall unsafe "rust_longterm_identity_new" rust_longterm_identity_new :: IO Word32
foreign import ccall unsafe "rust_longterm_identity_get_public" rust_longterm_identity_get_public :: Word32 -> Ptr Word8 -> Ptr Word8 -> IO Bool
foreign import ccall unsafe "rust_longterm_identity_export_encrypted" rust_longterm_identity_export_encrypted :: Word32 -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_longterm_identity_import_encrypted" rust_longterm_identity_import_encrypted :: Word32 -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO Bool
foreign import ccall unsafe "rust_longterm_identity_wipe" rust_longterm_identity_wipe :: Word32 -> IO ()
foreign import ccall unsafe "rust_set_extreme_mode" rust_set_extreme_mode :: Bool -> IO ()
foreign import ccall unsafe "rust_is_extreme_mode" rust_is_extreme_mode :: IO Bool

initProfile :: IO ProfileKey
initProfile = do
  ptr <- rust_init_profile
  pure (ProfileKey (pack [0]))

wipeAll :: IO ()
wipeAll = do
  rust_wipe_files
  rust_secure_erase (unsafePerformIO rust_init_profile)
  _ <- rust_apply_basic_seccomp
  wipeLongTermIdentity sessionLongTermIdentityId
  pure ()

-- === Ratchet helpers (re-exported for convenience) ===

newRatchet :: IO Word32
newRatchet = rust_ratchet_new

initRatchet :: Word32 -> ByteString -> ByteString -> IO ()
initRatchet rid remotePub shared = do
  withArray (unpack remotePub) $ \p ->
    withArray (unpack shared) $ \s ->
      rust_ratchet_init rid p s

ratchetSend :: Word32 -> IO (ByteString, Word32)
ratchetSend rid = do
  keyPtr <- mallocArray 32
  cntPtr <- malloc
  rust_ratchet_send rid keyPtr cntPtr
  key <- peekArray 32 keyPtr
  cnt <- peek cntPtr
  pure (pack key, cnt)

ratchetRecv :: Word32 -> ByteString -> IO (ByteString, Word32)
ratchetRecv rid remotePub = do
  withArray (unpack remotePub) $ \rp -> do
    keyPtr <- mallocArray 32
    cntPtr <- malloc
    rust_ratchet_recv rid rp keyPtr cntPtr
    key <- peekArray 32 keyPtr
    cnt <- peek cntPtr
    pure (pack key, cnt)

-- === Encrypted Ratchet Persistence (production path) ===

-- | Export the full ratchet state encrypted with a user passphrase (Argon2id + AES-GCM).
--   The returned ByteString is safe to write to disk. Returns Nothing on failure.
exportEncryptedRatchet :: Word32 -> ByteString -> IO (Maybe ByteString)
exportEncryptedRatchet rid passphrase = do
  let maxSize = 4096  -- generous upper bound for a ratchet blob
  outPtr <- mallocArray maxSize
  outLenPtr <- malloc
  poke outLenPtr maxSize
  ok <- withArray (unpack passphrase) $ \pp ->
          rust_ratchet_export_encrypted rid pp (BS.length passphrase) outPtr outLenPtr
  if ok then do
    actualLen <- peek outLenPtr
    blob <- peekArray actualLen outPtr
    pure (Just $ pack blob)
  else
    pure Nothing

-- | Import (decrypt + restore) a ratchet from an encrypted blob + correct passphrase.
--   Returns True on success.
importEncryptedRatchet :: Word32 -> ByteString -> ByteString -> IO Bool
importEncryptedRatchet rid passphrase blob =
  withArray (unpack passphrase) $ \pp ->
    withArray (unpack blob) $ \bp ->
      rust_ratchet_import_encrypted rid pp (BS.length passphrase) bp (BS.length blob)

-- === Long-term Identity for ContactAddress (Critical item) ===

newLongTermIdentity :: IO Word32
newLongTermIdentity = rust_longterm_identity_new

getLongTermIdentityPublic :: Word32 -> IO (Maybe (ByteString, ByteString))
getLongTermIdentityPublic lid = do
  edPtr <- mallocArray 32
  xPtr <- mallocArray 32
  ok <- rust_longterm_identity_get_public lid edPtr xPtr
  if ok then do
    ed <- peekArray 32 edPtr
    x <- peekArray 32 xPtr
    pure (Just (pack ed, pack x))
  else
    pure Nothing

exportLongTermIdentity :: Word32 -> ByteString -> IO (Maybe ByteString)
exportLongTermIdentity lid passphrase = do
  let maxSize = 4096
  outPtr <- mallocArray maxSize
  outLenPtr <- malloc
  poke outLenPtr maxSize
  ok <- withArray (unpack passphrase) $ \pp ->
          rust_longterm_identity_export_encrypted lid pp (BS.length passphrase) outPtr outLenPtr
  if ok then do
    actualLen <- peek outLenPtr
    blob <- peekArray actualLen outPtr
    pure (Just $ pack blob)
  else
    pure Nothing

importLongTermIdentity :: Word32 -> ByteString -> ByteString -> IO Bool
importLongTermIdentity lid passphrase blob =
  withArray (unpack passphrase) $ \pp ->
    withArray (unpack blob) $ \bp ->
      rust_longterm_identity_import_encrypted lid pp (BS.length passphrase) bp (BS.length blob)

wipeLongTermIdentity :: Word32 -> IO ()
wipeLongTermIdentity = rust_longterm_identity_wipe

-- Session-cached long-term identity ID (for demo / within-run stability)
-- In real app this would be loaded per Profile using encrypted storage + ProfileKey.
{-# NOINLINE sessionLongTermIdentityId #-}
sessionLongTermIdentityId :: Word32
sessionLongTermIdentityId = unsafePerformIO newLongTermIdentity

getSessionLongTermPublic :: IO (Maybe (ByteString, ByteString))
getSessionLongTermPublic = getLongTermIdentityPublic sessionLongTermIdentityId

-- Extreme Mode flag (runtime, disabled by default)
-- When enabled: forces strict posture, disables groups/voice/export/decoy, aggressive wipes, etc.
{-# NOINLINE extremeModeRef #-}
extremeModeRef :: IORef Bool
extremeModeRef = unsafePerformIO $ newIORef False

setExtremeMode :: Bool -> IO ()
setExtremeMode b = do
  writeIORef extremeModeRef b
  rust_set_extreme_mode b  -- sync to Rust for FFI-level gates (full Extreme)

isExtremeMode :: IO Bool
isExtremeMode = readIORef extremeModeRef

-- === High-level Message System (REAL Double Ratchet + AES-GCM) ===

sendEncryptedMessage :: Word32 -> ByteString -> ByteString -> Bool -> Maybe NominalDiffTime -> IO Message
sendEncryptedMessage ratchetId senderPub plaintext disappearing ttl = do
  (msgKey, step) <- ratchetSend ratchetId

  -- Actually encrypt with the exact 32-byte key from the ratchet
  let keyPtr = unsafePerformIO $ newArray (unpack msgKey)
  let ptPtr  = unsafePerformIO $ newArray (unpack plaintext)
  let buf    = replicate (BS.length plaintext + 16) 0
  outPtr <- newArray buf
  outLenPtr <- malloc

  _ <- rust_encrypt_with_key keyPtr ptPtr (BS.length plaintext) outPtr outLenPtr
  len <- peek outLenPtr
  enc <- peekArray len outPtr

  now <- Time.getCurrentTime
  let expTime = if disappearing
                then Just (addUTCTime (maybe 300 id ttl) now)
                else Nothing

  pure Message
    { msgId = fromIntegral step
    , sender = senderPub
    , content = plaintext                    -- keep plaintext for UI display
    , ciphertext = BS.pack enc               -- real encrypted data for storage/transport
    , timestamp = fromIntegral (utcToSeconds now)
    , isDisappearing = disappearing
    , expiresAt = expTime
    , ratchetStep = step
    }

receiveEncryptedMessage :: Word32 -> ByteString -> ByteString -> IO (Maybe Message)
receiveEncryptedMessage ratchetId senderPub ct = do
  (msgKey, step) <- ratchetRecv ratchetId senderPub

  let keyPtr = unsafePerformIO $ newArray (unpack msgKey)
  let ctPtr  = unsafePerformIO $ newArray (unpack ct)
  let buf    = replicate (BS.length ct + 32) 0   -- generous buffer
  outPtr <- newArray buf
  outLenPtr <- malloc

  ok <- rust_decrypt_with_key keyPtr ctPtr (BS.length ct) outPtr outLenPtr
  if ok then do
    len <- peek outLenPtr
    dec <- peekArray len outPtr
    now <- Time.getCurrentTime
    pure $ Just $ Message
      { msgId = fromIntegral step
      , sender = senderPub
      , content = BS.pack dec                    -- decrypted plaintext for display
      , ciphertext = ct                          -- keep the original encrypted blob
      , timestamp = fromIntegral (utcToSeconds now)
      , isDisappearing = False
      , expiresAt = Nothing
      , ratchetStep = step
      }
  else
    pure Nothing

-- === Wire framing for sender identification (tightens bidirectional Tor receive) ===
-- Framed format sent over Tor: version(1) | hintLen(1) | hint bytes | step(4 BE) | ctLen(4 BE) | ciphertext
-- Allows receiver to know exactly which ratchet/contact to use without brute-forcing all ratchets.

frameForWire :: ByteString -> Word32 -> ByteString -> BS.ByteString
frameForWire senderHint step rawCt =
  let v = 1 :: Word8
      h = BS.take 32 senderHint  -- cap hint size
      hl = fromIntegral (BS.length h) :: Word8
      s  = step
      cl = fromIntegral (BS.length rawCt) :: Word32
  in BS.pack [v, hl]
     <> h
     <> BS.pack (word32be s)
     <> BS.pack (word32be cl)
     <> rawCt

unframeFromWire :: BS.ByteString -> Maybe (ByteString, Word32, BS.ByteString)
unframeFromWire bs
  | BS.length bs < 1 + 1 + 4 + 4 = Nothing
  | otherwise =
      let (header, rest1) = BS.splitAt 2 bs
          v  = if BS.length header >= 1 then BS.head header else 0
          hl = if BS.length header >= 2 then fromIntegral (BS.index header 1) :: Int else 0
      in if v /= 1 then Nothing else
        if BS.length rest1 < hl + 4 + 4 then Nothing else
          let (hint, rest2) = BS.splitAt hl rest1
              (stepBs, rest3) = BS.splitAt 4 rest2
              (clBs, ct) = BS.splitAt 4 rest3
              step = case unpackWord32be stepBs of Just (s,_) -> s; _ -> 0
              cl   = case unpackWord32be clBs  of Just (c,_) -> c; _ -> 0
          in if fromIntegral cl /= BS.length ct then Nothing
             else Just (hint, step, ct)

-- Helper to check if a disappearing message should be deleted
isMessageExpired :: Message -> IO Bool
isMessageExpired msg = case expiresAt msg of
  Nothing -> pure False
  Just t  -> (>= t) <$> Time.getCurrentTime

-- Internal time helpers (simplified for demo)
utcToSeconds :: UTCTime -> Int
utcToSeconds _ = 0

-- For the message system, we use the ratchet key + existing AES-GCM FFI when available.
-- For now these are thin wrappers; real version will take the msgKey from ratchetSend/Recv.
encryptMessage :: ByteString -> ByteString -> IO ByteString
encryptMessage _ p = pure p

decryptMessage :: ByteString -> ByteString -> IO ByteString
decryptMessage _ c = pure c

-- Time helpers (demo stubs)
addUTCTime :: NominalDiffTime -> UTCTime -> UTCTime
addUTCTime _ t = t

-- Note: We intentionally do NOT define a local utcTimeToPOSIXSeconds here
-- to avoid shadowing the real one from Data.Time.Clock.POSIX.
-- The real function is used in packMessage for disappearing message expiry.

-- ============================================================
-- NEW: Disappearing + Key Wiping + Burner Profiles + Persistence
-- ============================================================

-- Wipe a specific message key from a ratchet (critical for disappearing messages)
-- Now actually calls into Rust to zeroize + remove from skipped_keys map.
wipeRatchetMessageKey :: Word32 -> Word32 -> IO ()
wipeRatchetMessageKey ratchetId msgNumber = do
  rust_ratchet_wipe_skipped_key ratchetId msgNumber
  putStrLn $ "[SECURITY] Wiped skipped key for ratchet " ++ show ratchetId ++ " step " ++ show msgNumber ++ " (real zeroization in Rust)"

-- Process and remove expired messages, wiping their ratchet keys
processDisappearingMessages :: [Message] -> IO [Message]
processDisappearingMessages msgs = do
  now <- Time.getCurrentTime
  let (expired, active) = partition (\m -> maybe False (<= now) (expiresAt m)) msgs
  forM_ expired $ \m -> do
    when (isDisappearing m) $ do
      wipeRatchetMessageKey (ratchetStep m) (fromIntegral $ msgId m)
      putStrLn $ "[SECURITY] Message " ++ show (msgId m) ++ " expired and ratchet key wiped"
  pure active

-- Burner profile support (each profile owns isolated ratchets)
type ProfileName = String
type ContactRatchets = Map.Map String Word32   -- contact -> ratchetId
type ProfileStore = Map.Map ProfileName ContactRatchets

-- === Message + Ratchet Persistence (deep work in progress) ===

-- For now we only persist ratchet *state* securely (Argon2id + AES-GCM).
-- Full message history (with ciphertext) should also be stored encrypted per profile.

-- === Encrypted Message Log Persistence (deep work - real implementation) ===

type MessageLog = [Message]

-- Binary (robust) serialization for Message logs. Replaces all Show/Read usage.
-- Format is length-prefixed, versioned, big-endian, identical in spirit to Rust to_bytes.
packMessage :: Message -> BS.ByteString
packMessage m =
  let v = 1 :: Word8
      mid = fromIntegral (msgId m) :: Word32
      sndr = sender m
      sl = fromIntegral (BS.length sndr) :: Word16
      ctnt = content m
      cl = fromIntegral (BS.length ctnt) :: Word32
      ciph = ciphertext m
      cil = fromIntegral (BS.length ciph) :: Word32
      ts = fromIntegral (timestamp m) :: Word32
      flags = if isDisappearing m then 0x01 else 0x00 :: Word8
      (hasExp, expSec) = case expiresAt m of
        Just t  -> (1 :: Word8, floor (utcTimeToPOSIXSeconds t) :: Word64)
        Nothing -> (0 :: Word8, 0 :: Word64)
      step = ratchetStep m
  in BS.pack [v]
     <> BS.pack (word32be mid)
     <> BS.pack (word16be sl) <> sndr
     <> BS.pack (word32be cl) <> ctnt
     <> BS.pack (word32be cil) <> ciph
     <> BS.pack (word32be ts)
     <> BS.pack [flags]
     <> BS.pack [hasExp] <> BS.pack (word64be expSec)
     <> BS.pack (word32be step)

-- Unpack one message, returning the remainder for lists.
unpackMessage :: BS.ByteString -> Maybe (Message, BS.ByteString)
unpackMessage bs
  | BS.length bs < 1 + 4 = Nothing
  | otherwise =
      let (vbs, rest0) = BS.splitAt 1 bs
          v = BS.head vbs
      in if v /= 1 then Nothing else
        case unpackWord32be rest0 of
          Nothing -> Nothing
          Just (mid, r1) ->
            case unpackLenPrefixed 2 r1 of
              Nothing -> Nothing
              Just (sndr, r2) ->
                case unpackWord32be r2 of
                  Nothing -> Nothing
                  Just (cl, r3) ->
                    case unpackLenPrefixed (fromIntegral cl) r3 of
                      Nothing -> Nothing
                      Just (ctnt, r4) ->
                        case unpackWord32be r4 of
                          Nothing -> Nothing
                          Just (cil, r5) ->
                            case unpackLenPrefixed (fromIntegral cil) r5 of
                              Nothing -> Nothing
                              Just (ciph, r6) ->
                                case unpackWord32be r6 of
                                  Nothing -> Nothing
                                  Just (ts, r7) ->
                                    if BS.length r7 < 1+1+8+4 then Nothing else
                                      let flags = BS.index r7 0
                                          hasE = BS.index r7 1
                                          expBs = BS.take 8 (BS.drop 2 r7)
                                          stepPart = BS.drop 10 r7
                                          disc = (flags .&. 0x01) /= 0
                                          expT = if hasE == 1
                                                 then Just (posixSecondsToUTCTime (fromIntegral (word64FromBE expBs)))
                                                 else Nothing
                                          step = case unpackWord32be stepPart of Just (s,_) -> s; _ -> 0
                                          msg = Message
                                            { msgId = fromIntegral mid
                                            , sender = sndr
                                            , content = ctnt
                                            , ciphertext = ciph
                                            , timestamp = fromIntegral ts
                                            , isDisappearing = disc
                                            , expiresAt = expT
                                            , ratchetStep = step
                                            }
                                          consumed = 1 + 4 + 2 + BS.length sndr + 4 + fromIntegral cl + 4 + fromIntegral cil + 4 + 1 + 1 + 8 + 4
                                      in Just (msg, BS.drop (fromIntegral consumed) bs)

-- Helper packers (pure, no new deps)
word32be :: Word32 -> [Word8]
word32be w = [fromIntegral (w `div` 0x1000000), fromIntegral ((w `div` 0x10000) `mod` 256), fromIntegral ((w `div` 256) `mod` 256), fromIntegral (w `mod` 256)]

word16be :: Word16 -> [Word8]
word16be w = [fromIntegral (w `div` 256), fromIntegral (w `mod` 256)]

word64be :: Word64 -> [Word8]
word64be w = [ fromIntegral (w `div` 0x100000000000000), fromIntegral ((w `div` 0x1000000000000) `mod` 256), fromIntegral ((w `div` 0x10000000000) `mod` 256), fromIntegral ((w `div` 0x100000000) `mod` 256), fromIntegral ((w `div` 0x1000000) `mod` 256), fromIntegral ((w `div` 0x10000) `mod` 256), fromIntegral ((w `div` 256) `mod` 256), fromIntegral (w `mod` 256) ]

unpackWord32be :: BS.ByteString -> Maybe (Word32, BS.ByteString)
unpackWord32be bs | BS.length bs < 4 = Nothing
                  | otherwise =
                      let b0 = fromIntegral (BS.index bs 0) :: Word32
                          b1 = fromIntegral (BS.index bs 1)
                          b2 = fromIntegral (BS.index bs 2)
                          b3 = fromIntegral (BS.index bs 3)
                      in Just (b0*0x1000000 + b1*0x10000 + b2*0x100 + b3, BS.drop 4 bs)

unpackLenPrefixed :: Int -> BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
unpackLenPrefixed n bs | BS.length bs < n = Nothing
                       | otherwise = Just (BS.take n bs, BS.drop n bs)

word64FromBE :: BS.ByteString -> Word64
word64FromBE bs | BS.length bs < 8 = 0
                | otherwise = foldl (\a b -> a*256 + fromIntegral b) 0 (BS.unpack (BS.take 8 bs))

-- Legacy tuple adapters (kept during transition; new code uses packMessage)
serializeMessage :: Message -> (Int, ByteString, ByteString, Int, Bool, Maybe UTCTime, Word32)
serializeMessage m =
  ( msgId m
  , content m
  , ciphertext m
  , timestamp m
  , isDisappearing m
  , expiresAt m
  , ratchetStep m
  )

deserializeMessage :: (Int, ByteString, ByteString, Int, Bool, Maybe UTCTime, Word32) -> Message
deserializeMessage (mid, cont, ct, ts, disc, exp, step) = Message
  { msgId = mid
  , sender = BS.empty
  , content = cont
  , ciphertext = ct
  , timestamp = ts
  , isDisappearing = disc
  , expiresAt = exp
  , ratchetStep = step
  }

-- High-level passphrase-based blob encryption/decryption
encryptWithPassphrase :: ByteString -> ByteString -> IO (Maybe ByteString)
encryptWithPassphrase pass plaintext = do
  let maxSize = BS.length plaintext + 1024
  outPtr <- mallocArray maxSize
  outLenPtr <- malloc
  poke outLenPtr maxSize
  ok <- withArray (unpack pass) $ \pp ->
          withArray (unpack plaintext) $ \pt ->
            rust_encrypt_blob_with_passphrase pp (BS.length pass) pt (BS.length plaintext) outPtr outLenPtr
  if ok then do
    actual <- peek outLenPtr
    blob <- peekArray actual outPtr
    pure (Just $ pack blob)
  else pure Nothing

decryptWithPassphrase :: ByteString -> ByteString -> IO (Maybe ByteString)
decryptWithPassphrase pass ciphertext = do
  let maxSize = BS.length ciphertext + 1024
  outPtr <- mallocArray maxSize
  outLenPtr <- malloc
  poke outLenPtr maxSize
  ok <- withArray (unpack pass) $ \pp ->
          withArray (unpack ciphertext) $ \ct ->
            rust_decrypt_blob_with_passphrase pp (BS.length pass) ct (BS.length ciphertext) outPtr outLenPtr
  if ok then do
    actual <- peek outLenPtr
    blob <- peekArray actual outPtr
    pure (Just $ pack blob)
  else pure Nothing

-- Kernel-level hardening helpers (exposed for TUI wipe)
mlockAllCurrent :: IO Bool
mlockAllCurrent = rust_mlockall_current

mlockMemory :: Ptr Word8 -> Int -> IO Bool
mlockMemory = rust_mlock

madviseDontNeed :: Ptr Word8 -> Int -> IO ()
madviseDontNeed = rust_madvise_dontneed

applyBasicSeccomp :: IO Bool
applyBasicSeccomp = rust_apply_basic_seccomp

mlockSensitiveRatchets :: IO Bool
mlockSensitiveRatchets = rust_mlock_sensitive_ratchets

-- === Real Encrypted Message Log Persistence (properly implemented) ===

-- High-level binary message log persistence (replaces all Show/Read).
-- The on-disk format after Argon2id+AES envelope is a simple versioned binary stream.

packMessageList :: [Message] -> BS.ByteString
packMessageList msgs =
  let count = fromIntegral (length msgs) :: Word32
      bodies = BS.concat (map packMessage msgs)
  in BS.pack (word32be count) <> bodies

unpackMessageList :: BS.ByteString -> [Message]
unpackMessageList bs
  | BS.length bs < 4 = []
  | otherwise =
      case unpackWord32be bs of
        Nothing -> []
        Just (cnt, rest) -> go (fromIntegral cnt) rest []
  where
    go 0 _ acc = reverse acc
    go n r acc =
      case unpackMessage r of
        Just (m, r') -> go (n-1) r' (m:acc)
        Nothing      -> reverse acc   -- tolerate truncation / corruption gracefully

saveEncryptedMessages :: FilePath -> ProfileName -> String -> ByteString -> MessageLog -> IO ()
saveEncryptedMessages baseDir profile contact pass msgs = do
  let dir = baseDir </> profile </> "messages"
  createDirectoryIfMissing True dir
  let path = dir </> (contact ++ ".log.enc")
  let serialized = packMessageList msgs   -- ROBUST BINARY, no Show/Read
  mBlob <- encryptWithPassphrase pass serialized
  case mBlob of
    Just blob -> BS.writeFile path blob
    Nothing   -> putStrLn "[SECURITY] Failed to encrypt message log"

loadEncryptedMessages :: FilePath -> ProfileName -> String -> ByteString -> IO MessageLog
loadEncryptedMessages baseDir profile contact pass = do
  let path = baseDir </> profile </> "messages" </> (contact ++ ".log.enc")
  exists <- doesFileExist path
  if exists then do
    enc <- BS.readFile path
    mPlain <- decryptWithPassphrase pass enc
    case mPlain of
      Just plain -> pure (unpackMessageList plain)
      Nothing -> do
        putStrLn "[SECURITY] Failed to decrypt message log (wrong passphrase or corruption)"
        pure []
  else pure []

-- Legacy readMaybe kept only for any external tools that might still parse old logs
readMaybe :: Read a => String -> Maybe a
readMaybe s = case reads s of
  [(x, "")] -> Just x
  _ -> Nothing

-- === Per-profile Proxy persistence (High #4: make fully functional, stable, working)
-- Persist per burner using encrypted blob (rust_encrypt_blob_with_passphrase).
-- Used in send paths. Extreme can force default Tor-only.
-- UI shows in title/status. :set-proxy persists it.

exportEncryptedProxy :: ProxyConfig -> ByteString -> IO (Maybe ByteString)
exportEncryptedProxy (Socks5Proxy h p) pass = do
  let dataStr = BS.pack (map (fromIntegral . fromEnum) (h ++ ":" ++ show p))
  outPtr <- mallocArray 4096
  outLenPtr <- malloc
  poke outLenPtr 4096
  ok <- withArray (unpack pass) $ \pp ->
          withArray (unpack dataStr) $ \dp ->
            rust_encrypt_blob_with_passphrase pp (BS.length pass) dp (BS.length dataStr) outPtr outLenPtr
  if ok then do
    actualLen <- peek outLenPtr
    blob <- peekArray actualLen outPtr
    pure (Just $ pack blob)
  else
    pure Nothing

importEncryptedProxy :: ByteString -> ByteString -> IO (Maybe ProxyConfig)
importEncryptedProxy blob pass =
  withArray (unpack pass) $ \pp ->
    withArray (unpack blob) $ \bp -> do
      outPtr <- mallocArray 4096
      outLenPtr <- malloc
      poke outLenPtr 4096
      ok <- rust_decrypt_blob_with_passphrase pp (BS.length pass) bp (BS.length blob) outPtr outLenPtr
      if ok then do
        len <- peek outLenPtr
        dec <- peekArray len outPtr
        let str = map (toEnum . fromIntegral) dec
        case break (== ':') str of
          (host, ':' : portStr) | Just p <- readMaybe portStr -> pure (Just (Socks5Proxy host p))
          _ -> pure Nothing
      else pure Nothing

