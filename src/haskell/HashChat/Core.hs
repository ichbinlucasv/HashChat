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
  , ratchetPublicKey
  , sendEncryptedMessage
  , receiveEncryptedMessage
  , isMessageExpired
  , exportEncryptedRatchet
  , importEncryptedRatchet
  , processDisappearingMessages
  , wipeRatchetMessageKey
  , frameForWire
  , unframeFromWire
  , buildWireAad
  , wireVersionV2
  , mlockAllCurrent
  , madviseDontNeed
  , applyBasicSeccomp
  , mlockSensitiveRatchets
  , saveEncryptedMessages
  , loadEncryptedMessages
  -- H2: passphrase-wrapped identity + onion at-rest (Rust session_persist)
  , generateLongTermSeed
  , saveIdentityOnionState
  , loadIdentityOnionState
  , identityStateExists
  , signContactLinkFromSeed
  , insecureDevPersistEnabled
  -- H3: full session persist (contacts + ratchet bytes + pending)
  , PersistedContact(..)
  , SessionPersistPayload(..)
  , packContactsSection
  , packKvSection
  , unpackContactsSection
  , unpackKvSection
  , saveSessionState
  , loadSessionState
  , commitOutgoingFrame
  , ratchetToBytes
  , ratchetFromBytes
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
import Foreign.C.Types (CChar)
import Foreign.C.String (withCString, CString)
import System.Environment (lookupEnv)
import Foreign.Marshal.Alloc (malloc)
import Foreign.Marshal.Array (withArray, peekArray, mallocArray, newArray)
import Foreign.Storable (peek, poke)
import System.Directory (createDirectoryIfMissing, doesFileExist)
import System.FilePath (takeDirectory, (</>))
import System.IO.Unsafe
import Data.Bits ((.|.), (.&.), testBit, setBit, clearBit)

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
foreign import ccall unsafe "rust_ratchet_public_key" rust_ratchet_public_key :: Word32 -> Ptr Word8 -> IO Bool
foreign import ccall unsafe "rust_ratchet_recv_decrypt" rust_ratchet_recv_decrypt
  :: Word32 -> Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> Ptr Word32 -> IO Bool

-- encrypt/decrypt: key, pt/ct, len, aad, aad_len, out, out_len
foreign import ccall unsafe "rust_encrypt_with_key" rust_encrypt_with_key
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_decrypt_with_key" rust_decrypt_with_key
  :: Ptr Word8 -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Ptr Int -> IO Bool

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

-- H1: verify signed contact link, static-DH, init_symmetric (never DH before verify)
foreign import ccall unsafe "rust_contact_bootstrap" rust_contact_bootstrap
  :: Word32 -> Ptr Word8 -> Ptr CChar -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_contact_link_verify" rust_contact_link_verify
  :: Ptr CChar -> Ptr Word8 -> Ptr Int -> Ptr Word8 -> Ptr Word8 -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_longterm_generate" rust_longterm_generate
  :: Ptr Word8 -> IO Bool

-- H2: passphrase-wrapped identity+onion persist + signed contact link from seed
foreign import ccall unsafe "rust_identity_state_save" rust_identity_state_save
  :: CString -> Word8 -> Ptr Word8 -> Int -> Ptr Word8
  -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO Bool
foreign import ccall unsafe "rust_identity_state_load" rust_identity_state_load
  :: CString -> Word8 -> Ptr Word8 -> Int -> Ptr Word8
  -> Ptr Word8 -> Ptr Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_identity_state_exists" rust_identity_state_exists
  :: CString -> IO Bool
foreign import ccall unsafe "rust_contact_link_sign" rust_contact_link_sign
  :: Ptr Word8 -> CString -> Ptr Word8 -> Ptr Int -> IO Bool

-- H3: full session persist + durable outgoing commit + raw ratchet bytes
foreign import ccall unsafe "rust_session_state_save" rust_session_state_save
  :: CString -> Word8 -> Ptr Word8 -> Int -> Ptr Word8
  -> Ptr Word8 -> Int -> Ptr Word8 -> Int
  -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO Bool
foreign import ccall unsafe "rust_session_state_load" rust_session_state_load
  :: CString -> Word8 -> Ptr Word8 -> Int -> Ptr Word8
  -> Ptr Word8 -> Ptr Int -> Ptr Word8 -> Ptr Int
  -> Ptr Word8 -> Ptr Int -> Ptr Word8 -> Ptr Int -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_session_commit_outgoing" rust_session_commit_outgoing
  :: CString -> Word8 -> Ptr Word8 -> Int
  -> CString -> Ptr Word8 -> Int -> CString -> Ptr Word8 -> Int -> IO Bool
foreign import ccall unsafe "rust_ratchet_to_bytes" rust_ratchet_to_bytes
  :: Word32 -> Ptr Word8 -> Ptr Int -> IO Bool
foreign import ccall unsafe "rust_ratchet_from_bytes" rust_ratchet_from_bytes
  :: Word32 -> Ptr Word8 -> Int -> IO Bool

initProfile :: IO ProfileKey
initProfile = do
  ptr <- rust_init_profile
  pure (ProfileKey (pack [0]))

wipeAll :: IO ()
wipeAll = do
  rust_wipe_files
  rust_secure_erase (unsafePerformIO rust_init_profile)
  _ <- rust_apply_basic_seccomp
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

-- | Current ratchet ephemeral public key (32 bytes) for wire v2 sender_dh.
ratchetPublicKey :: Word32 -> IO ByteString
ratchetPublicKey rid = do
  outPtr <- mallocArray 32
  ok <- rust_ratchet_public_key rid outPtr
  if ok then pack <$> peekArray 32 outPtr
  else pure (BS.replicate 32 0)

-- | Canonical AEAD AAD = version || hint || step(be32) || sender_dh(32)
wireVersionV2 :: Word8
wireVersionV2 = 2

buildWireAad :: Word8 -> ByteString -> Word32 -> ByteString -> ByteString
buildWireAad ver hint step senderDh =
  let h = BS.take 32 hint
      dh = if BS.length senderDh >= 32 then BS.take 32 senderDh else senderDh <> BS.replicate (32 - BS.length senderDh) 0
  in BS.singleton ver <> h <> BS.pack (word32be step) <> dh

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

-- === High-level Message System (REAL Double Ratchet + AES-GCM) ===

-- | Encrypt a message. Second arg is the wire hint (bound into AAD).
--   Returns (Message, sender_dh) so the caller can build a v2 frame.
sendEncryptedMessage :: Word32 -> ByteString -> ByteString -> Bool -> Maybe NominalDiffTime -> IO (Message, ByteString)
sendEncryptedMessage ratchetId senderHint plaintext disappearing ttl = do
  (msgKey, step) <- ratchetSend ratchetId
  senderDh <- ratchetPublicKey ratchetId
  let aad = buildWireAad wireVersionV2 senderHint step senderDh
      maxOut = BS.length plaintext + 12 + 16 + 64
  outPtr <- mallocArray maxOut
  outLenPtr <- malloc
  poke outLenPtr maxOut
  ok <- withArray (unpack msgKey) $ \keyPtr ->
          withArray (unpack plaintext) $ \ptPtr ->
            withArray (unpack aad) $ \aadPtr ->
              rust_encrypt_with_key keyPtr ptPtr (BS.length plaintext) aadPtr (BS.length aad) outPtr outLenPtr
  enc <- if ok then do
           len <- peek outLenPtr
           BS.pack <$> peekArray len outPtr
         else pure BS.empty

  now <- Time.getCurrentTime
  let expTime = if disappearing
                then Just (addUTCTime (maybe 300 id ttl) now)
                else Nothing
      msg = Message
        { msgId = fromIntegral step
        , sender = senderHint
        , content = plaintext
        , ciphertext = enc
        , timestamp = fromIntegral (utcToSeconds now)
        , isDisappearing = disappearing
        , expiresAt = expTime
        , ratchetStep = step
        }
  pure (msg, senderDh)

-- | C1 speculative receive: AEAD failure leaves ratchet untouched (Rust-side).
--   Requires wire hint + sender_dh + step for AAD (version || hint || step || sender_dh).
receiveEncryptedMessage :: Word32 -> ByteString -> ByteString -> Word32 -> ByteString -> IO (Maybe Message)
receiveEncryptedMessage ratchetId senderDh hint step ct = do
  let aad = buildWireAad wireVersionV2 hint step senderDh
      maxOut = BS.length ct + 64
  outPtr <- mallocArray maxOut
  outLenPtr <- malloc
  stepPtr <- malloc
  poke outLenPtr maxOut
  ok <- withArray (unpack senderDh) $ \rp ->
          withArray (unpack ct) $ \ctPtr ->
            withArray (unpack aad) $ \aadPtr ->
              rust_ratchet_recv_decrypt ratchetId rp ctPtr (BS.length ct) aadPtr (BS.length aad) outPtr outLenPtr stepPtr
  if ok then do
    len <- peek outLenPtr
    dec <- peekArray len outPtr
    gotStep <- peek stepPtr
    now <- Time.getCurrentTime
    pure $ Just $ Message
      { msgId = fromIntegral gotStep
      , sender = hint
      , content = BS.pack dec
      , ciphertext = ct
      , timestamp = fromIntegral (utcToSeconds now)
      , isDisappearing = False
      , expiresAt = Nothing
      , ratchetStep = gotStep
      }
  else
    pure Nothing

-- === Wire framing v2 (M4: reject v1 on desktop receive) ===
-- v2: version(1)=2 | hintLen(1) | hint | step(4 BE) | sender_dh(32) | ctLen(4 BE) | ciphertext

frameForWire :: ByteString -> Word32 -> ByteString -> ByteString -> BS.ByteString
frameForWire senderHint step senderDh rawCt =
  let v = wireVersionV2
      h = BS.take 32 senderHint
      hl = fromIntegral (BS.length h) :: Word8
      dh = if BS.length senderDh >= 32 then BS.take 32 senderDh else senderDh <> BS.replicate (32 - BS.length senderDh) 0
      cl = fromIntegral (BS.length rawCt) :: Word32
  in BS.pack [v, hl]
     <> h
     <> BS.pack (word32be step)
     <> dh
     <> BS.pack (word32be cl)
     <> rawCt

-- | Parse wire frame. Rejects version /= 2 and missing sender_dh (M4).
unframeFromWire :: BS.ByteString -> Maybe (ByteString, Word32, ByteString, BS.ByteString)
unframeFromWire bs
  | BS.length bs < 2 + 4 + 32 + 4 = Nothing
  | otherwise =
      let (header, rest1) = BS.splitAt 2 bs
          v  = BS.head header
          hl = fromIntegral (BS.index header 1) :: Int
      in if v /= wireVersionV2 then Nothing else
        if BS.length rest1 < hl + 4 + 32 + 4 then Nothing else
          let (hint, rest2) = BS.splitAt hl rest1
              (stepBs, rest3) = BS.splitAt 4 rest2
              (dh, rest4) = BS.splitAt 32 rest3
              (clBs, ct) = BS.splitAt 4 rest4
              step = case unpackWord32be stepBs of Just (s,_) -> s; _ -> 0
              cl   = case unpackWord32be clBs  of Just (c,_) -> c; _ -> 0
          in if fromIntegral cl /= BS.length ct then Nothing
             else Just (hint, step, dh, ct)

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
  putStrLn $ "[SECURITY] Wiped skipped key for ratchet " ++ show ratchetId ++ " step " ++ show msgNumber

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


-- =============================================================================
-- H2: Identity + onion at-rest (Rust session_persist via FFI)
-- Default: Argon2id(passphrase) wrap. Empty passphrase refused by Rust.
-- Insecure-dev: HASHCHAT_INSECURE_DEV_PERSIST=1 or insecureDev=True → machine.key
-- =============================================================================

generateLongTermSeed :: IO (Maybe ByteString)
generateLongTermSeed = do
  out <- mallocArray 32
  ok <- rust_longterm_generate out
  if ok then Just . pack <$> peekArray 32 out else pure Nothing

-- | Save identity seed + onion (+ optional onion private key bytes) under passphrase wrap.
--   Never writes onion private material as a plaintext sibling file.
saveIdentityOnionState
  :: FilePath -> Bool -> ByteString -> ByteString -> String -> ByteString -> IO Bool
saveIdentityOnionState dataDir insecureDev pass seed onion onionKey =
  if BS.length seed /= 32
    then pure False
    else withCString dataDir $ \dir ->
           withArray (unpack pass) $ \pp ->
             withArray (unpack seed) $ \sp ->
               withArray (unpack (BC.pack onion)) $ \op ->
                 withArray (unpack onionKey) $ \okp ->
                   rust_identity_state_save
                     dir
                     (if insecureDev then 1 else 0)
                     pp (BS.length pass)
                     sp
                     op (length onion)
                     okp (BS.length onionKey)

loadIdentityOnionState
  :: FilePath -> Bool -> ByteString -> IO (Maybe (ByteString, String, ByteString))
loadIdentityOnionState dataDir insecureDev pass = do
  seedPtr <- mallocArray 32
  let onionCap = 256
      keyCap = 4096
  onionPtr <- mallocArray onionCap
  keyPtr <- mallocArray keyCap
  onionLenPtr <- malloc
  keyLenPtr <- malloc
  poke onionLenPtr onionCap
  poke keyLenPtr keyCap
  ok <- withCString dataDir $ \dir ->
          withArray (unpack pass) $ \pp ->
            rust_identity_state_load
              dir
              (if insecureDev then 1 else 0)
              pp (BS.length pass)
              seedPtr
              onionPtr onionLenPtr
              keyPtr keyLenPtr
  if not ok
    then pure Nothing
    else do
      seed <- pack <$> peekArray 32 seedPtr
      oLen <- peek onionLenPtr
      kLen <- peek keyLenPtr
      onionBs <- peekArray oLen onionPtr
      keyBs <- peekArray kLen keyPtr
      pure $ Just (seed, BC.unpack (pack onionBs), pack keyBs)

identityStateExists :: FilePath -> IO Bool
identityStateExists dataDir =
  withCString dataDir rust_identity_state_exists

-- | Build signed contact link from a persisted 32-byte seed + onion.
signContactLinkFromSeed :: ByteString -> String -> IO (Maybe String)
signContactLinkFromSeed seed onion
  | BS.length seed /= 32 = pure Nothing
  | otherwise = do
      let cap = 1024
      outPtr <- mallocArray cap
      outLenPtr <- malloc
      poke outLenPtr cap
      ok <- withArray (unpack seed) $ \sp ->
              withCString onion $ \op ->
                rust_contact_link_sign sp op outPtr outLenPtr
      if not ok
        then pure Nothing
        else do
          n <- peek outLenPtr
          bs <- peekArray n outPtr
          pure $ Just (BC.unpack (pack bs))

-- | True when insecure-dev machine.key path is explicitly enabled.
insecureDevPersistEnabled :: IO Bool
insecureDevPersistEnabled = do
  m <- lookupEnv "HASHCHAT_INSECURE_DEV_PERSIST"
  pure (maybe False (const True) m)


-- =============================================================================
-- H3: Contacts + ratchet bytes + pending frames inside passphrase-wrapped store
-- Thin Haskell wrappers around Rust session_persist (v2 blob).
-- Prefer commitOutgoingFrame after encrypt and before Tor send.
-- Remaining race: crash after durable save but before Tor ACK may resend on
-- restart; peer should tolerate duplicates via skipped keys.
-- =============================================================================

data PersistedContact = PersistedContact
  { pcId          :: String
  , pcDisplayName :: String
  , pcOnion       :: String
  , pcX25519      :: ByteString  -- 32 bytes (zeros if unknown)
  , pcEd25519     :: ByteString  -- 32 bytes (zeros if unknown)
  } deriving (Eq, Show)

data SessionPersistPayload = SessionPersistPayload
  { spSeed     :: ByteString
  , spOnion    :: String
  , spOnionKey :: ByteString
  , spContacts :: [PersistedContact]
  , spRatchets :: [(String, ByteString)]  -- contact id -> DoubleRatchet::to_bytes
  , spPending  :: [(String, ByteString)]  -- dest onion -> framed ciphertext
  } deriving (Eq, Show)

word32ToBE4 :: Word32 -> ByteString
word32ToBE4 w = pack (word32be w)

readWord32BE :: ByteString -> Maybe (Word32, ByteString)
readWord32BE = unpackWord32be

packLenBytes :: ByteString -> ByteString
packLenBytes b = word32ToBE4 (fromIntegral (BS.length b)) <> b

packLenStr :: String -> ByteString
packLenStr s = packLenBytes (BC.pack s)

unpackLenBytesHs :: ByteString -> Maybe (ByteString, ByteString)
unpackLenBytesHs bs = do
  (n, rest) <- readWord32BE bs
  let n' = fromIntegral n
  if BS.length rest < n' then Nothing
  else Just (BS.take n' rest, BS.drop n' rest)

unpackLenStrHs :: ByteString -> Maybe (String, ByteString)
unpackLenStrHs bs = do
  (b, rest) <- unpackLenBytesHs bs
  pure (BC.unpack b, rest)

packContactsSection :: [PersistedContact] -> ByteString
packContactsSection cs =
  word32ToBE4 (fromIntegral (length cs)) <> BS.concat (map packOne cs)
  where
    pad32 b =
      let b' = if BS.length b >= 32 then BS.take 32 b else b <> BS.replicate (32 - BS.length b) 0
      in b'
    packOne c =
      packLenStr (pcId c)
      <> packLenStr (pcDisplayName c)
      <> packLenStr (pcOnion c)
      <> pad32 (pcX25519 c)
      <> pad32 (pcEd25519 c)

unpackContactsSection :: ByteString -> [PersistedContact]
unpackContactsSection bs =
  case readWord32BE bs of
    Nothing -> []
    Just (n, rest) -> go (fromIntegral n) rest []
  where
    go 0 _ acc = reverse acc
    go k r acc =
      case unpackOne r of
        Nothing -> reverse acc
        Just (c, r') -> go (k - 1) r' (c : acc)
    unpackOne r = do
      (cid, r1) <- unpackLenStrHs r
      (dn, r2) <- unpackLenStrHs r1
      (on, r3) <- unpackLenStrHs r2
      if BS.length r3 < 64 then Nothing
      else
        let x = BS.take 32 r3
            e = BS.take 32 (BS.drop 32 r3)
            r4 = BS.drop 64 r3
        in Just (PersistedContact cid dn on x e, r4)

packKvSection :: [(String, ByteString)] -> ByteString
packKvSection items =
  word32ToBE4 (fromIntegral (length items))
  <> BS.concat [ packLenStr k <> packLenBytes v | (k, v) <- items ]

unpackKvSection :: ByteString -> [(String, ByteString)]
unpackKvSection bs =
  case readWord32BE bs of
    Nothing -> []
    Just (n, rest) -> go (fromIntegral n) rest []
  where
    go 0 _ acc = reverse acc
    go k r acc =
      case unpackLenStrHs r of
        Nothing -> reverse acc
        Just (key, r1) ->
          case unpackLenBytesHs r1 of
            Nothing -> reverse acc
            Just (val, r2) -> go (k - 1) r2 ((key, val) : acc)

saveSessionState :: FilePath -> Bool -> ByteString -> SessionPersistPayload -> IO Bool
saveSessionState dataDir insecureDev pass payload
  | BS.length (spSeed payload) /= 32 = pure False
  | otherwise =
      let cblob = packContactsSection (spContacts payload)
          rblob = packKvSection (spRatchets payload)
          pblob = packKvSection (spPending payload)
          onionBs = BC.pack (spOnion payload)
      in withCString dataDir $ \dir ->
           withArray (unpack pass) $ \pp ->
             withArray (unpack (spSeed payload)) $ \sp ->
               withArray (unpack onionBs) $ \op ->
                 withArray (unpack (spOnionKey payload)) $ \okp ->
                   withArray (unpack cblob) $ \cp ->
                     withArray (unpack rblob) $ \rp ->
                       withArray (unpack pblob) $ \ppnd ->
                         rust_session_state_save
                           dir
                           (if insecureDev then 1 else 0)
                           pp (BS.length pass)
                           sp
                           op (BS.length onionBs)
                           okp (BS.length (spOnionKey payload))
                           cp (BS.length cblob)
                           rp (BS.length rblob)
                           ppnd (BS.length pblob)

loadSessionState :: FilePath -> Bool -> ByteString -> IO (Maybe SessionPersistPayload)
loadSessionState dataDir insecureDev pass = do
  seedPtr <- mallocArray 32
  let onionCap = 256
      keyCap = 4096
      sectionCap = 2 * 1024 * 1024
  onionPtr <- mallocArray onionCap
  keyPtr <- mallocArray keyCap
  contactsPtr <- mallocArray sectionCap
  ratchetsPtr <- mallocArray sectionCap
  pendingPtr <- mallocArray sectionCap
  onionLenPtr <- malloc
  keyLenPtr <- malloc
  contactsLenPtr <- malloc
  ratchetsLenPtr <- malloc
  pendingLenPtr <- malloc
  poke onionLenPtr onionCap
  poke keyLenPtr keyCap
  poke contactsLenPtr sectionCap
  poke ratchetsLenPtr sectionCap
  poke pendingLenPtr sectionCap
  ok <- withCString dataDir $ \dir ->
          withArray (unpack pass) $ \pp ->
            rust_session_state_load
              dir
              (if insecureDev then 1 else 0)
              pp (BS.length pass)
              seedPtr
              onionPtr onionLenPtr
              keyPtr keyLenPtr
              contactsPtr contactsLenPtr
              ratchetsPtr ratchetsLenPtr
              pendingPtr pendingLenPtr
  if not ok
    then pure Nothing
    else do
      seed <- pack <$> peekArray 32 seedPtr
      oLen <- peek onionLenPtr
      kLen <- peek keyLenPtr
      cLen <- peek contactsLenPtr
      rLen <- peek ratchetsLenPtr
      pLen <- peek pendingLenPtr
      onionBs <- peekArray oLen onionPtr
      keyBs <- peekArray kLen keyPtr
      cBs <- peekArray cLen contactsPtr
      rBs <- peekArray rLen ratchetsPtr
      pBs <- peekArray pLen pendingPtr
      pure $ Just SessionPersistPayload
        { spSeed = seed
        , spOnion = BC.unpack (pack onionBs)
        , spOnionKey = pack keyBs
        , spContacts = unpackContactsSection (pack cBs)
        , spRatchets = unpackKvSection (pack rBs)
        , spPending = unpackKvSection (pack pBs)
        }

commitOutgoingFrame
  :: FilePath -> Bool -> ByteString -> String -> ByteString -> String -> ByteString -> IO Bool
commitOutgoingFrame dataDir insecureDev pass contactId ratchetBytes destOnion frame =
  withCString dataDir $ \dir ->
    withArray (unpack pass) $ \pp ->
      withCString contactId $ \cid ->
        withArray (unpack ratchetBytes) $ \rb ->
          withCString destOnion $ \onion ->
            withArray (unpack frame) $ \fp ->
              rust_session_commit_outgoing
                dir
                (if insecureDev then 1 else 0)
                pp (BS.length pass)
                cid
                rb (BS.length ratchetBytes)
                onion
                fp (BS.length frame)

ratchetToBytes :: Word32 -> IO (Maybe ByteString)
ratchetToBytes rid = do
  let cap = 65536
  outPtr <- mallocArray cap
  outLenPtr <- malloc
  poke outLenPtr cap
  ok <- rust_ratchet_to_bytes rid outPtr outLenPtr
  if not ok
    then pure Nothing
    else do
      n <- peek outLenPtr
      bs <- peekArray n outPtr
      pure (Just (pack bs))

ratchetFromBytes :: Word32 -> ByteString -> IO Bool
ratchetFromBytes rid blob =
  withArray (unpack blob) $ \p ->
    rust_ratchet_from_bytes rid p (BS.length blob)

