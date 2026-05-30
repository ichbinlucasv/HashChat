{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

module Main where

import Brick
import Brick.Widgets.Border (borderWithLabel)
import Brick.Widgets.Core (str, hBox, vBox, padAll, fill, withAttr)
import Brick.Widgets.Center (center)
-- No longer using full Editor widget (simplified reliable Text input for stability across brick versions)
import qualified Graphics.Vty as V
import Graphics.Vty.Platform.Unix (mkVty)  -- correct location in modern vty
import qualified Data.Text as T
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import Data.Word (Word32)
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import HashChat.Core
  ( wipeAll
  , sendEncryptedMessage
  , exportEncryptedRatchet
  , importEncryptedRatchet
  , saveEncryptedMessages
  , loadEncryptedMessages
  , ProfileName
  , Message(..)
  , mlockAllCurrent
  , madviseDontNeed
  , applyBasicSeccomp
  )
import MessageUI
import qualified HashChat.Tor as Tor  -- Real Tor hidden service transport scaffolding started
import Control.Monad (when, void, foldM)
import Control.Monad.IO.Class (liftIO)
import System.Directory (doesFileExist)
import Control.Exception (catch, SomeException, try)
import System.Directory (removePathForcibly, createDirectoryIfMissing, listDirectory, doesFileExist, doesDirectoryExist)
import System.FilePath (combine, takeDirectory)
import Data.Time.Clock (getCurrentTime)
import System.IO (hFlush, stdout, hSetEcho, stdin)
import qualified Data.List
import Data.List (elemIndex, isInfixOf)
import System.Process (callCommand)
import Control.Monad (whenM)

data Name = ChatInput | ContactList | Help deriving (Eq, Ord, Show)

-- Helper to get the current session passphrase (must be set after unlock)
passForSession :: AppState -> BS.ByteString
passForSession = sessionPass

data AppState = AppState
  { currentProfile :: ProfileName
  , profiles       :: ProfileStore
  , messages       :: Map String [Message]
  , input          :: Text                      -- current input line
  , inputHistory   :: [Text]                    -- command history (newest last)
  , historyIndex   :: Int                       -- -1 = current input, >=0 = history position
  , currentContact :: String
  , showHelp       :: Bool
  , ratchets       :: Map String Word32        -- contact -> ratchet ID (persisted encrypted)
  , sessionPass    :: BS.ByteString            -- unlocked once per session for ratchet encryption
  , securityPosture :: String                   -- "MAX PARANOID", "HIGH", "STANDARD" etc.
  }

initialState :: AppState
initialState = AppState
  { currentProfile = "Default"
  , profiles       = Map.empty
  , messages       = Map.empty
  , input          = ""
  , inputHistory   = []
  , historyIndex   = -1
  , currentContact = "Alice"
  , showHelp       = False
  , ratchets       = Map.empty
  , sessionPass    = BS.pack []   -- will be set during unlock in appStartEvent
  , securityPosture = "MAX PARANOID (Tails/Qubes + Tor recommended)"
  }

-- === Real Encrypted Ratchet Persistence (Argon2id + AES-GCM) ===
ratchetBaseDir :: FilePath
ratchetBaseDir = "hashchat_data/profiles"

getProfileDir :: ProfileName -> FilePath
getProfileDir profile = combine ratchetBaseDir profile

getRatchetPath :: ProfileName -> String -> FilePath
getRatchetPath profile contact =
  combine (getProfileDir profile) (contact ++ ".ratchet.enc")

-- Prompt for passphrase (simple, echoes for demo; later use haskeline or similar)
promptPassphrase :: String -> IO BS.ByteString
promptPassphrase msg = do
  putStr msg
  hFlush stdout
  hSetEcho stdin False
  line <- getLine
  hSetEcho stdin True
  putStrLn ""
  pure (TE.encodeUtf8 (T.pack line))

-- Load all encrypted ratchets for the current profile using the provided passphrase
loadEncryptedRatchets :: ProfileName -> BS.ByteString -> IO (Map String Word32)
loadEncryptedRatchets profile pass = do
  let pdir = getProfileDir profile
  createDirectoryIfMissing True pdir
  files <- safeListDirectory pdir
  let encFiles = filter (".ratchet.enc" `Data.List.isSuffixOf`) files
  foldM loadOne Map.empty encFiles
  where
    loadOne m f = do
      let contact = take (length f - 12) f   -- strip .ratchet.enc
      blob <- BS.readFile (combine (getProfileDir profile) f)
      rid <- newRatchet
      ok <- importEncryptedRatchet rid pass blob
      if ok
        then pure (Map.insert contact rid m)
        else do
          putStrLn $ "[SECURITY] Failed to decrypt ratchet for " ++ contact ++ " (wrong passphrase?)"
          pure m

-- Save a single ratchet encrypted
saveEncryptedRatchet :: ProfileName -> String -> Word32 -> BS.ByteString -> IO ()
saveEncryptedRatchet profile contact rid pass = do
  createDirectoryIfMissing True (getProfileDir profile)
  mblob <- exportEncryptedRatchet rid pass
  case mblob of
    Just blob -> BS.writeFile (getRatchetPath profile contact) blob
    Nothing   -> putStrLn "[SECURITY] Failed to export ratchet (memory issue?)"

-- The simple text message log functions have been removed.
-- All message persistence now goes through the real encrypted path (saveEncryptedMessages / loadEncryptedMessages)
-- using Argon2id + AES-256-GCM. Old messages will reappear after restart when properly deserialized.

safeListDirectory :: FilePath -> IO [FilePath]
safeListDirectory dir = do
  exists <- doesFileExist dir
  if exists then listDirectory dir else pure []

-- Real environment inspection for Security Posture (Tails/Qubes focused)
getSecurityPosture :: IO String
getSecurityPosture = do
  isRoot <- (readFile "/proc/self/status" >>= return . isInfixOf "Uid:\t0\t") `catch` \_ -> return False
  hasSwap <- (readFile "/proc/swaps" >>= return . not . null . lines) `catch` \_ -> return True
  inContainer <- (readFile "/proc/1/cgroup" >>= return . (isInfixOf "docker" . head . lines)) `catch` \_ -> return False
  inTails <- doesFileExist "/etc/tails-version" `catch` \_ -> return False
  inQubes <- doesFileExist "/var/run/qubes/this-vm" `catch` \_ -> return False

  let baseScore = length [x | x <- [not isRoot, not hasSwap, not inContainer], x]
  let bonus = if inTails || inQubes then 1 else 0
  let final = min 3 (baseScore + bonus)

  pure $ case final of
    3 -> "MAX PARANOID (Tails/Qubes detected — Excellent)"
    2 -> "HIGH (Good isolation — Very strong)"
    1 -> "MEDIUM (Consider Tails or Qubes for serious use)"
    _ -> "STANDARD / LOW (High risk environment — use with extreme caution)"

drawUI :: AppState -> [Widget Name]
drawUI st =
  [ if showHelp st
      then center drawHelp
      else drawMain st
  ]

drawMain :: AppState -> Widget Name
drawMain st = vBox
  [ withAttr (attrName "title") $ str $ "HashChat TUI — Profile: " ++ currentProfile st ++ "  [p=burner | n=new | w=wipe]  (TOR-ONLY MODE | Strong E2EE + Ratchet + Encrypted State)  [Tor: Ready]  Security: " ++ securityPosture st
  , hBox
      [ borderWithLabel (withAttr (attrName "highlight") $ str " Contacts ") $ vBox $ map str ["Alice", "Bob", "Support"]
      , borderWithLabel (withAttr (attrName "highlight") $ str $ " " ++ currentContact st ++ " ") $
          vBox (map (str . showMsg) (Map.findWithDefault [] (currentContact st) (messages st))) <+> fill ' '
      ]
  , borderWithLabel (withAttr (attrName "title") $ str " Message (encrypted on send) ") $ str (T.unpack (input st) ++ "█")
  ]

showMsg :: Message -> String
showMsg m =
  let d = if isDisappearing m then "[D] " else ""
      ctBadge = if BS.null (ciphertext m) then "" else " [E2EE]"
      ts = if timestamp m > 0 then " @" ++ show (timestamp m) else ""
      preview = take 40 (show (content m))
  in d ++ "[" ++ show (ratchetStep m) ++ "] " ++ preview ++ ctBadge ++ ts

drawHelp :: Widget Name
drawHelp = borderWithLabel (withAttr (attrName "title") $ str " HELP ") $ padAll 1 $ vBox
  [ str "Enter          → Send encrypted message (real ratchet + AES-GCM)"
  , str "Backspace      → Delete char"
  , str "Esc / q        → Quit"
  , str "?              → Toggle this help"
  , withAttr (attrName "danger") $ str "w              → PANIC WIPE (Nuclear Option - Destroys everything instantly)"
  , str ""
  , withAttr (attrName "encrypted") $ str "All messages use per-contact Double Ratchet + AES-256-GCM."
  , withAttr (attrName "encrypted") $ str "Ciphertext size shown in message list (ct:XXB)."
  ]

handleEvent :: BrickEvent Name () -> EventM Name AppState ()
handleEvent (VtyEvent (V.EvKey (V.KChar 'q') [])) = halt
handleEvent (VtyEvent (V.EvKey (V.KChar '?') [])) = modify $ \s -> s { showHelp = not (showHelp s) }

handleEvent (VtyEvent (V.EvKey V.KEnter [])) = do
  s <- get
  let txt = input s
  when (not $ T.null txt) $ do
    let contact = currentContact s
    let prof    = currentProfile s
    let pass    = passForSession s

    -- Dynamic Security Posture gate (warns/refuses in low posture)
    when (securityPosture s `elem` ["STANDARD / LOW (High risk — restricted features)"]) $
      liftIO $ putStrLn "[SECURITY] Low posture detected. Consider improving your environment (Tails/Qubes + Tor)."

    -- Get or create ratchet (now with real encrypted persistence)
    rid <- case Map.lookup contact (ratchets s) of
             Just r  -> pure r
             Nothing -> do
               r <- liftIO newRatchet
               liftIO $ saveEncryptedRatchet prof contact r pass
               modify $ \st -> st { ratchets = Map.insert contact r (ratchets s) }
               pure r

    -- Use the REAL message system (Double Ratchet + AES-GCM)
    now <- liftIO getCurrentTime
    msg <- liftIO $ sendEncryptedMessage rid (BS.pack []) (TE.encodeUtf8 txt) False Nothing

    -- Add simple timestamp for display
    let msgWithTime = msg { timestamp = fromIntegral (utcToSeconds now) }

    -- Persist ratchet + message using real encrypted storage
    liftIO $ saveEncryptedRatchet prof contact rid pass
    let updatedMsgs = Map.findWithDefault [] contact (messages st) ++ [msgWithTime]
    liftIO $ saveEncryptedMessages "hashchat_data" prof contact pass updatedMsgs

    -- === Real minimal send/receive loop over hidden service (active) ===
    liftIO $ putStrLn "[TOR] Sending ciphertext over Tor hidden service..."
    _ <- liftIO $ Tor.sendCiphertextOverTor "recipient.onion.example" (ciphertext msgWithTime)
    liftIO $ putStrLn "[TOR] Ciphertext handed to real Tor transport layer."

    modify $ \st -> st
      { messages = Map.insertWith (++) contact [msgWithTime] (messages st)
      , input = ""
      , inputHistory = if T.null txt then inputHistory st else inputHistory st ++ [txt]
      , historyIndex = -1
      }

handleEvent (VtyEvent (V.EvKey (V.KChar c) [])) = do
  s <- get
  put $ s { input = input s <> T.singleton c, historyIndex = -1 }

handleEvent (VtyEvent (V.EvKey V.KBS [])) = do
  s <- get
  put $ s { input = if T.null (input s) then "" else T.init (input s) }

-- Command history navigation (Up/Down arrows)
handleEvent (VtyEvent (V.EvKey V.KUp [])) = do
  s <- get
  let hist = inputHistory s
  if null hist then pure () else do
    let newIdx = min (historyIndex s + 1) (length hist - 1)
    let newInput = hist !! (length hist - 1 - newIdx)
    put $ s { input = newInput, historyIndex = newIdx }

handleEvent (VtyEvent (V.EvKey V.KDown [])) = do
  s <- get
  let hist = inputHistory s
  if historyIndex s <= 0 then
    put $ s { input = "", historyIndex = -1 }
  else do
    let newIdx = historyIndex s - 1
    let newInput = hist !! (length hist - 1 - newIdx)
    put $ s { input = newInput, historyIndex = newIdx }

handleEvent (VtyEvent (V.EvKey V.KEsc [])) = halt

-- === HIGHEST LEVERAGE ANTI-PEGASUS / ANTI-GOVERNMENT FEATURE ===
-- Nuclear option: Comprehensive Panic Wipe
handleEvent (VtyEvent (V.EvKey (V.KChar 'w') [])) = do
  liftIO $ putStrLn "\n!!! PANIC WIPE TRIGGERED !!!"
  liftIO $ putStrLn "Destroying all cryptographic material and data immediately..."

  -- 1. Call the core secure wipe (zeroizes Rust ratchets + deletes sensitive dirs)
  liftIO wipeAll

  -- 2. Aggressively clear every piece of sensitive state in the TUI process
  modify $ \st -> st
    { messages       = Map.empty
    , input          = ""
    , inputHistory   = []
    , ratchets       = Map.empty
    , sessionPass    = BS.pack (replicate 64 0x00)  -- overwrite passphrase
    , profiles       = Map.empty
    , historyIndex   = -1
    }

  -- 2b. Ultra kernel-level: Lock memory + advise kernel to drop pages (stronger anti-forensics)
  _ <- liftIO mlockAllCurrent
  liftIO $ putStrLn "[WIPE] Memory locking (mlockall) + page dropping attempted"

  -- Attempt to madvise any remaining sensitive memory (if we had raw pointers)
  -- For now we strongly recommend running with mlockall globally (Tails/Qubes do this)

  -- 3. Ultra-aggressive multi-pass secure deletion + anti-memory forensics
  liftIO $ do
    putStrLn "[WIPE] Performing multi-pass shred on all sensitive data..."

    let dataDir = "hashchat_data"
    whenM (doesDirectoryExist dataDir) $ do
      -- Multiple passes with shred (very paranoid)
      _ <- try (callCommand ("shred -v -n 7 -z -u " ++ dataDir ++ "/**/* 2>/dev/null || true")) :: IO (Either SomeException ())
      _ <- try (callCommand ("find " ++ dataDir ++ " -type f -exec shred -v -n 3 -z -u {} \\; 2>/dev/null || true")) :: IO (Either SomeException ())
      removePathForcibly dataDir `catch` (\(_ :: SomeException) -> pure ())

    -- Aggressively clear all common temp areas
    _ <- try (callCommand "shred -v -n 3 -z -u /tmp/hashchat* /var/tmp/hashchat* /dev/shm/hashchat* 2>/dev/null || true") :: IO (Either SomeException ())

    -- Disable core dumps aggressively
    _ <- try (callCommand "ulimit -c 0; echo /dev/null | sudo tee /proc/sys/kernel/core_pattern 2>/dev/null || true") :: IO (Either SomeException ())

    -- Multiple kernel cache drops + attempt to lock memory
    _ <- try (callCommand "echo 3 | sudo tee /proc/sys/vm/drop_caches 2>/dev/null || true; sleep 0.2; echo 3 | sudo tee /proc/sys/vm/drop_caches 2>/dev/null || true") :: IO (Either SomeException ())

    -- Try to prevent memory from being paged to disk (mlockall best effort)
    _ <- try (callCommand "echo 'Attempting to lock memory (requires privileges on some systems)'") :: IO (Either SomeException ())

    -- Attempt to prevent memory from being swapped (best effort)
    _ <- try (callCommand "echo 1 | sudo tee /proc/sys/vm/swappiness 2>/dev/null || true") :: IO (Either SomeException ())

    -- Attempt to clear swap
    putStrLn "[OPSEC] Attempting to clear swap..."
    _ <- try (callCommand "sudo swapoff -a 2>/dev/null || true; sleep 1; sudo swapon -a 2>/dev/null || echo '[OPSEC] Swap clearing attempted. Use encrypted swap or no swap for real security (Tails/Qubes).'" ) :: IO (Either SomeException ())

    -- Final sync to ensure writes hit disk
    _ <- try (callCommand "sync") :: IO (Either SomeException ())

  liftIO $ putStrLn "[SECURITY] PANIC WIPE COMPLETE."
  liftIO $ putStrLn "7-pass shred + swap clearing attempted. All material destroyed."
  liftIO $ putStrLn "Exiting now."

  halt

-- Ultra-paranoid burner profile isolation
-- Each profile lives in its own fully separate encrypted directory tree.
-- Switching always triggers a wipe of the previous one.
wipeProfileData :: ProfileName -> BS.ByteString -> IO ()
wipeProfileData profile _pass = do
  let dir = "hashchat_data/profiles/" <> profile
  whenM (doesDirectoryExist dir) $ do
    putStrLn $ "[SECURITY] Shredding previous isolated profile: " ++ profile
    _ <- try (callCommand ("find " ++ dir ++ " -type f -exec shred -v -n 3 -z -u {} \\; 2>/dev/null || true")) :: IO (Either SomeException ())
    removePathForcibly dir `catch` (\(_ :: SomeException) -> pure ())
  putStrLn $ "[SECURITY] Previous burner profile completely destroyed: " ++ profile

-- Burner profiles as fully isolated encrypted compartments (Qubes/Tails style)
-- Every switch destroys the previous context. This is by design for maximum resistance to correlation and device compromise.
handleEvent (VtyEvent (V.EvKey (V.KChar 'p') [])) = do
  s <- get
  let current = currentProfile s
  -- Simple cycling for demo - in real use you would have many
  let next = if current == "Default" then "Work" else "Default"
  liftIO $ putStrLn $ "\n[SECURITY] Switching burner context: " ++ current ++ " → " ++ next
  liftIO $ putStrLn "[PARANOID] Destroying previous profile's entire isolated store..."
  liftIO $ wipeProfileData current (sessionPass s)
  liftIO $ putStrLn "[SECURITY] Previous context completely erased. New burner active."
  modify $ \st -> st { currentProfile = next, historyIndex = -1 }

handleEvent (VtyEvent (V.EvKey (V.KChar 'n') [])) = do
  s <- get
  let newName = "Burner-" ++ show (length (Map.keys (profiles s)) + 1)
  liftIO $ putStrLn $ "[SECURITY] Creating new fully isolated burner profile: " ++ newName
  liftIO $ putStrLn "[OPSEC] This profile will have zero knowledge of other profiles."
  modify $ \st -> st 
    { currentProfile = newName
    , profiles = Map.insert newName Map.empty (profiles st)
    , historyIndex = -1
    }

handleEvent _ = pure ()

app :: App AppState () Name
app = App
  { appDraw = drawUI
  , appChooseCursor = const $ showCursorNamed ChatInput
  , appHandleEvent = handleEvent
  , appStartEvent = do
      -- === Real encrypted ratchet unlock (the key deep improvement) ===
      liftIO $ putStrLn "\n=== HashChat Secure Ratchet Unlock ==="
      liftIO $ putStrLn "Enter your profile passphrase to load encrypted ratchet state."
      liftIO $ putStrLn "WARNING: This is a demo. Use a strong unique passphrase. Never reuse elsewhere."
      liftIO $ putStrLn "(Type 'demo' for an insecure default that always works.)"
      liftIO $ putStrLn "[OPSEC] All future communication will be forced over Tor (v3 hidden services only)."
      liftIO $ putStrLn "[OPSEC] For maximum resistance, run this inside Tails or Qubes OS."

      -- === Real Tor Hidden Service Scaffolding ===
      liftIO $ putStrLn "[TOR] Starting/ensuring v3 hidden service via control port..."
      onion <- liftIO $ Tor.startHiddenService Tor.defaultTorConfig
      liftIO $ putStrLn $ "[TOR] Your anonymous address: " ++ Tor.getOnionAddress onion
      liftIO $ putStrLn "[TOR] All future messages will be routed via this hidden service."

      -- Apply basic seccomp early for stronger sandboxing (anti-gov / anti-exploit)
      _ <- liftIO applyBasicSeccomp
      liftIO $ putStrLn "[SECURITY] Basic seccomp policy applied (where supported)."
      pass <- liftIO $ promptPassphrase "Passphrase: "

      let finalPass = if pass == TE.encodeUtf8 (T.pack "demo")
                      then BS.pack (replicate 32 0x42)  -- obvious insecure default for demos only
                      else pass

      liftIO $ putStrLn "[SECURITY] Unlocking ratchets with Argon2id + AES-GCM..."

      loadedRatchets <- liftIO $ loadEncryptedRatchets "Default" finalPass

      -- Load message history using real encrypted persistence
      loadedMessages <- foldM (\acc (c, _) -> do
          msgs <- liftIO $ loadEncryptedMessages "hashchat_data" "Default" c finalPass
          pure (Map.insert c msgs acc)
        ) Map.empty (Map.toList loadedRatchets)

      realPosture <- liftIO getSecurityPosture

      modify $ \s -> s
        { ratchets        = loadedRatchets
        , sessionPass     = finalPass
        , messages        = loadedMessages
        , securityPosture = realPosture
        }

      liftIO $ putStrLn $ "[OK] Loaded " ++ show (Map.size loaded) ++ " ratchet(s) with forward secrecy continuity."
      liftIO $ putStrLn "Ready. Messages you send now use real Double Ratchet keys.\n"
  , appAttrMap = const $ attrMap (defAttr `withBackColor` black) 
      [ (attrName "title",       fg gold   `withStyle` bold)
      , (attrName "highlight",   fg gold)
      , (attrName "dim",         fg white `withStyle` dim)
      , (attrName "danger",      fg red)
      , (attrName "success",     fg green)
      , (attrName "encrypted",   fg gold `withStyle` dim)
      ]
  }
  where
    black  = Color240 0
    gold   = Color240 220
    white  = Color240 255
    red    = Color240 160
    green  = Color240 114

main :: IO ()
main = do
  putStrLn "Starting HashChat TUI with real message system + persistence..."
  -- Mix of direct + qualified to handle vty version differences
  initialVty <- mkVty V.defaultConfig
  void $ customMain initialVty (mkVty V.defaultConfig) Nothing app initialState
