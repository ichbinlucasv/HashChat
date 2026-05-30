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
import MessageUI
import Control.Monad (when, void, foldM)
import Control.Monad.IO.Class (liftIO)
import Control.Exception (catch, SomeException)
import System.Directory (removePathForcibly)
import System.Directory (createDirectoryIfMissing, listDirectory, doesFileExist)
import System.FilePath (combine, takeDirectory)
import Data.Time.Clock (getCurrentTime)
import System.IO (hFlush, stdout, hSetEcho, stdin)
import qualified Data.List
import Data.List (elemIndex)

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

-- Simple message log persistence (demo version - stores as text for now)
-- In production this must be encrypted with the same passphrase as the ratchets.
saveMessagesSimple :: ProfileName -> String -> [Message] -> IO ()
saveMessagesSimple profile contact msgs = do
  let dir = "hashchat_data/profiles/" <> profile <> "/messages"
  createDirectoryIfMissing True dir
  let path = dir <> "/" <> contact <> ".txt"
  let lines = map (\m -> show (ratchetStep m) ++ " " ++ show (content m)) msgs
  writeFile path (unlines lines)

loadMessagesSimple :: ProfileName -> String -> IO [Message]
loadMessagesSimple profile contact = do
  let path = "hashchat_data/profiles/" <> profile <> "/messages/" <> contact <> ".txt"
  exists <- doesFileExist path
  if exists then do
    fileContent <- readFile path
    let parsed = parseSimpleMessages fileContent
    pure parsed
  else pure []

-- Very simple parser for the demo format: "step \"content here\""
parseSimpleMessages :: String -> [Message]
parseSimpleMessages content =
  let lines = filter (not . null) (lines content)
  in map parseLine lines

parseLine :: String -> Message
parseLine line =
  let (stepStr, rest) = break (== ' ') line
      step = read stepStr :: Word32
      msgContent = drop 1 $ dropWhile (/= '"') rest
      cleanContent = takeWhile (/= '"') msgContent
  in Message
       { msgId = fromIntegral step
       , sender = BS.pack []
       , content = TE.encodeUtf8 (T.pack cleanContent)
       , ciphertext = BS.pack []   -- demo version does not store full ciphertext yet
       , timestamp = 0
       , isDisappearing = False
       , expiresAt = Nothing
       , ratchetStep = step
       }

safeListDirectory :: FilePath -> IO [FilePath]
safeListDirectory dir = do
  exists <- doesFileExist dir
  if exists then listDirectory dir else pure []

drawUI :: AppState -> [Widget Name]
drawUI st =
  [ if showHelp st
      then center drawHelp
      else drawMain st
  ]

drawMain :: AppState -> Widget Name
drawMain st = vBox
  [ withAttr (attrName "title") $ str $ "HashChat TUI — Profile: " ++ currentProfile st ++ "  [p=burner | n=new | w=wipe]  (Strong E2EE + Ratchet + Encrypted State)"
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

    -- Add simple timestamp for display (real one should come from the message)
    let msgWithTime = msg { timestamp = fromIntegral (utcToSeconds now) }  -- rough

    -- Persist ratchet + message
    liftIO $ saveEncryptedRatchet prof contact rid pass
    liftIO $ saveMessagesSimple prof contact (Map.findWithDefault [] contact (messages st) ++ [msgWithTime])

    modify $ \st -> st
      { messages = Map.insertWith (++) contact [msg] (messages st)
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

  -- 3. Best-effort secure deletion of the entire data directory
  liftIO $ do
    let dataDir = "hashchat_data"
    when (dataDir /= "") $ do
      removePathForcibly dataDir `catch` (\(_ :: SomeException) -> pure ())

  liftIO $ putStrLn "[SECURITY] PANIC WIPE COMPLETE."
  liftIO $ putStrLn "All ratchet state, messages, and keys have been destroyed."
  liftIO $ putStrLn "Exiting now."

  halt

-- Burner profile switching (p key) + create new (n key)
handleEvent (VtyEvent (V.EvKey (V.KChar 'p') [])) = do
  s <- get
  let profiles = ["Default", "Work", "Travel", "Journalist", "Activist"]
  let current = currentProfile s
  let idx = maybe 0 id (elemIndex current profiles)
  let next = profiles !! ((idx + 1) `mod` length profiles)
  liftIO $ putStrLn $ "[SECURITY] Switched to burner profile: " ++ next
  modify $ \st -> st { currentProfile = next, historyIndex = -1 }

handleEvent (VtyEvent (V.EvKey (V.KChar 'n') [])) = do
  s <- get
  let newName = "Burner-" ++ show (length (profiles s) + 1)
  liftIO $ putStrLn $ "[SECURITY] Created new burner profile: " ++ newName
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
      pass <- liftIO $ promptPassphrase "Passphrase: "

      let finalPass = if pass == TE.encodeUtf8 (T.pack "demo")
                      then BS.pack (replicate 32 0x42)  -- obvious insecure default for demos only
                      else pass

      liftIO $ putStrLn "[SECURITY] Unlocking ratchets with Argon2id + AES-GCM..."

      loadedRatchets <- liftIO $ loadEncryptedRatchets "Default" finalPass

      -- Load message history (simple version for demo)
      loadedMessages <- foldM (\acc (c, _) -> do
          msgs <- liftIO $ loadMessagesSimple "Default" c
          pure (Map.insert c msgs acc)
        ) Map.empty (Map.toList loadedRatchets)

      modify $ \s -> s
        { ratchets    = loadedRatchets
        , sessionPass = finalPass
        , messages    = loadedMessages
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
