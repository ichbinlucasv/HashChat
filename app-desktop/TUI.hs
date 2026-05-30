{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE LambdaCase #-}

module Main where

import Brick
import Brick.Widgets.Border (borderWithLabel)
import Brick.Widgets.Core (str, hBox, vBox, padAll, fill, withAttr)
import Brick.Widgets.Center (center)
import Brick.Widgets.Edit (Editor, editor, renderEditor, getEditContents, handleEditorEvent)
import qualified Graphics.Vty as V
import qualified Data.Text as T
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import HashChat.Core
import MessageUI
import Control.Monad (when, void)
import System.Directory (createDirectoryIfMissing)
import System.FilePath (combine, takeDirectory)
import Data.Time.Clock (getCurrentTime)
import System.IO (hFlush, stdout, hSetEcho, stdin)
import qualified Data.List
import System.Directory (listDirectory, doesFileExist)
import Control.Monad (foldM)

data Name = ChatInput | ContactList | Help deriving (Eq, Ord, Show)

-- Helper to get the current session passphrase (must be set after unlock)
passForSession :: AppState -> ByteString
passForSession = sessionPass

data AppState = AppState
  { currentProfile :: ProfileName
  , profiles       :: ProfileStore
  , messages       :: Map String [Message]
  , input          :: Editor Text Name
  , currentContact :: String
  , showHelp       :: Bool
  , ratchets       :: Map String Word32        -- contact -> ratchet ID (persisted encrypted)
  , sessionPass    :: ByteString               -- unlocked once per session for ratchet encryption
  }

initialState :: AppState
initialState = AppState
  { currentProfile = "Default"
  , profiles       = Map.empty
  , messages       = Map.empty
  , input          = editor ChatInput (Just 1) ""
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
promptPassphrase :: String -> IO ByteString
promptPassphrase msg = do
  putStr msg
  hFlush stdout
  hSetEcho stdin False
  line <- getLine
  hSetEcho stdin True
  putStrLn ""
  pure (TE.encodeUtf8 (T.pack line))

-- Load all encrypted ratchets for the current profile using the provided passphrase
loadEncryptedRatchets :: ProfileName -> ByteString -> IO (Map String Word32)
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
saveEncryptedRatchet :: ProfileName -> String -> Word32 -> ByteString -> IO ()
saveEncryptedRatchet profile contact rid pass = do
  createDirectoryIfMissing True (getProfileDir profile)
  mblob <- exportEncryptedRatchet rid pass
  case mblob of
    Just blob -> BS.writeFile (getRatchetPath profile contact) blob
    Nothing   -> putStrLn "[SECURITY] Failed to export ratchet (memory issue?)"

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
  [ str $ "HashChat TUI — Profile: " ++ currentProfile st ++ "  (? help, q quit)"
  , hBox
      [ borderWithLabel (str " Contacts ") $ vBox $ map str ["Alice", "Bob", "Support"]
      , borderWithLabel (str $ " " ++ currentContact st ++ " ") $
          vBox (map (str . showMsg) (Map.findWithDefault [] (currentContact st) (messages st))) <+> fill ' '
      ]
  , borderWithLabel (str " Message ") $ renderEditor (str . T.unpack) True (input st)
  ]

showMsg :: Message -> String
showMsg m =
  let d = if isDisappearing m then "[D] " else ""
  in d ++ "[" ++ show (ratchetStep m) ++ "] " ++ show (content m)

drawHelp :: Widget Name
drawHelp = borderWithLabel (str " HELP ") $ padAll 1 $ vBox
  [ str "Enter to send (uses real Double Ratchet + AES-GCM)"
  , str "? toggle help | q quit"
  ]

handleEvent :: BrickEvent Name () -> EventM Name AppState ()
handleEvent (VtyEvent (V.EvKey (V.KChar 'q') [])) = halt
handleEvent (VtyEvent (V.EvKey (V.KChar '?') [])) = modify $ \s -> s { showHelp = not (showHelp s) }

handleEvent (VtyEvent (V.EvKey V.KEnter [])) = do
  s <- get
  let txt = T.concat (getEditContents (input s))
  when (not $ T.null txt) $ do
    let contact = currentContact s
    let prof    = currentProfile s
    let pass    = passForSession s   -- we store the unlocked passphrase in state for this session

    -- Get or create ratchet (now with real encrypted persistence)
    rid <- case Map.lookup contact (ratchets s) of
             Just r  -> pure r
             Nothing -> do
               r <- liftIO newRatchet
               liftIO $ saveEncryptedRatchet prof contact r pass
               modify $ \st -> st { ratchets = Map.insert contact r (ratchets s) }
               pure r

    -- Use the REAL message system (Double Ratchet + AES-GCM)
    msg <- liftIO $ sendEncryptedMessage rid (BS.pack []) (TE.encodeUtf8 txt) False Nothing

    -- Immediately persist the advanced ratchet state (forward secrecy)
    liftIO $ saveEncryptedRatchet prof contact rid pass

    modify $ \st -> st
      { messages = Map.insertWith (++) contact [msg] (messages st)
      , input = editor ChatInput (Just 1) ""
      }

handleEvent (VtyEvent ev) = do
  s <- get
  newEd <- handleEditorEvent (VtyEvent ev) (input s)
  put $ s { input = newEd }

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

      loaded <- liftIO $ loadEncryptedRatchets "Default" finalPass

      modify $ \s -> s
        { ratchets    = loaded
        , sessionPass = finalPass
        }

      liftIO $ putStrLn $ "[OK] Loaded " ++ show (Map.size loaded) ++ " ratchet(s) with forward secrecy continuity."
      liftIO $ putStrLn "Ready. Messages you send now use real Double Ratchet keys.\n"
  , appAttrMap = const $ attrMap defAttr []
  }

main :: IO ()
main = do
  putStrLn "Starting HashChat TUI with real message system + persistence..."
  initialVty <- V.mkVty V.defaultConfig
  void $ customMain initialVty (V.mkVty V.defaultConfig) Nothing app initialState
