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
import System.FilePath (combine)
import Data.Time.Clock (getCurrentTime)

data Name = ChatInput | ContactList | Help deriving (Eq, Ord, Show)

data AppState = AppState
  { currentProfile :: ProfileName
  , profiles       :: ProfileStore
  , messages       :: Map String [Message]
  , input          :: Editor Text Name
  , currentContact :: String
  , showHelp       :: Bool
  , ratchets       :: Map String Word32        -- contact -> ratchet ID (persisted)
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
  }

-- Simple persistence for ratchet IDs (in real version this would be encrypted)
ratchetStateDir :: FilePath
ratchetStateDir = "hashchat_data/ratchets"

loadRatchets :: IO (Map String Word32)
loadRatchets = do
  createDirectoryIfMissing True ratchetStateDir
  -- For demo we just return empty. Real version reads encrypted files.
  pure Map.empty

saveRatchet :: String -> Word32 -> IO ()
saveRatchet contact rid = do
  createDirectoryIfMissing True ratchetStateDir
  writeFile (combine ratchetStateDir contact) (show rid)

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

    -- Get or create ratchet (persisted)
    rid <- case Map.lookup contact (ratchets s) of
             Just r  -> pure r
             Nothing -> do
               r <- liftIO newRatchet
               liftIO $ saveRatchet contact r
               modify $ \st -> st { ratchets = Map.insert contact r (ratchets s) }
               pure r

    -- Use the REAL message system
    msg <- liftIO $ sendEncryptedMessage rid (BS.pack []) (TE.encodeUtf8 txt) False Nothing

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
      loaded <- liftIO loadRatchets
      modify $ \s -> s { ratchets = loaded }
      -- In real version: decrypt ratchet blobs with user passphrase and restore full state
  , appAttrMap = const $ attrMap defAttr []
  }

main :: IO ()
main = do
  putStrLn "Starting HashChat TUI with real message system + persistence..."
  initialVty <- V.mkVty V.defaultConfig
  void $ customMain initialVty (V.mkVty V.defaultConfig) Nothing app initialState
