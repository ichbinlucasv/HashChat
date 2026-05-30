{-# LANGUAGE OverloadedStrings #-}

module Main where

import Brick
import Brick.Widgets.Border (borderWithLabel)
import Brick.Widgets.Core (str, hBox, vBox, padAll, fill, withAttr)
import Brick.Widgets.Center (center)
import Brick.Widgets.Edit (Editor, editor, renderEditor, getEditContents)
import qualified Graphics.Vty as V
import qualified Data.Text as T
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import HashChat.Core
import MessageUI   -- our new bridge
import Control.Monad (when, void)

-- Very simplified but functional TUI that uses the real message system
data Name = ChatInput | ContactList deriving (Eq, Ord, Show)

data AppState = AppState
  { currentProfile :: ProfileName
  , profiles       :: ProfileStore
  , messages       :: Map String [Message]
  , input          :: Editor Text Name
  , currentContact :: String
  }

initialState :: AppState
initialState = AppState
  { currentProfile = "Default"
  , profiles       = Map.empty
  , messages       = Map.empty
  , input          = editor ChatInput (Just 1) ""
  , currentContact = "Alice"
  }

drawUI :: AppState -> [Widget Name]
drawUI st = [vBox
  [ str $ "HashChat TUI - Profile: " ++ currentProfile st
  , borderWithLabel (str " Contacts ") $ str "Alice\nBob\nSupport"
  , borderWithLabel (str $ " Chat with " ++ currentContact st) $
      vBox $ map (str . showMessage) (Map.findWithDefault [] (currentContact st) (messages st))
  , renderEditor (str . T.unpack) True (input st)
  ]]

showMessage :: Message -> String
showMessage m = "[" ++ show (ratchetStep m) ++ "] " ++ (if isDisappearing m then "[disappearing] " else "") ++ show (content m)

handleEvent :: BrickEvent Name () -> EventM Name AppState ()
handleEvent (VtyEvent (V.EvKey V.KEnter [])) = do
  s <- get
  let content = T.concat (getEditContents (input s))
  when (not $ T.null content) $ do
    -- Use the real message system
    let rid = 0  -- In real version get from current profile + contact
    newMsg <- liftIO $ sendEncryptedMessage rid (BS.pack []) (TE.encodeUtf8 content) False Nothing
    let updated = Map.insertWith (++) (currentContact s) [newMsg] (messages s)
    put $ s { messages = updated, input = editor ChatInput (Just 1) "" }
handleEvent (VtyEvent (V.EvKey (V.KChar 'q') [])) = halt
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
  , appStartEvent = pure ()
  , appAttrMap = const $ attrMap defAttr []
  }

main :: IO ()
main = do
  putStrLn "Starting HashChat TUI with real message system..."
  initialVty <- V.mkVty V.defaultConfig
  void $ customMain initialVty (V.mkVty V.defaultConfig) Nothing app initialState
