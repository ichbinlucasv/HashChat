module MessageUI where

-- Thin bridge so the Brick TUI can use the real message system
-- Import this in the main TUI.hs

import HashChat.Core
import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.ByteString (ByteString)
import Data.Time.Clock (NominalDiffTime)

-- Per-profile state the TUI can hold
type UIState = (ProfileStore, Map String [Message])   -- (ratchets per profile, messages per contact)

-- Send a message from the TUI (uses real ratchet encryption)
uiSendMessage :: Word32 -> ByteString -> ByteString -> Bool -> Maybe NominalDiffTime -> IO Message
uiSendMessage = sendEncryptedMessage

-- Receive a message in the TUI
uiReceiveMessage :: Word32 -> ByteString -> ByteString -> IO (Maybe Message)
uiReceiveMessage = receiveEncryptedMessage

-- Check and clean disappearing messages (call on refresh)
uiProcessDisappearing :: [Message] -> IO [Message]
uiProcessDisappearing = processDisappearingMessages

-- Burner profile helpers for the TUI
createNewBurner :: ProfileName -> ProfileStore -> ProfileStore
createNewBurner name store = Map.insert name Map.empty store

switchToBurner :: ProfileName -> ProfileStore -> Maybe ContactRatchets
switchToBurner name store = Map.lookup name store
