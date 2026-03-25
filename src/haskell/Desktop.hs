module Main where

import qualified GI.Gtk as Gtk
import GI.Gtk
import HashChat.Core
import Data.ByteString

main :: IO ()
main = do
  Gtk.init Nothing
  win <- windowNew WindowTypeToplevel
  setWindowTitle win "HashChat"
  setWindowDefaultSize win 1280 720
  setWindowResizable win True
  hbox <- boxNew OrientationHorizontal 0
  sidebar <- boxNew OrientationVertical 12
  btnNewChat <- buttonNewWithLabel "New Chat"
  btnAddContact <- buttonNewWithLabel "Add Contact (link/QR)"
  btnSendFile <- buttonNewWithLabel "Send File"
  btnVoice <- buttonNewWithLabel "Voice Message"
  btnAudioCall <- buttonNewWithLabel "Audio Call"
  btnVideoCall <- buttonNewWithLabel "Video Call"
  btnSettings <- buttonNewWithLabel "Settings"
  btnWipe1 <- buttonNewWithLabel "Panic Wipe - Step 1"
  btnWipe2 <- buttonNewWithLabel "Panic Wipe - Step 2 (final)"
  onButtonClicked btnWipe2 wipeAll
  containerAdd sidebar btnNewChat
  containerAdd sidebar btnAddContact
  containerAdd sidebar btnSendFile
  containerAdd sidebar btnVoice
  containerAdd sidebar btnAudioCall
  containerAdd sidebar btnVideoCall
  containerAdd sidebar btnSettings
  containerAdd sidebar btnWipe1
  containerAdd sidebar btnWipe2
  mainArea <- boxNew OrientationVertical 12
  containerAdd hbox sidebar
  containerAdd hbox mainArea
  containerAdd win hbox
  onWidgetDestroy win mainQuit
  widgetShowAll win
  main