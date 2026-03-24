module Main where
import qualified GI.Gtk as Gtk
import GI.Gtk
import HashChat.Core
import HashChat.FileTransfer
import HashChat.Contact
import HashChat.Voice
import HashChat.Call
import HashChat.Settings
import HashChat.Security
import Data.ByteString
main :: IO ()
main = do
  Gtk.init Nothing
  win <- Gtk.windowNew Gtk.WindowTypeToplevel
  setWindowTitle win "HashChat"
  setWindowDefaultSize win 1200 800
  hbox <- boxNew OrientationHorizontal 0
  sidebar <- boxNew OrientationVertical 10
  btnNewChat <- buttonNewWithLabel "New Chat"
  btnAddContact <- buttonNewWithLabel "Add Contact (link/QR)"
  btnFiles <- buttonNewWithLabel "Send File"
  btnVoice <- buttonNewWithLabel "Voice Message"
  btnAudioCall <- buttonNewWithLabel "Audio Call"
  btnVideoCall <- buttonNewWithLabel "Video Call"
  btnSettings <- buttonNewWithLabel "Settings"
  btnPrivacy <- buttonNewWithLabel "Privacy Settings"
  btnNetwork <- buttonNewWithLabel "Network Settings"
  btnWipe1 <- buttonNewWithLabel "Panic Wipe - Step 1"
  btnWipe2 <- buttonNewWithLabel "Panic Wipe - Step 2 (final)"
  onButtonClicked btnAddContact (addContactViaLink (pack []))
  onButtonClicked btnFiles (sendFile "/tmp/test")
  onButtonClicked btnVoice (recordVoiceMessage >> return ())
  onButtonClicked btnAudioCall startAudioCall
  onButtonClicked btnVideoCall startVideoCall
  onButtonClicked btnPrivacy openPrivacySettings
  onButtonClicked btnNetwork openNetworkSettings
  onButtonClicked btnWipe1 (dialogNew >>= \d -> dialogRun d >> widgetDestroy d)
  onButtonClicked btnWipe2 wipeAll
  containerAdd sidebar btnNewChat
  containerAdd sidebar btnAddContact
  containerAdd sidebar btnFiles
  containerAdd sidebar btnVoice
  containerAdd sidebar btnAudioCall
  containerAdd sidebar btnVideoCall
  containerAdd sidebar btnSettings
  containerAdd sidebar btnPrivacy
  containerAdd sidebar btnNetwork
  containerAdd sidebar btnWipe1
  containerAdd sidebar btnWipe2
  mainArea <- boxNew OrientationVertical 10
  containerAdd hbox sidebar
  containerAdd hbox mainArea
  containerAdd win hbox
  onWidgetDestroy win mainQuit
  widgetShowAll win
  main