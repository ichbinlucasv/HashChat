module HashChat.Voice where
import Data.ByteString
recordVoiceMessage :: IO ByteString
recordVoiceMessage = pure (pack [])