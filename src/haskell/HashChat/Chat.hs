module HashChat.Chat where

import Data.ByteString

data Message = Message
  { msgId :: Int
  , content :: ByteString
  , timestamp :: Int
  }

sendChatMessage :: ByteString -> ByteString -> IO ()
sendChatMessage _ _ = pure ()

receiveChatMessage :: ByteString -> IO (Maybe ByteString)
receiveChatMessage _ = pure Nothing