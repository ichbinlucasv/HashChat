module HashChat.Group where

import qualified Data.ByteString as BS

data Group = Group
  { groupId :: BS.ByteString
  , members :: [BS.ByteString]
  }

createGroup :: [BS.ByteString] -> IO Group
createGroup ms = pure $ Group
  { groupId = BS.pack (take 32 (cycle [0x01]))
  , members = ms
  }

joinGroup :: BS.ByteString -> IO ()
joinGroup _ = pure ()

sendGroupMessage :: BS.ByteString -> BS.ByteString -> IO ()
sendGroupMessage _ _ = pure ()