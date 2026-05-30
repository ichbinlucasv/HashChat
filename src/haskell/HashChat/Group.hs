module HashChat.Group where

-- Groups skeleton with metadata-resistant design notes
-- Real implementation will use something like sender keys (similar to Signal groups)
-- or a group ratchet with forward secrecy.

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

data Group = Group
  { groupId       :: ByteString
  , members       :: [ByteString]     -- pubkeys
  , groupRatchet  :: Maybe Word32     -- group ratchet ID (future)
  }

-- Placeholder for creating a group
createGroup :: [ByteString] -> IO Group
createGroup members = pure $ Group
  { groupId      = BS.pack (take 32 (cycle [0x02]))
  , members      = members
  , groupRatchet = Nothing
  }

-- In a real metadata-resistant group:
-- - Use per-sender ratchets or a group ratchet tree
-- - Never reveal who sent what to the server
-- - Forward secrecy per message
-- - Future: integrate with Tor hidden services for group relays

sendGroupMessage :: ByteString -> ByteString -> IO ()
sendGroupMessage _groupId _msg = pure ()

-- TODO: Add proper group ratchet + disappearing support per group
