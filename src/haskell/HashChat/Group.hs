module HashChat.Group where

-- Groups skeleton with metadata-resistant design notes
-- Real implementation will use something like sender keys (similar to Signal groups)
-- or a group ratchet with forward secrecy.

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)

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

-- Basic group ratchet idea (sender keys style for metadata resistance)
-- Each member maintains their own sending ratchet chain for the group.
-- Messages are encrypted to the current group key + per-sender ratchet.
-- This gives forward secrecy and hides sender metadata from the server.

data GroupRatchet = GroupRatchet
  { grGroupId      :: ByteString
  , memberRatchets :: [Word32]   -- one ratchet per member (sender keys)
  }

-- TODO (deep work):
-- - Proper Sender Keys implementation (like Signal)
-- - Key rotation on member leave/add
-- - Integration with disappearing messages
-- - Metadata resistant delivery (via Tor or mixnet)

-- For now this is a solid skeleton.
