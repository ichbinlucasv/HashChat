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

-- === Sender Keys Style Group Ratchet (in progress) ===

-- Each member has their own sending ratchet chain for the group.
-- This gives forward secrecy and metadata resistance (server doesn't know who sent what).

data GroupSenderKey = GroupSenderKey
  { gskRatchetId :: Word32
  , gskChainKey  :: ByteString
  , gskMsgCount  :: Word32
  }

-- Create a new sending ratchet for a member inside a group.
createMemberSendingRatchet :: Word32 -> GroupSenderKey
createMemberSendingRatchet rid = GroupSenderKey
  { gskRatchetId = rid
  , gskChainKey  = BS.replicate 32 0
  , gskMsgCount  = 0
  }

-- Advance sender key (per-member sending ratchet step for groups)
-- This is the single canonical implementation.
advanceSenderKey :: GroupSenderKey -> (ByteString, GroupSenderKey)
advanceSenderKey gsk =
  let newCount = gskMsgCount gsk + 1
      -- In production this would derive the next message key using HKDF
      -- from gskChainKey (matching the main DoubleRatchet KDF).
      msgKey   = BS.take 32 (BS.replicate 32 (fromIntegral (newCount `mod` 256)))
      newChain = BS.take 32 (BS.replicate 32 (fromIntegral ((newCount + 1) `mod` 256)))
  in (msgKey, gsk { gskChainKey = newChain, gskMsgCount = newCount })

-- Encrypt a group message using a member's sending key (very simplified)
encryptGroupMessage :: GroupSenderKey -> ByteString -> (ByteString, GroupSenderKey)
encryptGroupMessage gsk plaintext =
  let (msgKey, newGsk) = advanceSenderKey gsk
      -- In real version this would be AES-GCM with msgKey
      fakeCt = BS.append msgKey (BS.take 16 plaintext)  -- placeholder
  in (fakeCt, newGsk)

-- TODO (deep ongoing work):
-- - Proper HKDF-based chain advancement for group sender keys
-- - Key rotation when members join/leave
-- - Tying disappearing messages to sender key erasure
-- - Actual encryption using per-sender keys + group key

-- For now this is a solid, honest skeleton with real types.
