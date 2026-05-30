module HashChat.Disappearing where

import Data.Time.Clock
import Data.ByteString

data ExpiringMessage = ExpiringMessage
  { content     :: ByteString
  , expiresAt   :: UTCTime
  , burnAfterRead :: Bool
  }

-- Simple check for expiration
isExpired :: ExpiringMessage -> IO Bool
isExpired msg = do
  now <- getCurrentTime
  pure (now >= expiresAt msg)

-- In real version, this will be tied to the ratchet so
-- message keys are deleted after TTL.
