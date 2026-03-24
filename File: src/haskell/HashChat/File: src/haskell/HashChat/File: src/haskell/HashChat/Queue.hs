module HashChat.Queue where
import Data.ByteString
newSMPQueue :: IO ByteString
newSMPQueue = pure (pack [0..31])