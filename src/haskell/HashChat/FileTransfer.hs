module HashChat.FileTransfer where
import Data.ByteString
import Data.Time.Clock
sendFile :: FilePath -> IO ()
sendFile path = pure ()
receiveFile :: ByteString -> FilePath -> IO ()
receiveFile desc target = pure ()