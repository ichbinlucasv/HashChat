module HashChat.Core where
import Control.Concurrent.STM
import Data.ByteString
import Database.SQLite.Simple
import Foreign.Ptr
import Foreign.Marshal.Alloc
import System.IO.Unsafe
data ProfileKey = ProfileKey ByteString
data Queue = Queue ByteString
foreign import ccall unsafe "rust_init_profile" rust_init_profile :: IO (Ptr ())
foreign import ccall unsafe "rust_secure_erase" rust_secure_erase :: Ptr () -> IO ()
foreign import ccall unsafe "rust_hmac_verify" rust_hmac_verify :: Ptr Word8 -> Int -> IO Bool
foreign import ccall unsafe "rust_wipe_files" rust_wipe_files :: IO ()
initProfile :: IO ProfileKey
initProfile = do
  ptr <- rust_init_profile
  pure (ProfileKey (pack [0]))
sendMessage :: Queue -> ByteString -> IO ()
sendMessage = undefined
wipeAll :: IO ()
wipeAll = do
  rust_wipe_files
  rust_secure_erase (unsafePerformIO rust_init_profile)