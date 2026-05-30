module HashChat.Security where

import qualified Data.ByteString as BS
import Data.Word (Word8)
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Marshal.Array (pokeArray)
import Foreign.Storable

foreign import ccall unsafe "rust_hmac_verify" rust_hmac_verify :: Ptr Word8 -> Int -> IO Bool

extraHMACVerify :: BS.ByteString -> IO Bool
extraHMACVerify msg = do
  ptr <- mallocBytes (BS.length msg)
  pokeArray ptr (BS.unpack msg)
  rust_hmac_verify ptr (BS.length msg)