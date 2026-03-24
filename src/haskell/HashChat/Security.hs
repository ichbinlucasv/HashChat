module HashChat.Security where
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Foreign.Storable
extraHMACVerify :: ByteString -> IO Bool
extraHMACVerify msg = do
  ptr <- mallocBytes (length msg)
  pokeArray ptr (unpack msg)
  rust_hmac_verify ptr (length msg)