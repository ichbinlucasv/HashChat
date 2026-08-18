module HashChat.Security where

import qualified Data.ByteString as BS
import Data.Word (Word8)
import Foreign.Marshal.Alloc (allocaBytes, mallocBytes, free)
import Foreign.Marshal.Array (pokeArray, peekArray)
import Foreign.Ptr
import Foreign.Storable ()

foreign import ccall unsafe "rust_hmac_sign"
  rust_hmac_sign :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> IO Bool

foreign import ccall unsafe "rust_hmac_verify"
  rust_hmac_verify :: Ptr Word8 -> Int -> Ptr Word8 -> Int -> Ptr Word8 -> Int -> IO Bool

-- HMAC-SHA256(key, msg) -> 32-byte tag. False on FFI failure.
extraHMACSign :: BS.ByteString -> BS.ByteString -> IO (Maybe BS.ByteString)
extraHMACSign key msg = do
  keyPtr <- mallocBytes (BS.length key)
  msgPtr <- mallocBytes (max 1 (BS.length msg))
  pokeArray keyPtr (BS.unpack key)
  pokeArray msgPtr (BS.unpack msg)
  tag <- allocaBytes 32 $ \outPtr -> do
    ok <- rust_hmac_sign keyPtr (BS.length key) msgPtr (BS.length msg) outPtr
    if ok then Just . BS.pack <$> peekArray 32 outPtr else pure Nothing
  free keyPtr
  free msgPtr
  pure tag

-- Constant-time verify of HMAC-SHA256(key, msg) against tag.
extraHMACVerify :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO Bool
extraHMACVerify key msg tag = do
  keyPtr <- mallocBytes (BS.length key)
  msgPtr <- mallocBytes (max 1 (BS.length msg))
  tagPtr <- mallocBytes (BS.length tag)
  pokeArray keyPtr (BS.unpack key)
  pokeArray msgPtr (BS.unpack msg)
  pokeArray tagPtr (BS.unpack tag)
  ok <- rust_hmac_verify keyPtr (BS.length key) msgPtr (BS.length msg) tagPtr (BS.length tag)
  free keyPtr
  free msgPtr
  free tagPtr
  pure ok