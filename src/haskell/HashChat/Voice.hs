module HashChat.Voice where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)

-- Voice messages use the same ratchet keys as text (per-message keys from Double Ratchet).
-- Streaming: we chunk the audio, encrypt each chunk with successive ratchet keys (or derived subkeys).
recordVoiceMessage :: IO ByteString
recordVoiceMessage = pure (BS.pack [0x56, 0x4F, 0x49, 0x43, 0x45])  -- "VOICE" marker (real recording would use Android mic + JNI)

-- Encrypt a voice chunk using a ratchet-derived key (same path as normal messages)
encryptVoiceChunk :: Word32 -> ByteString -> ByteString -> IO ByteString
encryptVoiceChunk _ratchetId _key chunk = pure chunk  -- real version calls rust_encrypt_with_key + framing

-- In the real system voice is streamed chunk-by-chunk over the ratchet with forward secrecy per chunk.