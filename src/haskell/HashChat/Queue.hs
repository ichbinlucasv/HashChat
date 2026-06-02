module HashChat.Queue where
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)
import System.Random (randomRIO)
import Control.Monad (replicateM)

-- Phase 1 Roadmap: Unidirectional simplex-style queues (SMP-inspired) for metadata elimination.
-- One queue per direction per contact reduces bidirectional correlation risk.
-- Layered on top of existing Tor/I2P framing + ratchets (ratchets stay per-contact).
-- Supports rotation (new queue id periodically), redundancy, decoy traffic.

type QueueId = ByteString  -- 32-byte identifier (can be .onion suffix or random pubhint)

data SMPQueue = SMPQueue
  { qId       :: QueueId
  , qDir      :: Direction
  , qContact  :: String
  , qStep     :: Word32     -- for rotation/decoy
  , qActive   :: Bool
  }

data Direction = Send | Receive deriving (Eq, Show)

-- Create a fresh unidirectional queue (real random, not placeholder).
newSMPQueue :: String -> Direction -> IO SMPQueue
newSMPQueue contact dir = do
  bytes <- replicateM 32 (randomRIO (0,255))
  let qid = BS.pack bytes
  pure $ SMPQueue qid dir contact 0 True

-- Rotate to a new queue id (for forward secrecy of queue endpoint + metadata resistance).
rotateQueue :: SMPQueue -> IO SMPQueue
rotateQueue q = do
  newQ <- newSMPQueue (qContact q) (qDir q)
  pure newQ { qStep = qStep q + 1 }

-- Basic decoy generator stub (Phase 1): produce dummy framed blob of similar size.
-- In full impl: call send with dummy ratchet-derived key or zero-padded, on secondary queues.
generateDecoy :: Int -> IO ByteString
generateDecoy size = do
  bytes <- replicateM size (randomRIO (0,255))
  pure $ BS.pack bytes

-- Per-contact queue set (two directions for true simplex).
data ContactQueues = ContactQueues
  { sendQ    :: SMPQueue
  , recvQ    :: SMPQueue
  , lastRot  :: Word32
  }

newContactQueues :: String -> IO ContactQueues
newContactQueues c = do
  sq <- newSMPQueue c Send
  rq <- newSMPQueue c Receive
  pure $ ContactQueues sq rq 0

-- Should rotate? (every N messages or time; simple counter for Phase 1)
shouldRotate :: ContactQueues -> Word32 -> Bool
shouldRotate cq currentStep = currentStep - lastRot cq > 50  -- rotate after ~50 msgs

-- Integrate note: In TUI/Core, when sending/receiving, check shouldRotate, call rotateQueue,
-- announce new queue id to peer via control message or first frame, switch to new queue for future.
-- Decoys sent on old/secondary queues. This + multi-path (Tor + I2P) gives strong resistance.
-- Extreme disables queue exposure / rotation surface.

-- Legacy placeholder kept for compatibility during transition.
newSMPQueueLegacy :: IO ByteString
newSMPQueueLegacy = pure (BS.pack [0..31])