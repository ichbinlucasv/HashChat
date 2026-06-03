module HashChat.Relay
  ( RelayConfig(..)
  , defaultRelayConfig
  , startRelay
  , stopRelay
  , announceToRelay
  , discoverViaRelay
  , relaySendQueueCt
  , relayReceive
  ) where

-- Self-hostable relay + discovery server skeleton (Phase3, Sec6/7 roadmap).
-- Open protocol for community-operated relays (no central control).
-- Supports queue sync, peer discovery, optional paid hosting (freemium per PAID plan).
-- Transport: can run over Tor HS (mandatory primary) or UDP for local/mesh.
-- Extreme: can disable relay use (Tor direct only).
-- Integrates with Queue.hs (unidirectional SMP queues) + mesh for offline sync.
--
-- MVP: announce presence, simple store-and-forward for framed cts (ratchet protected).
-- Real: rate limits, auth via long-term pub, paid credits for priority/unlimited.
-- See ROADMAP: self-hostable relay + discovery servers (open), Pro = relay hosting service.

import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word32)
import Control.Concurrent (forkIO, threadDelay)
import Control.Monad (forever, when)
import System.IO (hPutStrLn, hGetLine)
import Network.Socket
import qualified Data.Map.Strict as Map
import Data.IORef (newIORef, readIORef, writeIORef, IORef)
import Control.Exception (try, SomeException)

data RelayConfig = RelayConfig
  { relayHost :: String
  , relayPort :: Int
  , relayTorHS :: Bool          -- run as Tor hidden service (recommended)
  , maxQueuePerPeer :: Int
  } deriving (Show, Eq)

defaultRelayConfig :: RelayConfig
defaultRelayConfig = RelayConfig "127.0.0.1" 12346 True 100

-- In real server: maintain per-peer queues of undelivered framed cts (keyed by long-term pub or qid).
type RelayStore = IORef (Map.Map ByteString [ByteString])  -- peerId -> [framed ct]

startRelay :: RelayConfig -> IO ()
startRelay cfg = do
  putStrLn $ "[RELAY] Starting self-hostable relay (Phase3 MVP) on " ++ relayHost cfg ++ ":" ++ show (relayPort cfg)
  putStrLn "  - Announce your relay onion/addr for discovery (open protocol)."
  putStrLn "  - Peers use for queue sync when direct Tor/mesh unavailable."
  putStrLn "  - Paid hosting: unlimited storage, priority, enterprise (see PAID_VERSION_PLAN + ROADMAP Sec7)."
  putStrLn "  - Extreme clients refuse custom relays (Tor primary only)."
  -- Stub server loop (real: use warp or network-simple + Tor control for HS).
  _ <- forkIO $ forever $ do
    threadDelay 1000000
    putStrLn "[RELAY] (stub) listening for announce/queue sync... (run real listener on port or Tor HS)"
  putStrLn "[RELAY] Relay MVP started (integrate with TUI :relay announce, Core for send/receive)."

stopRelay :: IO ()
stopRelay = putStrLn "[RELAY] Stopping relay (stub)."

-- Client side: announce presence (long-term pub + onion for callback).
announceToRelay :: RelayConfig -> ByteString -> String -> IO (Either String ())
announceToRelay cfg pubId myOnion = do
  putStrLn $ "[RELAY] Announcing to relay " ++ relayHost cfg ++ " (pub " ++ show (BS.take 8 pubId) ++ ", onion " ++ myOnion ++ ")"
  -- Real: connect (over Tor SOCKS if relayTorHS), send "ANNOUNCE <pub> <onion> <queues>".
  pure (Right ())

-- Discover peers via relay (returns list of (pub, onion) for mesh/queue bootstrap).
discoverViaRelay :: RelayConfig -> IO [(ByteString, String)]
discoverViaRelay cfg = do
  putStrLn $ "[RELAY] Discovering peers via relay " ++ relayHost cfg ++ " (Phase3 DHT alternative)."
  -- Stub: return demo peers. Real: query relay for public channel subs or 1:1 prekeys.
  pure [(BS.pack (replicate 32 0x99), "demo-relay-peer.onion:12345")]

-- Send a queue ct to relay for store-and-forward to peer (ratchet ct is opaque).
relaySendQueueCt :: RelayConfig -> ByteString -> ByteString -> IO (Either String ())
relaySendQueueCt cfg peerPub ct = do
  putStrLn $ "[RELAY] Queueing " ++ show (BS.length ct) ++ " bytes for " ++ show (BS.take 8 peerPub) ++ " via relay (store-and-forward)."
  -- Real: send framed over relay connection; relay stores until peer polls or push.
  pure (Right ())

-- Poll/receive queued cts from relay (for offline sync).
relayReceive :: RelayConfig -> ByteString -> IO [ByteString]
relayReceive cfg myPub = do
  putStrLn $ "[RELAY] Polling relay for queued cts for " ++ show (BS.take 8 myPub)
  -- Stub: no real cts. Real: return list of framed cts (same wire format as Tor/mesh).
  pure []

-- Integration notes (TUI/Core):
-- - :relay announce  -> calls announceToRelay with long-term pub + onion.
-- - On send if no direct: try relaySendQueueCt (after local mesh/Tor fail).
-- - drainIncoming + sync: also poll relayReceive, feed to process like mesh (unframe + ratchet + QROT).
-- - Self-host: run relay binary (future: separate exe or in hashchat --relay), publish onion.
-- - Monetization: free limited queue, Pro = unlimited + priority + custom domain.
-- See ROADMAP Phase3, THREATMODEL (new surface gated by Extreme + posture).