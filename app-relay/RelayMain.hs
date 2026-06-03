{-# LANGUAGE OverloadedStrings #-}
module Main where

-- Phase3 High priority: Self-hostable relay server binary.
-- This is the community-operated relay for queue sync, discovery, offline-first (mesh/Starlink failover).
-- Open protocol; paid hosting optional (Pro tier per PAID/ROADMAP Sec7).
-- Run with: cabal run hashchat-relay  (or nix build later).
-- Ties to TUI :relay, Core, queues for ratchet-protected cts (opaque to relay).

import HashChat.Relay
import System.Environment (getArgs)
import Control.Concurrent (threadDelay)
import System.IO (hPutStrLn, stderr)

main :: IO ()
main = do
  args <- getArgs
  let cfg = defaultRelayConfig
  putStrLn "=== HashChat Self-Host Relay Server (Phase3) ==="
  putStrLn "Open protocol for queue sync / discovery / offline resilience."
  putStrLn "All cts are ratchet E2EE (opaque). Extreme clients refuse custom relays."
  putStrLn "Paid hosting: unlimited storage, priority (see PAID_VERSION_PLAN.md + ROADMAP)."
  putStrLn "Usage: hashchat-relay [port]"
  case args of
    [pStr] | Just p <- readMaybe pStr -> do
      let myCfg = cfg { relayPort = p }
      startRelay myCfg
      putStrLn $ "Relay listening on port " ++ show p ++ " (Tor HS recommended for prod)."
      -- Stub loop (real: proper server with rate limits, auth via long-term pub, storage).
      forever $ threadDelay 1000000000
    _ -> do
      startRelay cfg
      putStrLn "Relay MVP started on default port 12346 (use Tor HS for real anon relay)."
      forever $ threadDelay 1000000000
  where
    readMaybe :: String -> Maybe Int
    readMaybe s = case reads s of
      [(x,"")] -> Just x
      _ -> Nothing

    forever act = act >> forever act