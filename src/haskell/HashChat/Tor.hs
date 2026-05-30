module HashChat.Tor
  ( OnionAddress(..)
  , startHiddenService
  , stopHiddenService
  , getOnionAddress
  , TorConfig(..)
  , defaultTorConfig
  , launchTorIfNeeded
  ) where

import Network.Socket
import System.IO
import Control.Exception (bracket, try, SomeException)
import Data.List (isPrefixOf)
import System.Directory (doesFileExist, createDirectoryIfMissing)
import System.FilePath (takeDirectory)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

data OnionAddress = OnionAddress String deriving (Show, Eq)

data TorConfig = TorConfig
  { controlHost :: String
  , controlPort :: Int
  , torDataDir  :: FilePath
  , hiddenServiceDir :: FilePath
  }

defaultTorConfig :: TorConfig
defaultTorConfig = TorConfig
  { controlHost = "127.0.0.1"
  , controlPort = 9051
  , torDataDir  = "tor/data"
  , hiddenServiceDir = "tor/hidden_service"
  }

-- Connect to Tor control port and send a command
sendTorCommand :: TorConfig -> String -> IO String
sendTorCommand cfg cmd = do
  addrInfos <- getAddrInfo Nothing (Just $ controlHost cfg) (Just $ show $ controlPort cfg)
  let serverAddr = head addrInfos
  sock <- socket (addrFamily serverAddr) Stream defaultProtocol
  connect sock (addrAddress serverAddr)
  h <- socketToHandle sock ReadWriteMode
  hSetBuffering h LineBuffering

  -- Authenticate (cookie or null for dev)
  hPutStrLn h "AUTHENTICATE"
  _ <- hGetLine h

  hPutStrLn h cmd
  response <- hGetContents h  -- read until close or multi-line

  hClose h
  close sock
  pure response

startHiddenService :: TorConfig -> IO OnionAddress
startHiddenService cfg = do
  createDirectoryIfMissing True (hiddenServiceDir cfg)
  createDirectoryIfMissing True (takeDirectory $ torDataDir cfg)

  -- Check for persisted hostname
  let hostnameFile = hiddenServiceDir cfg ++ "/hostname"
  exists <- doesFileExist hostnameFile
  if exists
    then do
      onion <- readFile hostnameFile
      pure $ OnionAddress (head $ lines onion)
    else do
      -- Add v3 hidden service via control port
      let cmd = "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:8080"
      resp <- sendTorCommand cfg cmd
      let onion = extractOnion resp
      -- Persist
      writeFile hostnameFile onion
      pure $ OnionAddress onion

extractOnion :: String -> String
extractOnion resp =
  case filter (isPrefixOf "250-ServiceID=") (lines resp) of
    (line:_) -> drop 13 line ++ ".onion"
    _        -> "failed-to-get-onion.onion"

stopHiddenService :: TorConfig -> OnionAddress -> IO ()
stopHiddenService cfg (OnionAddress onion) = do
  -- In real impl: DEL_ONION <serviceid>
  let cmd = "DEL_ONION " ++ takeWhile (/= '.') onion
  _ <- sendTorCommand cfg cmd
  pure ()

getOnionAddress :: OnionAddress -> String
getOnionAddress (OnionAddress a) = a

-- Simple launcher helper (user still needs tor binary)
launchTorIfNeeded :: TorConfig -> FilePath -> IO ()
launchTorIfNeeded cfg torrcPath = do
  putStrLn $ "To enable real Tor hidden service, run:\n  tor -f " ++ torrcPath
  putStrLn "Then the control port will be available."
  -- Future: use process to spawn tor with our torrc and wait for bootstrap.
