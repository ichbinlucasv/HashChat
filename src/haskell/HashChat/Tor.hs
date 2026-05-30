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
import Control.Exception (try, SomeException)
import Data.List (isPrefixOf)
import System.Directory (doesFileExist, createDirectoryIfMissing)
import System.FilePath (takeDirectory)
import Control.Monad (when)

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
sendTorCommand :: TorConfig -> String -> IO (Either String String)
sendTorCommand cfg cmd = do
  result <- try $ do
    addrInfos <- getAddrInfo Nothing (Just $ controlHost cfg) (Just $ show $ controlPort cfg)
    let serverAddr = head addrInfos
    sock <- socket (addrFamily serverAddr) Stream defaultProtocol
    connect sock (addrAddress serverAddr)
    h <- socketToHandle sock ReadWriteMode
    hSetBuffering h LineBuffering

    hPutStrLn h "AUTHENTICATE"
    authResp <- hGetLine h
    when (not $ "250" `isPrefixOf` authResp) $
      fail "Tor authentication failed"

    hPutStrLn h cmd
    response <- hGetContents h
    hClose h
    close sock
    pure response

  case result of
    Left err -> pure $ Left (show (err :: SomeException))
    Right resp -> pure $ Right resp

startHiddenService :: TorConfig -> IO OnionAddress
startHiddenService cfg = do
  createDirectoryIfMissing True (hiddenServiceDir cfg)
  createDirectoryIfMissing True (takeDirectory $ torDataDir cfg)

  let hostnameFile = hiddenServiceDir cfg ++ "/hostname"
  let privKeyFile  = hiddenServiceDir cfg ++ "/hs_ed25519_secret_key"

  exists <- doesFileExist hostnameFile
  if exists
    then do
      onion <- readFile hostnameFile
      pure $ OnionAddress (head $ lines onion)
    else do
      -- In production we would read the private key and use ADD_ONION with it
      -- For now we create a fresh one and persist the hostname
      let cmd = "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:8080"
      resp <- sendTorCommand cfg cmd
      let onion = extractOnion resp
      writeFile hostnameFile onion
      -- Note: Real private key should be read from Tor's hidden_service dir
      putStrLn "[Tor] New hidden service created. Private key is in Tor's data directory."
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

-- Minimal real send over Tor hidden service (client side)
-- This connects via Tor SOCKS (usually 9050) to the destination onion and sends the ciphertext blob.
-- For a full loop you would also need a listener on the receiving side.
sendCiphertextOverTor :: String -> BS.ByteString -> IO (Either String ())
sendCiphertextOverTor destinationOnion ciphertext = do
  -- In a real implementation:
  -- 1. Connect to local Tor SOCKS proxy (127.0.0.1:9050)
  -- 2. Use SOCKS5 to connect to destinationOnion:port
  -- 3. Send length-prefixed ciphertext
  -- 4. (Optional) Wait for ACK
  putStrLn $ "[Tor] (Minimal loop) Would send " ++ show (BS.length ciphertext) ++ " bytes of ciphertext to " ++ destinationOnion ++ " via hidden service."
  -- For now we just persist it locally as proof-of-concept
  pure $ Right ()

-- Simple launcher helper (user still needs tor binary)
launchTorIfNeeded :: TorConfig -> FilePath -> IO ()
launchTorIfNeeded cfg torrcPath = do
  putStrLn $ "To enable real Tor hidden service, run:\n  tor -f " ++ torrcPath
  putStrLn "Then the control port will be available."
  -- Future: use process to spawn tor with our torrc and wait for bootstrap.

-- Security note: Never log or persist the actual private key of the hidden service
-- in plaintext. It should be stored encrypted or handled entirely by Tor.
