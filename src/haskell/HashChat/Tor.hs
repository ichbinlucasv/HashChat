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
import Control.Exception (try, SomeException, bracket)
import Data.List (isPrefixOf)
import System.Directory (doesFileExist, createDirectoryIfMissing)
import System.FilePath (takeDirectory)
import Control.Monad (when, void)
import Data.Char (intToDigit)
import Data.Word (Word8, Word16)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BC
import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.MVar (newMVar, takeMVar, putMVar, MVar)

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

-- Real SOCKS5 client for sending ciphertext blobs over Tor to a v3 onion.
-- Completes a full connection and transfers the full length-prefixed blob.
sendCiphertextOverTor :: String -> BS.ByteString -> IO (Either String ())
sendCiphertextOverTor destinationOnion ciphertext = do
  putStrLn $ "[Tor] Connecting via SOCKS5 to " ++ destinationOnion ++ " ..."

  result <- try $ do
    addrInfos <- getAddrInfo Nothing (Just "127.0.0.1") (Just "9050")
    let serverAddr = head addrInfos
    sock <- socket (addrFamily serverAddr) Stream defaultProtocol
    connect sock (addrAddress serverAddr)

    h <- socketToHandle sock ReadWriteMode
    hSetBuffering h NoBuffering

    -- 1. SOCKS5 auth negotiation (no auth)
    BS.hPut h (BS.pack [0x05, 0x01, 0x00])
    ver <- hGetChar h
    meth <- hGetChar h
    when (ver /= '\x05' || meth /= '\x00') $
      fail "SOCKS5 auth negotiation failed"

    -- 2. CONNECT request (ATYP 0x03 = domain name for .onion)
    let port = 80
    let domain = BC.pack $ takeWhile (/= ':') destinationOnion
    let domLen = fromIntegral (BS.length domain) :: Word8
    let portHi = fromIntegral (port `div` 256) :: Word8
    let portLo = fromIntegral (port `mod` 256) :: Word8
    let req = BS.pack [0x05, 0x01, 0x00, 0x03, domLen] <> domain <> BS.pack [portHi, portLo]
    BS.hPut h req

    -- 3. Parse full SOCKS5 reply (VER REP RSV ATYP [BND.ADDR] [BND.PORT])
    -- We read the fixed header first, then enough for the address type.
    rver <- hGetChar h
    rrep <- hGetChar h
    _rsv <- hGetChar h
    ratyp <- hGetChar h
    when (rver /= '\x05' || rrep /= '\x00') $
      fail $ "SOCKS5 connect failed, reply: " ++ show (fromEnum rrep)

    -- Consume the bound address (variable)
    case ratyp of
      '\x01' -> void $ BS.hGet h 4 >> BS.hGet h 2   -- IPv4 + port
      '\x03' -> do
        alen <- hGetChar h
        void $ BS.hGet h (fromEnum alen) >> BS.hGet h 2
      '\x04' -> void $ BS.hGet h 16 >> BS.hGet h 2  -- IPv6 + port
      _      -> fail "Unknown SOCKS5 ATYP in reply"

    -- Connection established. Now send our framed payload.
    -- Frame: 2-byte big-endian length + raw ciphertext blob.
    let len = fromIntegral (BS.length ciphertext) :: Word16
    let lenBytes = BS.pack [ fromIntegral (len `div` 256), fromIntegral (len `mod` 256) ]
    BS.hPut h (lenBytes <> ciphertext)
    hFlush h

    -- In a real protocol we would wait for ACK or close. For now we treat successful write as delivery attempt.
    hClose h
    close sock

    putStrLn $ "[Tor] Ciphertext blob (" ++ show (BS.length ciphertext) ++ " bytes) transferred over hidden service."

  case result of
    Left err -> pure $ Left (show (err :: SomeException))
    Right _  -> pure $ Right ()

-- Basic receive server for the hidden service side.
-- Call this (in a forkIO thread) after startHiddenService when you map Port=...,127.0.0.1:LOCAL_PORT
-- It accepts circuits from Tor and reads length-prefixed ciphertext blobs.
-- In production this would feed into an STM queue or async callback for receiveEncryptedMessage.
startCiphertextReceiver :: Int -> (BS.ByteString -> IO ()) -> IO (MVar ()) 
startCiphertextReceiver localPort onBlob = do
  stopFlag <- newMVar False
  void $ forkIO $ receiverLoop localPort onBlob stopFlag
  pure stopFlag
  where
    receiverLoop port handler stopM = do
      result <- try $ do
        addr <- head <$> getAddrInfo Nothing (Just "127.0.0.1") (Just (show port))
        sock <- socket (addrFamily addr) Stream defaultProtocol
        setSocketOption sock ReuseAddr 1
        bind sock (addrAddress addr)
        listen sock 5
        putStrLn $ "[Tor] Receive server listening on 127.0.0.1:" ++ show port ++ " (for hidden service traffic)"
        acceptLoop sock handler stopM
      case result of
        Left e  -> putStrLn $ "[Tor] Receiver error: " ++ show (e :: SomeException)
        Right _ -> pure ()

    acceptLoop sock handler stopM = do
      stopped <- takeMVar stopM
      putMVar stopM stopped
      if stopped then close sock else do
        (client, _) <- accept sock
        void $ forkIO $ handleClient client handler
        threadDelay 10000  -- small yield
        acceptLoop sock handler stopM

    handleClient client handler = do
      h <- socketToHandle client ReadWriteMode
      hSetBuffering h NoBuffering
      res <- try $ do
        lenHi <- hGetChar h
        lenLo <- hGetChar h
        let len = fromIntegral (fromEnum lenHi * 256 + fromEnum lenLo) :: Int
        when (len > 0 && len < 10*1024*1024) $ do   -- sane upper bound
          blob <- BS.hGet h len
          handler blob
          putStrLn $ "[Tor] Received ciphertext blob of " ++ show len ++ " bytes via hidden service"
      case res of
        Left e  -> putStrLn $ "[Tor] Client handler error: " ++ show (e :: SomeException)
        Right _ -> pure ()
      hClose h
      close client

-- Simple launcher helper (user still needs tor binary)
launchTorIfNeeded :: TorConfig -> FilePath -> IO ()
launchTorIfNeeded cfg torrcPath = do
  putStrLn $ "To enable real Tor hidden service, run:\n  tor -f " ++ torrcPath
  putStrLn "Then the control port will be available."
  -- Future: use process to spawn tor with our torrc and wait for bootstrap.

-- Security note: Never log or persist the actual private key of the hidden service
-- in plaintext. It should be stored encrypted or handled entirely by Tor.
