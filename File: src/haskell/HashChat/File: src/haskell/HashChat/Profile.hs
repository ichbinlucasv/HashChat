module HashChat.Profile where
import Data.ByteString
import Database.SQLite.Simple
createLocalProfile :: ByteString -> IO ()
createLocalProfile key = do
  conn <- open "hashchat.db"
  execute_ conn "PRAGMA key='hashchat-secure-passphrase';"
  execute_ conn "CREATE TABLE IF NOT EXISTS profiles (pubkey BLOB PRIMARY KEY, display_name TEXT);"
  execute_ conn "CREATE TABLE IF NOT EXISTS queues (queue_id BLOB PRIMARY KEY, profile_pubkey BLOB);"
  execute_ conn "CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, queue_id BLOB, content BLOB);"
  execute_ conn "CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, file_desc BLOB, chunk_size INTEGER);"
  execute conn "INSERT OR IGNORE INTO profiles (pubkey) VALUES (?)" (Only key)
getProfileKey :: IO ByteString
getProfileKey = do
  conn <- open "hashchat.db"
  execute_ conn "PRAGMA key='hashchat-secure-passphrase';"
  [Only k] <- query_ conn "SELECT pubkey FROM profiles LIMIT 1"
  pure k