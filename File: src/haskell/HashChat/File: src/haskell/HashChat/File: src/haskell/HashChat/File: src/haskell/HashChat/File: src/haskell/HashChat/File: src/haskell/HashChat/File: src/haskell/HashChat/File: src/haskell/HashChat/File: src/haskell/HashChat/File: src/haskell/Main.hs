module Main where
import HashChat.Core
import HashChat.Profile
main :: IO ()
main = do
  _ <- initProfile
  putStrLn "HashChat started"