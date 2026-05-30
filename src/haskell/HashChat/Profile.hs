module HashChat.Profile
  ( ProfileName
  , ContactRatchets
  , ProfileStore
  , createBurnerProfile
  , switchBurnerProfile
  , getCurrentRatchets
  , addContactToProfile
  ) where

import qualified Data.Map.Strict as Map
import Data.Map.Strict (Map)
import Data.ByteString (ByteString)

type ProfileName = String
type ContactRatchets = Map String Word32   -- contact name -> ratchet ID

-- A profile owns its own set of ratchets (complete isolation between burners)
type ProfileStore = Map ProfileName ContactRatchets

-- Create a new burner profile (starts with no contacts)
createBurnerProfile :: ProfileName -> ProfileStore -> ProfileStore
createBurnerProfile name store =
  if Map.member name store
    then store
    else Map.insert name Map.empty store

-- Switch to a burner profile (returns its contact -> ratchet map)
switchBurnerProfile :: ProfileName -> ProfileStore -> Maybe ContactRatchets
switchBurnerProfile name store = Map.lookup name store

-- Get the ratchets for the currently active profile
getCurrentRatchets :: ProfileName -> ProfileStore -> ContactRatchets
getCurrentRatchets name store = Map.findWithDefault Map.empty name store

-- Add a new contact to a specific burner profile (creates new ratchet later)
addContactToProfile :: ProfileName -> String -> ProfileStore -> ProfileStore
addContactToProfile profile contact store =
  Map.adjust (Map.insert contact 0) profile store   -- 0 means "needs ratchet creation"
