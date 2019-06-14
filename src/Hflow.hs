{-# language
        BangPatterns
      , DerivingStrategies
      , GeneralisedNewtypeDeriving
  #-}

module Hflow
  (
  ) where

import Data.Bits
import Data.Int
import Data.Word

data Packet = Packet {}

--data Header = Header
--  {
--  }

-- | NetFlow Version.
data Version
  = Version5 -- ^ NetFlow Version 5
  | Version9 -- ^ NetFlow Version 9
  | VersionUnsupported -- ^ NetFlow Version that is none of {5,9}
  deriving stock (Eq, Ord)
  deriving stock (Show, Read)

-- | Number of FlowSet records (both template and data) contained
--   within this packet.
newtype Count = Count { getCount :: Int }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)

-- | Time in milliseconds since this device was first booted.
newtype SystemUptime = SystemUptime { getSystemUptime :: Int64 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)

-- | Seconds since 0000 Coordinated Universal Time (UTC) 1970.
newtype UnixSeconds = UnixSeconds { getUnixSeconds :: Int64 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)

-- | Incremental sequence counter of all export packets sent by this
--   export device; this value is cumulative, and it can be used to
--   identify whether any export packets have been missed.
--
--   /Note/: This is a change from the NetFlow Version 5 and Version 8
--   headers, where this number represented "total flows".
newtype SequenceNumber = SequenceNumber { getSequenceNumber :: Int64 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)

newtype SourceId = SourceId { getSourceId :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)

