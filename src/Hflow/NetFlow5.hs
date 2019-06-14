{-# language
        BangPatterns
      , DataKinds
      , DerivingStrategies
      , GeneralizedNewtypeDeriving
      , PolyKinds
      , ScopedTypeVariables
      , StandaloneDeriving
      , TypeApplications
      , UnboxedTuples
  #-}

{-# options_ghc -fno-warn-orphans #-}

module Hflow.NetFlow5
  ( --parse

    Packet(..)
  , Header(..)
  , Record(..)
  , Count(..)
  , SysUptime(..)
  , UnixSecs(..)
  , UnixNSecs(..)
  , FlowSequence(..)
  , EngineType(..)
  , EngineId(..)
  , SamplingInterval(..)
  , SrcAddr(..)
  , DstAddr(..)
  , NextHop(..)
  , Input(..)
  , Output(..)
  , DPkts(..)
  , DOctets(..)
  , FirstSysUptime(..)
  , LastSysUptime(..)
  , SrcPort(..)
  , DstPort(..)
  , Pad1(..)
  , TcpFlags(..)
  , Prot(..)
  , Tos(..)
  , SrcAs(..)
  , DstAs(..)
  , SrcMask(..)
  , DstMask(..)
  , Pad2(..)
  ) where

import Prelude hiding (read)

import Data.Bytes.Types (MutableBytes(..))
import Data.Coerce (coerce)
import Data.Primitive
import Data.Primitive.ByteArray.Unaligned
import Control.Monad.Primitive (PrimMonad(..))
import Data.Word
import Net.Types (IPv4(..))
import System.ByteOrder

-------------------------- Helpers --------------------------

{-
parse :: PrimMonad m
  => MutableBytes (PrimState m)
  -> m (Either String Packet)
parse marr@(MutableBytes mbarr _ _) = do
  let !sz = sizeofByteArray mbarr
  if isBadBacketSize sz
    then do
      h <- runParser header marr
      pure undefined
    else pure
      $ Left
      $ "packet size was not 24 + 48m, where m <- [1..]."

isBadPacketSize :: Int -> Bool
isBadPacketSize sz = (sz - headerSize) `mod` recordSize == 0

isBadRecordArray :: Count -> Int -> Bool
isBadRecordArray (Count cnt) szRecs =
  fromIntegral cnt == szRecs `div` recordSize
-}

runParser :: PrimMonad m
  => MutableBytes (PrimState m)
  -> Parser m a
  -> m (MutableBytes (PrimState m), a)
runParser marr (Parser p) = p marr

data Packet = Packet
  !Header
  !(Array Record)

coerceFixed :: forall m a b. Functor m => m (Fixed b a) -> m a
coerceFixed = fmap coerce
{-# inline coerceFixed #-}

read :: forall m a. (PrimMonad m, Bytes a, PrimUnaligned a)
  => Int
  -> MutableBytes (PrimState m)
  -> m a
read ix (MutableBytes marr o l) = coerceFixed
  (readUnalignedByteArray marr (o + ix) :: m (Fixed 'BigEndian a))
{-# inline read #-}

shift :: Int -> MutableBytes s -> MutableBytes s
shift !parsedLen (MutableBytes m o l) = MutableBytes m (o + parsedLen) l

type Reader m a = MutableBytes (PrimState m) -> m a

newtype Parser m a = Parser
  (MutableBytes (PrimState m) -> m (MutableBytes (PrimState m), a))

-------------------------- Header Types --------------------------

data Header = Header
  { headerVersion :: !Version
  , headerCount :: !Count
  , headerSysUptime :: !SysUptime
  , headerUnixSecs :: !UnixSecs
  , headerUnixNSecs :: !UnixNSecs
  , headerFlowSequence :: !FlowSequence
  , headerEngineType :: !EngineType
  , headerEngineId :: !EngineId
  , headerSamplingInterval :: !SamplingInterval
  }

-- | Size of NetFlow Version 5 packet header.
headerSize :: Int
headerSize = 24
{-# inline headerSize #-}

-- | Size of NetFlow Version 5 packet record.
recordSize :: Int
recordSize = 48
{-# inline recordSize #-}

-- | NetFlow export format version number.
data Version
  = Version5
  | VersionOther !Word16
  deriving stock (Eq, Ord)
  deriving stock (Show, Read)

-- | Number of flows exported in this packet (1-30).
newtype Count = Count { getCount :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Current time in milliseconds since the export device booted
newtype SysUptime = SysUptime { getSysUptime :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

newtype UnixSecs = UnixSecs { getUnixSecs :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

newtype UnixNSecs = UnixNSecs { getUnixNSecs :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

newtype FlowSequence = FlowSequence { getFlowSequence :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

newtype EngineType = EngineType { getEngineType :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

newtype EngineId = EngineId { getEngineId :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

newtype SamplingInterval = SamplingInterval { getSamplingInterval :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-------------------------- Header Readers --------------------------

version :: forall m. (PrimMonad m) => Reader m Version
version marr = do
  x <- read @m @Word16 0 marr
  pure $ if x == 5 then Version5 else VersionOther x

count :: forall m. (PrimMonad m) => Reader m Count
count = read @m @Count 2

sysUptime :: forall m. (PrimMonad m) => Reader m SysUptime
sysUptime = read @m @SysUptime 4

unixSecs :: forall m. (PrimMonad m) => Reader m UnixSecs
unixSecs = read @m @UnixSecs 8

unixNSecs :: forall m. (PrimMonad m) => Reader m UnixNSecs
unixNSecs = read @m @UnixNSecs 12

flowSequence :: forall m. (PrimMonad m) => Reader m FlowSequence
flowSequence = read @m @FlowSequence 16

engineType :: forall m. (PrimMonad m) => Reader m EngineType
engineType = read @m @EngineType 20

engineId :: forall m. (PrimMonad m) => Reader m EngineId
engineId = read @m @EngineId 21

samplingInterval :: forall m. (PrimMonad m) => Reader m SamplingInterval
samplingInterval = read @m @SamplingInterval 22

header :: forall m. PrimMonad m => Parser m Header
header = Parser $ \marr -> do
  h <- Header
    <$> version marr
    <*> count marr
    <*> sysUptime marr
    <*> unixSecs marr
    <*> unixNSecs marr
    <*> flowSequence marr
    <*> engineType marr
    <*> engineId marr
    <*> samplingInterval marr
  pure (shift headerSize marr, h)

-------------------------- Record Types --------------------------

deriving newtype instance Bytes IPv4
deriving newtype instance PrimUnaligned IPv4
deriving newtype instance PrimUnaligned a => PrimUnaligned (Fixed b a)

data Record = Record
  { recordSrcAddr :: !SrcAddr
  , recordDstAddr :: !DstAddr
  , recordNextHop :: !NextHop
  , recordInput :: !Input
  , recordOutput :: !Output
  , recordDPkts :: !DPkts
  , recordDOctets :: !DOctets
  , recordFirst :: !FirstSysUptime
  , recordLast :: !LastSysUptime
  , recordSrcPort :: !SrcPort
  , recordDstPort :: !DstPort
  , recordPad1 :: !Pad1
  , recordTcpFlags :: !TcpFlags
  , recordProt :: !Prot
  , recordTos :: !Tos
  , recordSrcAs :: !SrcAs
  , recordDstAs :: !DstAs
  , recordSrcMask :: !SrcMask
  , recordDstMask :: !DstMask
  , recordPad2 :: !Pad2
  }

-- | Source 'IPv4' address.
newtype SrcAddr = SrcAddr { getSrcAddr :: IPv4 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Destination 'IPv4' address.
newtype DstAddr = DstAddr { getDstAddr :: IPv4 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | 'IPv4' address of next hop router.
newtype NextHop = NextHop { getNextHop :: IPv4 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | SNMP index of input interface.
newtype Input = Input { getInput :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | SNMP index of output interface.
newtype Output = Output { getOutput :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Packets in the flow.
newtype DPkts = DPkts { getDPkts :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Total number of Layer 3 bytes in the packets of the flow.
newtype DOctets = DOctets { getDOctets :: Word32 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | 'SysUptime' at the start of the flow.
newtype FirstSysUptime = FirstSysUptime { getFirst :: SysUptime }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | 'SysUptime' at the time the last packet of the flow was received.
newtype LastSysUptime = LastSysUptime { getLast :: SysUptime }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | TCP/UDP source port number or equivalent.
newtype SrcPort = SrcPort { getSrcPort :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | TCP/UDP destination port number or equivalent.
newtype DstPort = DstPort { getDstPort :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Unused (zero) bytes.
newtype Pad1 = Pad1 { getPad1 :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Cumulative OR of TCP flags.
newtype TcpFlags = TcpFlags { getTcpFlags :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | IP protocol type <described here https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>.
newtype Prot = Prot { getProt :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | IP type of service (ToS).
newtype Tos = Tos { getTos :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Autonomous system number of the source, either origin or peer.
newtype SrcAs = SrcAs { getSrcAs :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Autonomous system number of the destination, either origin or peer.
newtype DstAs = DstAs { getDstAs :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Source address prefix mask bits.
newtype SrcMask = SrcMask { getSrcMask :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Destination address prefix mask bits.
newtype DstMask = DstMask { getDstMask :: Word8 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

-- | Unused (zero) bytes.
newtype Pad2 = Pad2 { getPad2 :: Word16 }
  deriving newtype (Eq, Ord)
  deriving newtype (Show, Read)
  deriving newtype (Prim, PrimUnaligned, Bytes)

srcAddr :: forall m. PrimMonad m => Reader m SrcAddr
srcAddr = read @m @SrcAddr 0

dstAddr :: forall m. PrimMonad m => Reader m DstAddr
dstAddr = read @m @DstAddr 4

nextHop :: forall m. PrimMonad m => Reader m NextHop
nextHop = read @m @NextHop 8

input :: forall m. PrimMonad m => Reader m Input
input = read @m @Input 12

output :: forall m. PrimMonad m => Reader m Output
output = read @m @Output 14

dPkts :: forall m. PrimMonad m => Reader m DPkts
dPkts = read @m @DPkts 16

dOctets :: forall m. PrimMonad m => Reader m DOctets
dOctets = read @m @DOctets 20

firstSysUptime :: forall m. PrimMonad m => Reader m FirstSysUptime
firstSysUptime = read @m @FirstSysUptime 24

lastSysUptime :: forall m. PrimMonad m => Reader m LastSysUptime
lastSysUptime = read @m @LastSysUptime 28

srcPort :: forall m. PrimMonad m => Reader m SrcPort
srcPort = read @m @SrcPort 32

dstPort :: forall m. PrimMonad m => Reader m DstPort
dstPort = read @m @DstPort 34

pad1 :: forall m. PrimMonad m => Reader m Pad1
pad1 = read @m @Pad1 36

tcpFlags :: forall m. PrimMonad m => Reader m TcpFlags
tcpFlags = read @m @TcpFlags 37

prot :: forall m. PrimMonad m => Reader m Prot
prot = read @m @Prot 38

tos :: forall m. PrimMonad m => Reader m Tos
tos = read @m @Tos 39

srcAs :: forall m. PrimMonad m => Reader m SrcAs
srcAs = read @m @SrcAs 40

dstAs :: forall m. PrimMonad m => Reader m DstAs
dstAs = read @m @DstAs 42

srcMask :: forall m. PrimMonad m => Reader m SrcMask
srcMask = read @m @SrcMask 44

dstMask :: forall m. PrimMonad m => Reader m DstMask
dstMask = read @m @DstMask 45

pad2 :: forall m. PrimMonad m => Reader m Pad2
pad2 = read @m @Pad2 46

record :: forall m. PrimMonad m => Parser m Record
record = Parser $ \marr -> do
  r <- Record
    <$> srcAddr marr
    <*> dstAddr marr
    <*> nextHop marr
    <*> input marr
    <*> output marr
    <*> dPkts marr
    <*> dOctets marr
    <*> firstSysUptime marr
    <*> lastSysUptime marr
    <*> srcPort marr
    <*> dstPort marr
    <*> pad1 marr
    <*> tcpFlags marr
    <*> prot marr
    <*> tos marr
    <*> srcAs marr
    <*> dstAs marr
    <*> srcMask marr
    <*> dstMask marr
    <*> pad2 marr
  pure (shift recordSize marr, r)

