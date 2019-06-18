{-# language
        BangPatterns
      , DataKinds
      , DerivingStrategies
      , FlexibleInstances
      , GeneralizedNewtypeDeriving
      , MultiParamTypeClasses
      , NamedFieldPuns
      , PolyKinds
      , RankNTypes
      , ScopedTypeVariables
      , StandaloneDeriving
      , TypeApplications
      , UnboxedTuples
      , ViewPatterns
  #-}

{-# options_ghc -fno-warn-orphans #-}

module Hflow.NetFlow5
  ( packet
  , runParser
  , Parser(..)
  , get

  , Packet(..)
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

import Control.Monad.ST
import Control.Monad.Except
import Data.Bytes.Types (MutableBytes(..))
import Data.Coerce (coerce)
import Data.Primitive
import Data.Primitive.ByteArray.Unaligned
import Data.Word
import Net.Types (IPv4(..))
import System.ByteOrder

import qualified GHC.Exts as Exts

-------------------------- Helpers --------------------------

data ParseError = ParseError
{-
  = InitialOffsetNotZero -- ^ The input buffer did not have an initial
                         --   offset of zero.
  | InitialLengthNotCorrect -- ^ The input buffer's true length was
                            --   modified to not be its original length.
--  | PacketSizeNot2448m -- ^ packet size was not congruent to (m - 24) mod 48
  | CountIsIncorrect -- ^ The number of flows that the header prescribed
                     --   was incorrect.
  | PacketButNoFlows -- ^ A NetFlow v5 'Packet' was received, but there
                     --   were no flows.
  | SmallerThanHeader
-}

packet :: Parser Packet
packet = do
  h@Header{headerCount} <- header
  r <- records headerCount
  pure (Packet h r)

-- | Returns leftovers and potentially a value.
runParser :: ()
  => MutableBytes s
  -> Parser a
  -> ST s (MutableBytes s, Either ParseError a)
runParser marr (Parser p) = p marr

data Packet = Packet
  !Header
  !(Array Record)

read :: forall a s. (Bytes a, PrimUnaligned a)
  => Int
  -> MutableBytes s
  -> ST s a
read ix (MutableBytes marr o _) = coerce
  (readUnalignedByteArray marr (o + ix) :: ST s (Fixed 'BigEndian a))
{-# inline read #-}

shift :: Int -> MutableBytes s -> MutableBytes s
shift !parsedLen (MutableBytes m o l) = MutableBytes m (o + parsedLen) (l - parsedLen)

-- | A 'Reader' is assumed to not be able to fail.
--   This is an internal invariant.
type Reader s a = MutableBytes s -> ST s a

newtype Parser a = Parser
  (forall s. MutableBytes s -> ST s (MutableBytes s, Either ParseError a))
-- | Get the offset and length information out of the parser.
get :: Parser (Int, Int)
get = Parser $ \marr@(MutableBytes _ off len) -> do
  pure (marr, Right (off, len))

instance Functor Parser where
  fmap f (Parser p) = Parser $ \s -> do
    (s', e) <- p s
    pure (s', fmap f e)

instance Applicative Parser where
  pure x = Parser $ \s -> pure (s, Right x)
  (<*>) = ap

instance Monad Parser where
  --(>>=) :: Parser a -> (a -> Parser b) -> Parser b
  (Parser p) >>= k = Parser $ \s -> do
    (s', e) <- p s
    case e of
      Left err -> pure (s', Left err)
      Right a -> case k a of Parser p' -> p' s'

instance MonadError ParseError Parser where
  throwError e = Parser $ \m -> pure (m, Left e)
  catchError (Parser p) f = Parser $ \s -> do
    (s', e) <- p s
    case e of
      Left err -> case f err of (Parser p') -> p' s'
      Right _ -> pure (s', e)

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

version :: Reader s Version
version marr = do
  x <- read @Word16 0 marr
  pure $ if x == 5 then Version5 else VersionOther x

count :: forall s. Reader s Count
count = read @Count 2

sysUptime :: forall s. Reader s SysUptime
sysUptime = read @SysUptime 4

unixSecs :: forall s. Reader s UnixSecs
unixSecs = read @UnixSecs 8

unixNSecs :: forall s. Reader s UnixNSecs
unixNSecs = read @UnixNSecs 12

flowSequence :: forall s. Reader s FlowSequence
flowSequence = read @FlowSequence 16

engineType :: forall s. Reader s EngineType
engineType = read @EngineType 20

engineId :: forall s. Reader s EngineId
engineId = read @EngineId 21

samplingInterval :: forall s. Reader s SamplingInterval
samplingInterval = read @SamplingInterval 22

-- | Run a parser, shifting the underlying buffer by a given
--   ammount.
parseWithShift :: Int -> (forall s. Reader s a) -> Parser a
parseWithShift s reader = Parser $ \marr -> do
  p <- reader marr
  pure (shift s marr, Right p)

header :: Parser Header
header = do
  (_, len) <- get
  if len < headerSize
    then throwError ParseError
    else parseWithShift headerSize headerReader

headerReader :: Reader s Header
headerReader marr = Header
  <$> version marr
  <*> count marr
  <*> sysUptime marr
  <*> unixSecs marr
  <*> unixNSecs marr
  <*> flowSequence marr
  <*> engineType marr
  <*> engineId marr
  <*> samplingInterval marr

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

srcAddr :: forall s. Reader s SrcAddr
srcAddr = read @SrcAddr 0

dstAddr :: forall s. Reader s DstAddr
dstAddr = read @DstAddr 4

nextHop :: forall s. Reader s NextHop
nextHop = read @NextHop 8

input :: forall s. Reader s Input
input = read @Input 12

output :: forall s. Reader s Output
output = read @Output 14

dPkts :: forall s. Reader s DPkts
dPkts = read @DPkts 16

dOctets :: forall s. Reader s DOctets
dOctets = read @DOctets 20

firstSysUptime :: forall s. Reader s FirstSysUptime
firstSysUptime = read @FirstSysUptime 24

lastSysUptime :: forall s. Reader s LastSysUptime
lastSysUptime = read @LastSysUptime 28

srcPort :: forall s. Reader s SrcPort
srcPort = read @SrcPort 32

dstPort :: forall s. Reader s DstPort
dstPort = read @DstPort 34

pad1 :: forall s. Reader s Pad1
pad1 = read @Pad1 36

tcpFlags :: forall s. Reader s TcpFlags
tcpFlags = read @TcpFlags 37

prot :: forall s. Reader s Prot
prot = read @Prot 38

tos :: forall s. Reader s Tos
tos = read @Tos 39

srcAs :: forall s. Reader s SrcAs
srcAs = read @SrcAs 40

dstAs :: forall s. Reader s DstAs
dstAs = read @DstAs 42

srcMask :: forall s. Reader s SrcMask
srcMask = read @SrcMask 44

dstMask :: forall s. Reader s DstMask
dstMask = read @DstMask 45

pad2 :: forall s. Reader s Pad2
pad2 = read @Pad2 46

record :: Parser Record
record = do
  (_, len) <- get
  if len < recordSize
    then throwError ParseError
    else parseWithShift recordSize recordReader

records :: Count -> Parser (Array Record)
records (fromIntegral . getCount -> sz)
  = fmap Exts.fromList $ replicateM sz record

recordReader :: Reader s Record
recordReader marr = Record
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
