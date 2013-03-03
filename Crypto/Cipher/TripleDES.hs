-- |
-- Module      : Crypto.Cipher.TripleDES
-- License     : BSD-style
-- Stability   : experimental
-- Portability : ???

module Crypto.Cipher.TripleDES
    ( DesEee3Key(..)
    , DesEde3Key(..)
    , DesEee2Key(..)
    , DesEde2Key(..)
    ) where

import Control.Applicative ((<$>))
import Control.Monad (replicateM)
import Data.Serialize (Get, Put, Serialize(..), runGet, runPut,
                       getWord8, putWord64le)
import Data.Word (Word64)
import Foreign (castPtr, peek)
import System.IO.Unsafe (unsafePerformIO)
import Data.ByteString.Unsafe (unsafeUseAsCString)
import qualified Data.ByteString as B
import qualified Data.Bits as Bits

import Crypto.Classes (BlockCipher(..))
import Codec.Utils (Octet, fromOctets)
import qualified Codec.Encryption.DES as DES

data DesEee3Key = DesEee3Key Word64 Word64 Word64 -- three different keys
    deriving (Show, Eq)

data DesEde3Key = DesEde3Key Word64 Word64 Word64 -- three different keys
    deriving (Show, Eq)

data DesEee2Key = DesEee2Key Word64 Word64 -- key1 and key3 are equal
    deriving (Show, Eq)

data DesEde2Key = DesEde2Key Word64 Word64 -- key1 and key3 are equal
    deriving (Show, Eq)

triplePut :: Word64 -> Word64 -> Word64 -> Put
triplePut f s t = putWord64le f >> putWord64le s >> putWord64le t

doublePut :: Word64 -> Word64 -> Put
doublePut f s = putWord64le f >> putWord64le s

getFixedParityOctet :: Get Octet
getFixedParityOctet = do
    sourceWord <- getWord8
    return $ case odd(Bits.popCount sourceWord) of
        True  -> Bits.clearBit sourceWord lsb
        False -> sourceWord
  where
    lsb = 0

getFixedParityWord64le :: Get Word64
getFixedParityWord64le =
    fromOctets octetsNumber <$> replicateM octetsNumber getFixedParityOctet
  where
    octetsNumber = 8 :: Int

tripleGet :: Get (Word64, Word64, Word64)
tripleGet = do
    f <- getFixedParityWord64le
    s <- getFixedParityWord64le
    t <- getFixedParityWord64le
    return (f, s, t)

doubleGet :: Get (Word64, Word64)
doubleGet = do
    f <- getFixedParityWord64le
    s <- getFixedParityWord64le
    return (f, s)

uncurry3 :: (a -> b -> c -> d) -> ((a, b, c) -> d)
uncurry3 f (x, y, z) = f x y z

instance Serialize DesEee3Key where
    put (DesEee3Key f s t) = triplePut f s t
    get = uncurry3 DesEee3Key <$> tripleGet

instance Serialize DesEde3Key where
    put (DesEde3Key f s t) = triplePut f s t
    get = uncurry3 DesEde3Key <$> tripleGet

instance Serialize DesEee2Key where
    put (DesEee2Key f s) = doublePut f s
    get = uncurry DesEee2Key <$> doubleGet

instance Serialize DesEde2Key where
    put (DesEde2Key f s) = doublePut f s
    get = uncurry DesEde2Key <$> doubleGet

-- TODO: some docs
bsToWord64 :: B.ByteString -> Word64
bsToWord64 bs = unsafePerformIO $ unsafeUseAsCString bs $ peek . castPtr

word64ToBs :: Word64 -> B.ByteString
word64ToBs = runPut . putWord64le

instance BlockCipher DesEee3Key where
    blockSize = 64
    encryptBlock (DesEee3Key f s t) = word64ToBs .
        DES.encrypt f . DES.encrypt s . DES.encrypt t . bsToWord64
    decryptBlock (DesEee3Key f s t) = word64ToBs .
        DES.decrypt t . DES.decrypt s . DES.decrypt f . bsToWord64
    buildKey = either (const Nothing) Just . runGet get
    keyLength = 64 * 3

instance BlockCipher DesEde3Key where
    blockSize = 64
    encryptBlock (DesEde3Key f s t) = word64ToBs .
        DES.encrypt f . DES.decrypt s . DES.encrypt t . bsToWord64
    decryptBlock (DesEde3Key f s t) = word64ToBs .
        DES.decrypt t . DES.encrypt s . DES.decrypt f . bsToWord64
    buildKey = either (const Nothing) Just . runGet get
    keyLength = 64 * 3

instance BlockCipher DesEee2Key where
    blockSize = 64
    encryptBlock (DesEee2Key f s) = word64ToBs .
        DES.encrypt f . DES.encrypt s . DES.encrypt f . bsToWord64
    decryptBlock (DesEee2Key f s) = word64ToBs .
        DES.decrypt f . DES.decrypt s . DES.decrypt f . bsToWord64
    buildKey = either (const Nothing) Just . runGet get
    keyLength = 64 * 2

instance BlockCipher DesEde2Key where
    blockSize = 64
    encryptBlock (DesEde2Key f s) = word64ToBs .
        DES.encrypt f . DES.decrypt s . DES.encrypt f . bsToWord64
    decryptBlock (DesEde2Key f s) = word64ToBs .
        DES.decrypt f . DES.encrypt s . DES.decrypt f . bsToWord64
    buildKey = either (const Nothing) Just . runGet get
    keyLength = 64 * 2
