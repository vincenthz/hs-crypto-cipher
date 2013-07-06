-- |
-- Module      : Crypto.Cipher.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- symmetric cipher basic types
--
{-# LANGUAGE DeriveDataTypeable #-}
module Crypto.Cipher.Types
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , StreamCipher(..)
    -- * Key type and constructor
    , Key
    , makeKey
    -- * Initial Vector type and constructor
    , IV
    , makeIV
    , nullIV
    , ivAdd
    -- * Authentification Tag
    , AuthTag(..)
    ) where

import Data.SecureMem
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Byteable
import Data.Word
import Data.Bits (shiftR, xor)

-- | Symmetric cipher class.
class Cipher cipher where
    -- | Initialize a cipher context from a key
    cipherInit    :: Key cipher -> cipher
    -- | Cipher name
    cipherName    :: cipher -> String
    -- | return the size of the key required for this cipher.
    -- Some cipher accept any size for key
    cipherKeySize :: cipher -> Maybe Int

-- | Symmetric stream cipher class
class Cipher cipher => StreamCipher cipher where
    -- | Encrypt using the stream cipher
    streamEncrypt :: cipher -> ByteString -> (ByteString, cipher)
    -- | Decrypt using the stream cipher
    streamDecrypt :: cipher -> ByteString -> (ByteString, cipher)

-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize    :: cipher -> Int

    -- | Encrypt using the ECB mode.
    --
    -- input need to be a multiple of the blocksize
    ecbEncrypt :: cipher -> ByteString -> ByteString
    -- | Decrypt using the ECB mode.
    --
    -- input need to be a multiple of the blocksize
    ecbDecrypt :: cipher -> ByteString -> ByteString

    -- | encrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcEncrypt :: cipher -> IV cipher -> ByteString -> ByteString
    cbcEncrypt = cbcEncryptGeneric
    -- | decrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcDecrypt :: cipher -> IV cipher -> ByteString -> ByteString
    cbcDecrypt = cbcDecryptGeneric

    -- | combine using the CTR mode.
    --
    -- CTR mode produce a stream of randomized data that is combined
    -- (by XOR operation) with the input stream.
    --
    -- encryption and decryption are the same operation.
    --
    -- input can be of any size
    ctrCombine :: cipher -> IV cipher -> ByteString -> ByteString
    ctrCombine = ctrCombineGeneric

{-
    -- | encrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize
    xtsEncrypt :: cipher -> IV cipher -> ByteString -> ByteString
    xtsEncrypt = xtsEncryptGeneric
    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize
    xtsDecrypt :: cipher -> IV cipher -> ByteString -> ByteString
    xtsDecrypt = xtsDecryptGeneric
-}

-- | a Key parametrized by the cipher
newtype Key c = Key SecureMem deriving (Eq)

instance ToSecureMem (Key c) where
    toSecureMem (Key sm) = sm
instance Byteable (Key c) where
    toBytes (Key sm) = toBytes sm

-- | an IV parametrized by the cipher
newtype IV c = IV ByteString deriving (Eq)
instance Byteable (IV c) where
    toBytes (IV sm) = sm

-- | Authentification Tag for AE cipher mode
newtype AuthTag = AuthTag ByteString

instance Eq AuthTag where
    (AuthTag a) == (AuthTag b) = constEqBytes a b
instance Byteable AuthTag where
    toBytes (AuthTag bs) = bs

-- | Create an IV for a specified block cipher
makeIV :: (Byteable b, BlockCipher c) => b -> Maybe (IV c)
makeIV b = toIV undefined
  where toIV :: BlockCipher c => c -> Maybe (IV c)
        toIV cipher
          | byteableLength b == sz = Just (IV $ toBytes b)
          | otherwise              = Nothing
          where sz = blockSize cipher

-- | Create an IV that is effectively representing the number 0
nullIV :: BlockCipher c => IV c
nullIV = toIV undefined
  where toIV :: BlockCipher c => c -> IV c
        toIV cipher = IV $ B.replicate (blockSize cipher) 0

-- | Increment an IV by a number.
--
-- Assume the IV is in Big Endian format.
ivAdd :: BlockCipher c => IV c -> Int -> IV c
ivAdd (IV b) i = IV $ snd $ B.mapAccumR addCarry i b
  where addCarry :: Int -> Word8 -> (Int, Word8)
        addCarry acc w
            | acc == 0  = (0, w)
            | otherwise = let (hi,lo) = acc `divMod` 256
                              nw      = lo + (fromIntegral w)
                           in (hi + (nw `shiftR` 8), fromIntegral nw)

-- | Create a Key for a specified cipher
makeKey :: (ToSecureMem b, Cipher c) => b -> Maybe (Key c)
makeKey b = toKey undefined (toSecureMem b)
  where toKey :: Cipher c => c -> SecureMem -> Maybe (Key c)
        toKey cipher sm =
            case cipherKeySize cipher of
                Nothing                           -> Just $ Key sm
                Just sz | sz == byteableLength sm -> Just $ Key sm
                        | otherwise               -> Nothing

cbcEncryptGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
cbcEncryptGeneric cipher (IV ivini) input = B.concat $ doEnc ivini $ chunk (blockSize cipher) input
  where doEnc _  []     = []
        doEnc iv (i:is) =
            let o = ecbEncrypt cipher $ bxor iv i
             in o : doEnc o is

cbcDecryptGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
cbcDecryptGeneric cipher (IV ivini) input = B.concat $ doDec ivini $ chunk (blockSize cipher) input
  where doDec _  []     = []
        doDec iv (i:is) =
            let o = bxor iv $ ecbDecrypt cipher i
             in o : doDec i is

ctrCombineGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
ctrCombineGeneric cipher ivini input = B.concat $ doCnt ivini $ chunk (blockSize cipher) input
  where doCnt _  [] = []
        doCnt iv (i:is) =
            let ivEnc = ecbEncrypt cipher (toBytes iv)
             in bxor i ivEnc : doCnt (ivAdd iv 1) is

chunk :: Int -> ByteString -> [ByteString]
chunk sz bs = split bs
  where split b | B.length b <= sz = [b]
                | otherwise        =
                        let (b1, b2) = B.splitAt sz b
                         in b1 : split b2

bxor :: ByteString -> ByteString -> ByteString
bxor src dst = B.pack $ B.zipWith xor src dst
