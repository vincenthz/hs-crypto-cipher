-- |
-- Module      : Crypto.Cipher.Types.Block
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- block cipher basic types
--
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Types.Block
    ( BlockCipher(..)
    , IV
    , makeIV
    , nullIV
    , ivAdd
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Byteable
import Data.Word
import Data.Bits (shiftR, Bits)
import Crypto.Cipher.Types.Base

-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize    :: cipher -> Int

    -- | Encrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbEncrypt :: cipher -> ByteString -> ByteString

    -- | Decrypt blocks
    --
    -- the input string need to be multiple of the block size
    ecbDecrypt :: cipher -> ByteString -> ByteString

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
