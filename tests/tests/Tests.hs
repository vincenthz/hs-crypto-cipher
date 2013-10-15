{-# LANGUAGE ViewPatterns #-}
module Main where

import Test.Framework (defaultMain)
import Crypto.Cipher.Types
import Crypto.Cipher.Types.Unsafe
import Crypto.Cipher.Tests
import qualified Data.ByteString as B
import Data.Bits (xor)

-- | the XOR cipher is so awesome that it doesn't need any key or state.
-- Also it's a stream and block cipher at the same time.
data XorCipher = XorCipher

instance Cipher XorCipher where
    cipherInit _    = XorCipher
    cipherName _    = "xor"
    cipherKeySize _ = KeySizeRange 1 32

instance BlockCipher XorCipher where
    blockSize  _   = 16
    ecbEncryptMutable cipher d s len = onBlock cipher xorBS d s len
    ecbDecryptMutable cipher d s len = onBlock cipher xorBS d s len

xorBS b = B.pack $ B.zipWith xor (B.replicate (B.length b) 0xa5) b

instance StreamCipher XorCipher where
    streamCombine _ b = (B.pack $ B.zipWith xor (B.replicate (B.length b) 0x12) b, XorCipher)

tests =
    [ testBlockCipher defaultKATs (undefined :: XorCipher)
    , testStreamCipher defaultStreamKATs (undefined :: XorCipher)
    ]

main = defaultMain tests
