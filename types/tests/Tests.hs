{-# LANGUAGE ViewPatterns #-}
module Main where

import Test.Framework (defaultMain)
import Crypto.Cipher.Types
import Crypto.Cipher.Tests
import qualified Data.ByteString as B
import Data.Bits (xor)

-- | the XOR cipher is so awesome that it doesn't need any key or state.
data XorCipher = XorCipher

instance Cipher XorCipher where
    cipherInit _    = XorCipher
    cipherKeySize _ = Just 0

instance BlockCipher XorCipher where
    blockSize  _   = 16
    ecbEncrypt _ b = B.pack $ B.zipWith xor (B.replicate (B.length b) 0xa5) b
    ecbDecrypt _ b = B.pack $ B.zipWith xor (B.replicate (B.length b) 0xa5) b

tests = testPropertyModes (undefined :: XorCipher)

main = defaultMain tests
