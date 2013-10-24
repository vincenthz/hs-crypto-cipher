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
    ecbEncrypt _ s = xorBS s
    ecbDecrypt _ s = xorBS s

instance BlockCipherIO XorCipher where
    ecbEncryptMutable cipher d s len = onBlock cipher xorBS d s len
    ecbDecryptMutable cipher d s len = onBlock cipher xorBS d s len

instance StreamCipher XorCipher where
    streamCombine _ b = (B.pack $ B.zipWith xor (B.replicate (B.length b) 0x12) b, XorCipher)

xorBS :: B.ByteString -> B.ByteString
xorBS b = B.pack $ B.zipWith xor (B.replicate (B.length b) 0xa5) b

tests =
    [ testBlockCipher defaultKATs cipher
    , testBlockCipherIO defaultKATs cipher
    , testStreamCipher defaultStreamKATs cipher
    ]
  where cipher :: XorCipher
        cipher = undefined

main = defaultMain tests
