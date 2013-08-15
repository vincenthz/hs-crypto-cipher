-- |
-- Module      : Crypto.Cipher.TripleDES
-- License     : BSD-style
-- Stability   : experimental
-- Portability : ???

module Crypto.Cipher.TripleDES
    ( DES_EEE3
    , DES_EDE3
    , DES_EEE2
    , DES_EDE2
    ) where

import Data.Word
import Data.Byteable
import qualified Data.ByteString as B

import Crypto.Cipher.Types
import Crypto.Cipher.DES.Primitive
import Crypto.Cipher.DES.Serialization

-- | 3DES with 3 different keys used all in the same direction
data DES_EEE3 = DES_EEE3 Word64 Word64 Word64
    deriving (Eq)

-- | 3DES with 3 different keys used in alternative direction
data DES_EDE3 = DES_EDE3 Word64 Word64 Word64 
    deriving (Eq)

-- | 3DES where the first and third keys are equal, used in the same direction
data DES_EEE2 = DES_EEE2 Word64 Word64 -- key1 and key3 are equal
    deriving (Eq)

-- | 3DES where the first and third keys are equal, used in alternative direction
data DES_EDE2 = DES_EDE2 Word64 Word64 -- key1 and key3 are equal
    deriving (Eq)

instance Cipher DES_EEE3 where
    cipherName    _ = "3DES_EEE"
    cipherKeySize _ = Just 24
    cipherInit k    = init3DES DES_EEE3 k

instance Cipher DES_EDE3 where
    cipherName    _ = "3DES_EDE"
    cipherKeySize _ = Just 24
    cipherInit k    = init3DES DES_EDE3 k

instance Cipher DES_EDE2 where
    cipherName    _ = "2DES_EDE"
    cipherKeySize _ = Just 16
    cipherInit k    = init2DES DES_EDE2 k

instance Cipher DES_EEE2 where
    cipherName    _ = "2DES_EEE"
    cipherKeySize _ = Just 16
    cipherInit k    = init2DES DES_EEE2 k

instance BlockCipher DES_EEE3 where
    blockSize _ = 8
    ecbEncrypt (DES_EEE3 k1 k2 k3) = unblockify . map (encrypt k1 . encrypt k2 . encrypt k3) . blockify
    ecbDecrypt (DES_EEE3 k1 k2 k3) = unblockify . map (decrypt k3 . decrypt k2 . decrypt k1) . blockify

instance BlockCipher DES_EDE3 where
    blockSize _ = 8
    ecbEncrypt (DES_EDE3 k1 k2 k3) = unblockify . map (encrypt k1 . decrypt k2 . encrypt k3) . blockify
    ecbDecrypt (DES_EDE3 k1 k2 k3) = unblockify . map (decrypt k3 . encrypt k2 . decrypt k1) . blockify

instance BlockCipher DES_EEE2 where
    blockSize _ = 8
    ecbEncrypt (DES_EEE2 k1 k2) = unblockify . map (encrypt k1 . encrypt k2 . encrypt k1) . blockify
    ecbDecrypt (DES_EEE2 k1 k2) = unblockify . map (decrypt k1 . decrypt k2 . decrypt k1) . blockify

instance BlockCipher DES_EDE2 where
    blockSize _ = 8
    ecbEncrypt (DES_EDE2 k1 k2) = unblockify . map (encrypt k1 . decrypt k2 . encrypt k1) . blockify
    ecbDecrypt (DES_EDE2 k1 k2) = unblockify . map (decrypt k1 . encrypt k2 . decrypt k1) . blockify

init3DES :: Byteable b => (Word64 -> Word64 -> Word64 -> a) -> b -> a
init3DES constr k
    | len == 24 = constr k1 k2 k3
    | otherwise = error "3DES: not a valid key length (valid=24)"
  where len = byteableLength k
        (Block k1, Block k2, Block k3) =
            let (b1, k') = B.splitAt 8 (toBytes k)
                (b2, b3) = B.splitAt 8 k'
             in (toW64 b1, toW64 b2, toW64 b3)

init2DES :: Byteable b => (Word64 -> Word64 -> a) -> b -> a
init2DES constr k
    | len == 16 = constr k1 k2
    | otherwise = error "2DES: not a valid key length (valid=16)"
  where len = byteableLength k
        (Block k1, Block k2) =
            let (b1, b2) = B.splitAt 8 (toBytes k)
             in (toW64 b1, toW64 b2)
