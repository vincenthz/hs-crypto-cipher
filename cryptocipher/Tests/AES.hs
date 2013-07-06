{-# LANGUAGE CPP #-}
module AES (aesTests) where

-- unfortunately due to a bug in some version of cabal
-- there's no way to have a condition cpp-options in the cabal file
-- for test suite. to run test with AESni, uncomment the following
-- #define HAVE_AESNI

import qualified Crypto.Cipher.AES as AESHs

import Crypto.Classes
import qualified Crypto.Modes as CAPI

import Data.Word
import Data.List
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Control.Monad
import Control.Applicative
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck

newtype IV = IV ByteString
    deriving (Show,Eq)
newtype Key128 = Key128 ByteString
    deriving (Show,Eq)
newtype Message = Message ByteString
    deriving (Show,Eq)

arbitraryBS sz = B.pack <$> replicateM sz (choose (0,255) :: Gen Word8)

instance Arbitrary IV where
    arbitrary = IV <$> arbitraryBS 16

instance Arbitrary Key128 where
    arbitrary = Key128 <$> arbitraryBS 16

instance Arbitrary Message where
    arbitrary = choose (1,102) >>= \sz -> Message <$> arbitraryBS (16*sz)

ecbTests l (Key128 k, Message m) = (== 1) $ length $ nub $ map (\f -> f k m) l
cbcTests l (IV iv, Key128 k, Message m) = (== 1) $ length $ nub $ map (\f -> f k iv m) l

aesTests =
    [ testProperty "ECB Encryption Equivalent" $ ecbTests
        [ (\k m -> AESHs.encryptECB (AESHs.initKey k) m)
        ]
    , testProperty "CBC Encryption Equivalent" $ cbcTests
        [ (\k iv m -> AESHs.encryptCBC (AESHs.initKey k) (AESHs.IV iv) m)
        ]
    , testProperty "ECB Decryption Equivalent" $ ecbTests
        [ (\k m -> AESHs.decryptECB (AESHs.initKey k) m)
        ]
    , testProperty "CBC Decryption Equivalent" $ cbcTests
        [ (\k iv m -> AESHs.decryptCBC (AESHs.initKey k) (AESHs.IV iv) m)
        ]
    ]
