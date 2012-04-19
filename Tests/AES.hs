module AES (aesTests) where

import qualified Crypto.Cipher.AES.Haskell as AESHs
import qualified Crypto.Cipher.AES.X86NI as AESNI

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

ebcTests l (Key128 k, Message m) = (== 1) $ length $ nub $ map (\f -> f k m) l
cbcTests l (IV iv, Key128 k, Message m) = (== 1) $ length $ nub $ map (\f -> f k iv m) l

unright (Right r) = r
unright (Left e) = error e

aesTests =
    [ testProperty "ECB Encryption Equivalent" $ ebcTests
        [ (\k m -> AESHs.encrypt (unright $ AESHs.initKey128 k) m)
        , (\k m -> AESNI.encrypt (AESNI.initKey128 k) m)
        ]
    , testProperty "CBC Encryption Equivalent" $ cbcTests
        [ (\k iv m -> AESHs.encryptCBC (unright $ AESHs.initKey128 k) iv m)
        , (\k iv m -> AESNI.encryptCBC (AESNI.initKey128 k) iv m)
        ]
    , testProperty "ECB Decryption Equivalent" $ ebcTests
        [ (\k m -> AESHs.decrypt (unright $ AESHs.initKey128 k) m)
        , (\k m -> AESNI.decrypt (AESNI.initKey128 k) m)
        ]
    , testProperty "CBC Decryption Equivalent" $ cbcTests
        [ (\k iv m -> AESHs.decryptCBC (unright $ AESHs.initKey128 k) iv m)
        , (\k iv m -> AESNI.decryptCBC (AESNI.initKey128 k) iv m)
        ]
    ]
