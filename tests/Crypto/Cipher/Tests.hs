-- |
-- Module      : Crypto.Cipher.Tests
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--

{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Tests
    ( testPropertyModes
    ) where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Crypto.Cipher.Types
import qualified Data.ByteString as B
import Data.Byteable
import Data.Maybe

-- | a ECB unit test
data ECBUnit a = ECBUnit (Key a) B.ByteString
    deriving (Eq)

-- | a CBC unit test
data CBCUnit a = CBCUnit (Key a) (IV a) B.ByteString
    deriving (Eq)

-- | a CTR unit test
data CTRUnit a = CTRUnit (Key a) (IV a) B.ByteString
    deriving (Eq)

-- | a XTS unit test
data XTSUnit a = XTSUnit (Key a) (Key a) (IV a) B.ByteString
    deriving (Eq)

instance Show (ECBUnit a) where
    show (ECBUnit key b) = "ECB(key=" ++ show (toBytes key) ++ ",input=" ++ show b ++ ")"
instance Show (CBCUnit a) where
    show (CBCUnit key iv b) = "CBC(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (CTRUnit a) where
    show (CTRUnit key iv b) = "CTR(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (XTSUnit a) where
    show (XTSUnit key1 key2 iv b) = "CTR(key1=" ++ show (toBytes key1) ++ ",key2=" ++ show (toBytes key2) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"

{-
data GCMUnit = GCMUnit B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data KeyUnit = KeyUnit B.ByteString
    deriving (Show,Eq)
-}

generateKey :: BlockCipher a => Gen (Key a)
generateKey = keyFromCipher undefined
  where keyFromCipher :: BlockCipher a => a -> Gen (Key a)
        keyFromCipher cipher = case cipherKeySize cipher of
                                Just sz -> fromJust . makeKey . B.pack <$> replicateM sz arbitrary
                                Nothing -> fromJust . makeKey . B.pack <$> (choose (1,66) >>= \sz -> replicateM sz arbitrary)

generateIv :: BlockCipher a => Gen (IV a)
generateIv = ivFromCipher undefined
  where ivFromCipher :: BlockCipher a => a -> Gen (IV a)
        ivFromCipher cipher = fromJust . makeIV . B.pack <$> replicateM (blockSize cipher) arbitrary

generateIvGCM = choose (12,90) >>= \sz -> (B.pack <$> replicateM sz arbitrary)

generatePlaintextMultiple16 = choose (1,128) >>= \size -> replicateM (size*16) arbitrary >>= return . B.pack

generatePlaintext = choose (0,324) >>= \size -> replicateM size arbitrary >>= return . B.pack

instance BlockCipher a => Arbitrary (ECBUnit a) where
    arbitrary = ECBUnit <$> generateKey
                        <*> generatePlaintextMultiple16

instance BlockCipher a => Arbitrary (CBCUnit a) where
    arbitrary = CBCUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultiple16

instance BlockCipher a => Arbitrary (CTRUnit a) where
    arbitrary = CTRUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintext

instance BlockCipher a => Arbitrary (XTSUnit a) where
    arbitrary = XTSUnit <$> generateKey
                        <*> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultiple16

{-
instance Arbitrary GCMUnit where
    arbitrary = GCMUnit <$> generateKey
                        <*> generateIvGCM
                        <*> generatePlaintext
                        <*> generatePlaintext

-}

testProperty_ECB (ECBUnit (cipherInit -> ctx) plaintext) =
    plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

testProperty_CBC (CBCUnit (cipherInit -> ctx) testIV plaintext) =
    plaintext `assertEq` cbcDecrypt ctx testIV (cbcEncrypt ctx testIV plaintext)

testProperty_CTR (CTRUnit (cipherInit -> ctx) testIV plaintext) =
    plaintext `assertEq` ctrCombine ctx testIV (ctrCombine ctx testIV plaintext)

{-
testProperty_XTS (XTSUnit (cipherInit -> ctx1) (cipherInit -> ctx2) testIV plaintext) =
    plaintext `assertEq` xtsDecrypt (ctx1, ctx2) testIV 0 (xtsEncrypt (ctx1, ctx2) testIV 0 plaintext)
-}

assertEq :: B.ByteString -> B.ByteString -> Bool
assertEq b1 b2 | b1 /= b2  = error ("b1: " ++ show b1 ++ " b2: " ++ show b2)
               | otherwise = True

{-
testProperty_GCM (GCMUnit (AES.initAES -> ctx) testIV aad plaintext) =
    let (cipherText, tag) = AES.encryptGCM ctx testIV aad plaintext in
    let (plaintext2, tag2) = AES.decryptGCM ctx testIV aad cipherText in
    (plaintext `assertEq` plaintext2) && (tag == tag2)
-}

testPropertyModes :: BlockCipher a => a -> [Test]
testPropertyModes cipher =
    [ testGroup "decrypt.encrypt==id"
        [ testProperty "ECB" ecbProp
        , testProperty "CBC" cbcProp
        , testProperty "CTR" ctrProp
        ]
    ]
  where (ecbProp,cbcProp,ctrProp) = toTests cipher
        toTests :: BlockCipher a
                => a
                -> ((ECBUnit a -> Bool), (CBCUnit a -> Bool), (CTRUnit a -> Bool))
        toTests _ = (testProperty_ECB
                    ,testProperty_CBC
                    ,testProperty_CTR
                    )
