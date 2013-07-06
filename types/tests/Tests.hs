{-# LANGUAGE ViewPatterns #-}
module Main where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit

import Test.QuickCheck
import Test.QuickCheck.Test
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Crypto.Cipher.Types
import qualified Data.ByteString as B
import Data.Byteable
import Data.Maybe
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

data ECBUnit a = ECBUnit (Key a) B.ByteString
    deriving (Eq)
data CBCUnit a = CBCUnit (Key a) (IV a) B.ByteString
    deriving (Eq)
data CTRUnit a = CTRUnit (Key a) (IV a) B.ByteString
    deriving (Eq)

instance Show (ECBUnit a) where
    show (ECBUnit key b) = "ECB(key=" ++ show (toBytes key) ++ ",input=" ++ show b ++ ")"
instance Show (CBCUnit a) where
    show (CBCUnit key iv b) = "CBC(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (CTRUnit a) where
    show (CTRUnit key iv b) = "CTR(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
{-
data XTSUnit = XTSUnit B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data GCMUnit = GCMUnit B.ByteString B.ByteString B.ByteString B.ByteString
    deriving (Show,Eq)
data KeyUnit = KeyUnit B.ByteString
    deriving (Show,Eq)
-}

--generateKeyOf size = fromJust . makeKey . B.pack <$> replicateM size arbitrary

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

{-
instance Arbitrary GCMUnit where
    arbitrary = GCMUnit <$> generateKey
                        <*> generateIvGCM
                        <*> generatePlaintext
                        <*> generatePlaintext

instance Arbitrary XTSUnit where
    arbitrary = do
        size <- elements [16,32]
        XTSUnit <$> generateKeyOf size
                <*> generateKeyOf size
                <*> generateIv
                <*> generatePlaintextMultiple16
-}

idECBTests (ECBUnit (cipherInit -> ctx) plaintext) =
    plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

idCBCTests (CBCUnit (cipherInit -> ctx) testIV plaintext) =
    plaintext `assertEq` cbcDecrypt ctx testIV (cbcEncrypt ctx testIV plaintext)

idCTRTests (CTRUnit (cipherInit -> ctx) testIV plaintext) =
    plaintext `assertEq` ctrCombine ctx testIV (ctrCombine ctx testIV plaintext)

assertEq :: B.ByteString -> B.ByteString -> Bool
assertEq b1 b2 | b1 /= b2  = error ("b1: " ++ show b1 ++ " b2: " ++ show b2)
               | otherwise = True
{-
idXTSTests (XTSUnit (AES.initAES -> ctx1) (AES.initAES -> ctx2) testIV plaintext) =
    plaintext `assertEq` AES.decryptXTS (ctx1, ctx2) testIV 0 (AES.encryptXTS (ctx1, ctx2) testIV 0 plaintext)

idGCMTests (GCMUnit (AES.initAES -> ctx) testIV aad plaintext) =
    let (cipherText, tag) = AES.encryptGCM ctx testIV aad plaintext in
    let (plaintext2, tag2) = AES.decryptGCM ctx testIV aad cipherText in
    (plaintext `assertEq` plaintext2) && (tag == tag2)
-}

tests =
    [ testProperty "ebc (decrypt . encrypt == id)" (idECBTests :: ECBUnit XorCipher -> Bool)
    , testProperty "cbc (decrypt . encrypt == id)" (idCBCTests :: CBCUnit XorCipher -> Bool)
    , testProperty "ctr (combine . combine == id)" (idCTRTests :: CTRUnit XorCipher -> Bool)
    ]

main = defaultMain tests
