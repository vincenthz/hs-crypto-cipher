{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Tests.Properties
    where

import Control.Applicative
import Control.Monad

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)
import Test.QuickCheck

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

-- | a CBC unit test
data CFBUnit a = CFBUnit (Key a) (IV a) B.ByteString
    deriving (Eq)

-- | a CFB unit test
data CFB8Unit a = CFB8Unit (Key a) (IV a) B.ByteString
    deriving (Eq)

-- | a CTR unit test
data CTRUnit a = CTRUnit (Key a) (IV a) B.ByteString
    deriving (Eq)

-- | a XTS unit test
data XTSUnit a = XTSUnit (Key a) (Key a) (IV a) B.ByteString
    deriving (Eq)

-- | a AEAD unit test
data AEADUnit a = AEADUnit (Key a) B.ByteString B.ByteString B.ByteString
    deriving (Eq)

data StreamUnit a = StreamUnit (Key a) B.ByteString
    deriving (Eq)

instance Show (ECBUnit a) where
    show (ECBUnit key b) = "ECB(key=" ++ show (toBytes key) ++ ",input=" ++ show b ++ ")"
instance Show (CBCUnit a) where
    show (CBCUnit key iv b) = "CBC(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (CFBUnit a) where
    show (CFBUnit key iv b) = "CFB(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (CFB8Unit a) where
    show (CFB8Unit key iv b) = "CFB8(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (CTRUnit a) where
    show (CTRUnit key iv b) = "CTR(key=" ++ show (toBytes key) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (XTSUnit a) where
    show (XTSUnit key1 key2 iv b) = "XTS(key1=" ++ show (toBytes key1) ++ ",key2=" ++ show (toBytes key2) ++ ",iv=" ++ show (toBytes iv) ++ ",input=" ++ show b ++ ")"
instance Show (AEADUnit a) where
    show (AEADUnit key iv aad b) = "AEAD(key=" ++ show (toBytes key) ++ ",iv=" ++ show iv ++ ",aad=" ++ show (toBytes aad) ++ ",input=" ++ show b ++ ")"
instance Show (StreamUnit a) where
    show (StreamUnit key b) = "Stream(key=" ++ show (toBytes key) ++ ",input=" ++ show b ++ ")"

-- | Generate an arbitrary valid key for a specific block cipher
generateKey :: Cipher a => Gen (Key a)
generateKey = keyFromCipher undefined
  where keyFromCipher :: Cipher a => a -> Gen (Key a)
        keyFromCipher cipher = do
            sz <- case cipherKeySize cipher of
                         KeySizeRange low high -> choose (low, high)
                         KeySizeFixed v -> return v
                         KeySizeEnum l  -> elements l
            either (error . show) id . makeKey . B.pack <$> replicateM sz arbitrary

-- | Generate an arbitrary valid IV for a specific block cipher
generateIv :: BlockCipher a => Gen (IV a)
generateIv = ivFromCipher undefined
  where ivFromCipher :: BlockCipher a => a -> Gen (IV a)
        ivFromCipher cipher = fromJust . makeIV . B.pack <$> replicateM (blockSize cipher) arbitrary

-- | Generate an arbitrary valid IV for AEAD for a specific block cipher
generateIvAEAD :: Gen B.ByteString
generateIvAEAD = choose (12,90) >>= \sz -> (B.pack <$> replicateM sz arbitrary)

-- | Generate a plaintext multiple of 16 bytes. TODO replace by one function that use the blockSize
-- cipher instance
generatePlaintextMultiple16 :: Gen B.ByteString
generatePlaintextMultiple16 = choose (1,128) >>= \size -> replicateM (size*16) arbitrary >>= return . B.pack

generatePlaintext :: Gen B.ByteString
generatePlaintext = choose (0,324) >>= \size -> replicateM size arbitrary >>= return . B.pack

instance BlockCipher a => Arbitrary (ECBUnit a) where
    arbitrary = ECBUnit <$> generateKey
                        <*> generatePlaintextMultiple16

instance BlockCipher a => Arbitrary (CBCUnit a) where
    arbitrary = CBCUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultiple16

instance BlockCipher a => Arbitrary (CFBUnit a) where
    arbitrary = CFBUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultiple16

instance BlockCipher a => Arbitrary (CFB8Unit a) where
    arbitrary = CFB8Unit <$> generateKey <*> generateIv <*> generatePlaintext

instance BlockCipher a => Arbitrary (CTRUnit a) where
    arbitrary = CTRUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintext

instance BlockCipher a => Arbitrary (XTSUnit a) where
    arbitrary = XTSUnit <$> generateKey
                        <*> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultiple16

instance BlockCipher a => Arbitrary (AEADUnit a) where
    arbitrary = AEADUnit <$> generateKey
                         <*> generateIvAEAD
                         <*> generatePlaintext
                         <*> generatePlaintext

instance StreamCipher a => Arbitrary (StreamUnit a) where
    arbitrary = StreamUnit <$> generateKey
                           <*> generatePlaintext

-- | Test a generic block cipher for properties
-- related to block cipher modes.
testModes :: BlockCipher a => a -> [Test]
testModes cipher =
    [ testGroup "decrypt.encrypt==id"
        [ testProperty "ECB" ecbProp
        , testProperty "CBC" cbcProp
        , testProperty "CFB" cfbProp
        , testProperty "CFB8" cfb8Prop
        , testProperty "CTR" ctrProp
        , testProperty "XTS" xtsProp
        , testProperty "OCB" (aeadProp AEAD_OCB)
        , testProperty "CCM" (aeadProp AEAD_CCM)
        , testProperty "EAX" (aeadProp AEAD_EAX)
        , testProperty "CWC" (aeadProp AEAD_CWC)
        , testProperty "GCM" (aeadProp AEAD_GCM)
        ]
    ]
  where (ecbProp,cbcProp,cfbProp,cfb8Prop,ctrProp,xtsProp,aeadProp) = toTests cipher
        toTests :: BlockCipher a
                => a
                -> ((ECBUnit a -> Bool),
                    (CBCUnit a -> Bool),
                    (CFBUnit a -> Bool),
                    (CFB8Unit a -> Bool),
                    (CTRUnit a -> Bool),
                    (XTSUnit a -> Bool),
                    (AEADMode -> AEADUnit a -> Bool))
        toTests _ = (testProperty_ECB
                    ,testProperty_CBC
                    ,testProperty_CFB
                    ,testProperty_CFB8
                    ,testProperty_CTR
                    ,testProperty_XTS
                    ,testProperty_AEAD
                    )
        testProperty_ECB (ECBUnit (cipherInit -> ctx) plaintext) =
            plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

        testProperty_CBC (CBCUnit (cipherInit -> ctx) testIV plaintext) =
            plaintext `assertEq` cbcDecrypt ctx testIV (cbcEncrypt ctx testIV plaintext)

        testProperty_CFB (CFBUnit (cipherInit -> ctx) testIV plaintext) =
            plaintext `assertEq` cfbDecrypt ctx testIV (cfbEncrypt ctx testIV plaintext)

        testProperty_CFB8 (CFB8Unit (cipherInit -> ctx) testIV plaintext) =
            plaintext `assertEq` cfb8Decrypt ctx testIV (cfb8Encrypt ctx testIV plaintext)

        testProperty_CTR (CTRUnit (cipherInit -> ctx) testIV plaintext) =
            plaintext `assertEq` ctrCombine ctx testIV (ctrCombine ctx testIV plaintext)

        testProperty_XTS (XTSUnit (cipherInit -> ctx1) (cipherInit -> ctx2) testIV plaintext)
            | blockSize ctx1 == 16 = plaintext `assertEq` xtsDecrypt (ctx1, ctx2) testIV 0 (xtsEncrypt (ctx1, ctx2) testIV 0 plaintext)
            | otherwise            = True

        testProperty_AEAD mode (AEADUnit (cipherInit -> ctx) testIV aad plaintext) =
            case aeadInit mode ctx testIV of
                Just iniAead ->
                    let aead           = aeadAppendHeader iniAead aad
                        (eText, aeadE) = aeadEncrypt aead plaintext
                        (dText, aeadD) = aeadDecrypt aead eText
                        eTag           = aeadFinalize aeadE (blockSize ctx)
                        dTag           = aeadFinalize aeadD (blockSize ctx)
                     in (plaintext `assertEq` dText) && (toBytes eTag `assertEq` toBytes dTag)
                Nothing -> True

testStream :: StreamCipher a => a -> [Test]
testStream cipher = [testProperty "combine.combine==id" (testStreamUnit cipher)]
  where testStreamUnit :: StreamCipher a => a -> (StreamUnit a -> Bool)
        testStreamUnit _ (StreamUnit (cipherInit -> ctx) plaintext) =
            let cipherText = fst $ streamCombine ctx plaintext
             in fst (streamCombine ctx cipherText) `assertEq` plaintext

assertEq :: B.ByteString -> B.ByteString -> Bool
assertEq b1 b2 | b1 /= b2  = error ("b1: " ++ show b1 ++ " b2: " ++ show b2)
               | otherwise = True
