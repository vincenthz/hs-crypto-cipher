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

-- | any sized bytestring
newtype Plaintext a = Plaintext B.ByteString
    deriving (Show,Eq)

instance Byteable (Plaintext a) where
    toBytes (Plaintext b) = b

-- | A multiple of blocksize bytestring
newtype PlaintextBS a = PlaintextBS B.ByteString
    deriving (Show,Eq)

instance Byteable (PlaintextBS a) where
    toBytes (PlaintextBS b) = b

-- | a ECB unit test
data ECBUnit a = ECBUnit (Key a) (PlaintextBS a)
    deriving (Eq)

-- | a CBC unit test
data CBCUnit a = CBCUnit (Key a) (IV a) (PlaintextBS a)
    deriving (Eq)

-- | a CBC unit test
data CFBUnit a = CFBUnit (Key a) (IV a) (PlaintextBS a)
    deriving (Eq)

-- | a CFB unit test
data CFB8Unit a = CFB8Unit (Key a) (IV a) (Plaintext a)
    deriving (Eq)

-- | a CTR unit test
data CTRUnit a = CTRUnit (Key a) (IV a) (Plaintext a)
    deriving (Eq)

-- | a XTS unit test
data XTSUnit a = XTSUnit (Key a) (Key a) (IV a) (PlaintextBS a)
    deriving (Eq)

-- | a AEAD unit test
data AEADUnit a = AEADUnit (Key a) B.ByteString (Plaintext a) (Plaintext a)
    deriving (Eq)

-- | Stream cipher unit test
data StreamUnit a = StreamUnit (Key a) (Plaintext a)
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

-- | Generate a plaintext multiple of blocksize bytes
generatePlaintextMultipleBS :: BlockCipher a => Gen (PlaintextBS a)
generatePlaintextMultipleBS = choose (1,128) >>= \size -> replicateM (size * 16) arbitrary >>= return . PlaintextBS . B.pack

-- | Generate any sized plaintext
generatePlaintext :: Gen (Plaintext a)
generatePlaintext = choose (0,324) >>= \size -> replicateM size arbitrary >>= return . Plaintext . B.pack

instance BlockCipher a => Arbitrary (ECBUnit a) where
    arbitrary = ECBUnit <$> generateKey
                        <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (CBCUnit a) where
    arbitrary = CBCUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (CFBUnit a) where
    arbitrary = CFBUnit <$> generateKey
                        <*> generateIv
                        <*> generatePlaintextMultipleBS

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
                        <*> generatePlaintextMultipleBS

instance BlockCipher a => Arbitrary (AEADUnit a) where
    arbitrary = AEADUnit <$> generateKey
                         <*> generateIvAEAD
                         <*> generatePlaintext
                         <*> generatePlaintext

instance StreamCipher a => Arbitrary (StreamUnit a) where
    arbitrary = StreamUnit <$> generateKey
                           <*> generatePlaintext

testBlockCipherBasic :: BlockCipher a => a -> [Test]
testBlockCipherBasic cipher = [ testProperty "ECB" ecbProp ]
  where ecbProp = toTests cipher
        toTests :: BlockCipher a => a -> (ECBUnit a -> Bool)
        toTests _ = testProperty_ECB
        testProperty_ECB (ECBUnit (cipherInit -> ctx) (toBytes -> plaintext)) =
            plaintext `assertEq` ecbDecrypt ctx (ecbEncrypt ctx plaintext)

testBlockCipherModes :: BlockCipher a => a -> [Test]
testBlockCipherModes cipher =
    [ testProperty "CBC" cbcProp
    , testProperty "CFB" cfbProp
    , testProperty "CFB8" cfb8Prop
    , testProperty "CTR" ctrProp
    ]
  where (cbcProp,cfbProp,cfb8Prop,ctrProp) = toTests cipher
        toTests :: BlockCipher a
                => a
                -> ((CBCUnit a -> Bool), (CFBUnit a -> Bool), (CFB8Unit a -> Bool), (CTRUnit a -> Bool))
        toTests _ = (testProperty_CBC
                    ,testProperty_CFB
                    ,testProperty_CFB8
                    ,testProperty_CTR
                    )
        testProperty_CBC (CBCUnit (cipherInit -> ctx) testIV (toBytes -> plaintext)) =
            plaintext `assertEq` cbcDecrypt ctx testIV (cbcEncrypt ctx testIV plaintext)

        testProperty_CFB (CFBUnit (cipherInit -> ctx) testIV (toBytes -> plaintext)) =
            plaintext `assertEq` cfbDecrypt ctx testIV (cfbEncrypt ctx testIV plaintext)

        testProperty_CFB8 (CFB8Unit (cipherInit -> ctx) testIV (toBytes -> plaintext)) =
            plaintext `assertEq` cfb8Decrypt ctx testIV (cfb8Encrypt ctx testIV plaintext)

        testProperty_CTR (CTRUnit (cipherInit -> ctx) testIV (toBytes -> plaintext)) =
            plaintext `assertEq` ctrCombine ctx testIV (ctrCombine ctx testIV plaintext)

testBlockCipherAEAD :: BlockCipher a => a -> [Test]
testBlockCipherAEAD cipher =
    [ testProperty "OCB" (aeadProp AEAD_OCB)
    , testProperty "CCM" (aeadProp AEAD_CCM)
    , testProperty "EAX" (aeadProp AEAD_EAX)
    , testProperty "CWC" (aeadProp AEAD_CWC)
    , testProperty "GCM" (aeadProp AEAD_GCM)
    ]
  where aeadProp = toTests cipher
        toTests :: BlockCipher a => a -> (AEADMode -> AEADUnit a -> Bool)
        toTests _ = testProperty_AEAD
        testProperty_AEAD mode (AEADUnit (cipherInit -> ctx) testIV (toBytes -> aad) (toBytes -> plaintext)) =
            case aeadInit mode ctx testIV of
                Just iniAead ->
                    let aead           = aeadAppendHeader iniAead aad
                        (eText, aeadE) = aeadEncrypt aead plaintext
                        (dText, aeadD) = aeadDecrypt aead eText
                        eTag           = aeadFinalize aeadE (blockSize ctx)
                        dTag           = aeadFinalize aeadD (blockSize ctx)
                     in (plaintext `assertEq` dText) && (toBytes eTag `assertEq` toBytes dTag)
                Nothing -> True

testBlockCipherXTS :: BlockCipher a => a -> [Test]
testBlockCipherXTS cipher = [testProperty "XTS" xtsProp]
  where xtsProp = toTests cipher
        toTests :: BlockCipher a => a -> (XTSUnit a -> Bool)
        toTests _ = testProperty_XTS

        testProperty_XTS (XTSUnit (cipherInit -> ctx1) (cipherInit -> ctx2) testIV (toBytes -> plaintext))
            | blockSize ctx1 == 16 = plaintext `assertEq` xtsDecrypt (ctx1, ctx2) testIV 0 (xtsEncrypt (ctx1, ctx2) testIV 0 plaintext)
            | otherwise            = True

-- | Test a generic block cipher for properties
-- related to block cipher modes.
testModes :: BlockCipher a => a -> [Test]
testModes cipher =
    [ testGroup "decrypt.encrypt==id"
        (testBlockCipherBasic cipher ++ testBlockCipherModes cipher ++ testBlockCipherAEAD cipher ++ testBlockCipherXTS cipher)
    ]

-- | Test a generic block cipher for properties
-- related to BlockCipherIO cipher modes.
testIOModes :: BlockCipherIO a => a -> [Test]
testIOModes cipher =
    [ testGroup "mutable"
        [ testProperty "ECB" (testProperty_ECB cipher)
        , testProperty "CBC" (testProperty_CBC cipher) ]
    ]
  where testProperty_ECB :: BlockCipherIO a => a -> (ECBUnit a) -> Bool
        testProperty_ECB _ (ECBUnit (cipherInit -> ctx) (toBytes -> plaintext)) =
            plaintext == B.unsafeCreate (B.length plaintext) encryptDecryptMutable
          where encryptDecryptMutable buf = withBytePtr plaintext $ \src -> do
                    ecbEncryptMutable ctx buf src (fromIntegral $ B.length plaintext)
                    ecbDecryptMutable ctx buf buf (fromIntegral $ B.length plaintext)

        testProperty_CBC :: BlockCipherIO a => a -> (CBCUnit a) -> Bool
        testProperty_CBC _ (CBCUnit (cipherInit -> ctx) testIV (toBytes -> plaintext)) =
            plaintext == B.unsafeCreate (B.length plaintext) encryptDecryptMutable
          where encryptDecryptMutable buf =
                    void $ B.create (B.length plaintext) $ \tmp ->
                    withBytePtr plaintext $ \src ->
                    withBytePtr testIV $ \iv -> do
                        cbcEncryptMutable ctx iv tmp src (fromIntegral $ B.length plaintext)
                        cbcDecryptMutable ctx iv buf tmp (fromIntegral $ B.length plaintext)
                    
-- | Test stream mode
testStream :: StreamCipher a => a -> [Test]
testStream cipher = [testProperty "combine.combine==id" (testStreamUnit cipher)]
  where testStreamUnit :: StreamCipher a => a -> (StreamUnit a -> Bool)
        testStreamUnit _ (StreamUnit (cipherInit -> ctx) (toBytes -> plaintext)) =
            let cipherText = fst $ streamCombine ctx plaintext
             in fst (streamCombine ctx cipherText) `assertEq` plaintext

assertEq :: B.ByteString -> B.ByteString -> Bool
assertEq b1 b2 | b1 /= b2  = error ("b1: " ++ show b1 ++ " b2: " ++ show b2)
               | otherwise = True
