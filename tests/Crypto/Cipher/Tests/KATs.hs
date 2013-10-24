module Crypto.Cipher.Tests.KATs
    where

import Data.ByteString (ByteString)

import Test.Framework (Test, testGroup, TestName)
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit ((@?=))
import Crypto.Cipher.Types
import Data.Maybe

-- | ECB KAT
data KAT_ECB = KAT_ECB
    { ecbKey        :: ByteString -- ^ Key
    , ecbPlaintext  :: ByteString -- ^ Plaintext
    , ecbCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | CBC KAT
data KAT_CBC = KAT_CBC
    { cbcKey        :: ByteString -- ^ Key
    , cbcIV         :: ByteString -- ^ IV
    , cbcPlaintext  :: ByteString -- ^ Plaintext
    , cbcCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | CFB KAT
data KAT_CFB = KAT_CFB
    { cfbKey        :: ByteString -- ^ Key
    , cfbIV         :: ByteString -- ^ IV
    , cfbPlaintext  :: ByteString -- ^ Plaintext
    , cfbCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | CTR KAT
data KAT_CTR = KAT_CTR
    { ctrKey        :: ByteString -- ^ Key
    , ctrIV         :: ByteString -- ^ IV (usually represented as a 128 bits integer)
    , ctrPlaintext  :: ByteString -- ^ Plaintext 
    , ctrCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | XTS KAT
data KAT_XTS = KAT_XTS
    { xtsKey1       :: ByteString -- ^ 1st XTS key
    , xtsKey2       :: ByteString -- ^ 2nd XTS key
    , xtsIV         :: ByteString -- ^ XTS IV
    , xtsPlaintext  :: ByteString -- ^ plaintext
    , xtsCiphertext :: ByteString -- ^ Ciphertext
    } deriving (Show,Eq)

-- | AEAD KAT
data KAT_AEAD = KAT_AEAD
    { aeadMode       :: AEADMode   -- ^ AEAD mode to use
    , aeadKey        :: ByteString -- ^ Key
    , aeadIV         :: ByteString -- ^ IV for initialization
    , aeadHeader     :: ByteString -- ^ Authentificated Header
    , aeadPlaintext  :: ByteString -- ^ Plaintext
    , aeadCiphertext :: ByteString -- ^ Ciphertext
    , aeadTaglen     :: Int        -- ^ aead tag len
    , aeadTag        :: AuthTag    -- ^ expected tag
    } deriving (Show,Eq)

-- | all the KATs. use defaultKATs to prevent compilation error
-- from future expansion of this data structure
data KATs = KATs
    { kat_ECB  :: [KAT_ECB]
    , kat_CBC  :: [KAT_CBC]
    , kat_CFB  :: [KAT_CFB]
    , kat_CTR  :: [KAT_CTR]
    , kat_XTS  :: [KAT_XTS]
    , kat_AEAD :: [KAT_AEAD]
    } deriving (Show,Eq)

-- | KAT for Stream cipher
data KAT_Stream = KAT_Stream
    { streamKey        :: ByteString
    , streamPlaintext  :: ByteString
    , streamCiphertext :: ByteString
    } deriving (Show,Eq)

-- | the empty KATs
defaultKATs :: KATs
defaultKATs = KATs
    { kat_ECB  = []
    , kat_CBC  = []
    , kat_CFB  = []
    , kat_CTR  = []
    , kat_XTS  = []
    , kat_AEAD = []
    }

-- | the empty KATs for stream
defaultStreamKATs :: [KAT_Stream]
defaultStreamKATs = []

-- | tests related to KATs
testKATs :: BlockCipher cipher
         => KATs
         -> cipher
         -> Test
testKATs kats cipher = testGroup "KAT"
    (   maybeGroup makeECBTest "ECB" (kat_ECB kats)
     ++ maybeGroup makeCBCTest "CBC" (kat_CBC kats)
     ++ maybeGroup makeCFBTest "CFB" (kat_CFB kats)
     ++ maybeGroup makeCTRTest "CTR" (kat_CTR kats)
     ++ maybeGroup makeXTSTest "XTS" (kat_XTS kats)
     ++ maybeGroup makeAEADTest "AEAD" (kat_AEAD kats)
    )
  where makeECBTest i d =
            [ testCase ("E" ++ i) (ecbEncrypt ctx (ecbPlaintext d) @?= ecbCiphertext d)
            , testCase ("D" ++ i) (ecbDecrypt ctx (ecbCiphertext d) @?= ecbPlaintext d)
            ]
          where ctx = cipherInit (cipherMakeKey cipher $ ecbKey d)
        makeCBCTest i d =
            [ testCase ("E" ++ i) (cbcEncrypt ctx iv (cbcPlaintext d) @?= cbcCiphertext d)
            , testCase ("D" ++ i) (cbcDecrypt ctx iv (cbcCiphertext d) @?= cbcPlaintext d)
            ]
          where ctx = cipherInit (cipherMakeKey cipher $ cbcKey d)
                iv  = cipherMakeIV cipher $ cbcIV d
        makeCFBTest i d =
            [ testCase ("E" ++ i) (cfbEncrypt ctx iv (cfbPlaintext d) @?= cfbCiphertext d)
            , testCase ("D" ++ i) (cfbDecrypt ctx iv (cfbCiphertext d) @?= cfbPlaintext d)
            ]
          where ctx = cipherInit (cipherMakeKey cipher $ cfbKey d)
                iv  = cipherMakeIV cipher $ cfbIV d
        makeCTRTest i d =
            [ testCase ("E" ++ i) (ctrCombine ctx iv (ctrPlaintext d) @?= ctrCiphertext d)
            , testCase ("D" ++ i) (ctrCombine ctx iv (ctrCiphertext d) @?= ctrPlaintext d)
            ]
          where ctx = cipherInit (cipherMakeKey cipher $ ctrKey d)
                iv  = cipherMakeIV cipher $ ctrIV d
        makeXTSTest i d  =
            [ testCase ("E" ++ i) (xtsEncrypt ctx iv 0 (xtsPlaintext d) @?= xtsCiphertext d)
            , testCase ("D" ++ i) (xtsDecrypt ctx iv 0 (xtsCiphertext d) @?= xtsPlaintext d)
            ]
          where ctx1 = cipherInit (cipherMakeKey cipher $ xtsKey1 d)
                ctx2 = cipherInit (cipherMakeKey cipher $ xtsKey2 d)
                ctx  = (ctx1, ctx2)
                iv   = cipherMakeIV cipher $ xtsIV d
        makeAEADTest i d =
            [ testCase ("AE" ++ i) (etag @?= aeadTag d)
            , testCase ("AD" ++ i) (dtag @?= aeadTag d)
            , testCase ("E" ++ i)  (ebs @?= aeadCiphertext d)
            , testCase ("D" ++ i)  (dbs @?= aeadPlaintext d)
            ]
          where ctx  = cipherInit (cipherMakeKey cipher $ aeadKey d)
                (Just aead) = aeadInit (aeadMode d) ctx (aeadIV d)
                aeadHeaded     = aeadAppendHeader aead (aeadHeader d)
                (ebs,aeadEFinal) = aeadEncrypt aeadHeaded (aeadPlaintext d)
                (dbs,aeadDFinal) = aeadDecrypt aeadHeaded (aeadCiphertext d)
                etag = aeadFinalize aeadEFinal (aeadTaglen d)
                dtag = aeadFinalize aeadDFinal (aeadTaglen d)
               
testStreamKATs :: StreamCipher cipher => [KAT_Stream] -> cipher -> Test
testStreamKATs kats cipher = testGroup "KAT" $ maybeGroup makeStreamTest "Stream" kats
  where makeStreamTest i d =
            [ testCase ("E" ++ i) (fst (streamCombine ctx (streamPlaintext d)) @?= streamCiphertext d)
            , testCase ("D" ++ i) (fst (streamCombine ctx (streamCiphertext d)) @?= streamPlaintext d)
            ]
          where ctx = cipherInit (cipherMakeKey cipher $ streamKey d)

cipherMakeKey :: Cipher cipher => cipher -> ByteString -> Key cipher
cipherMakeKey c bs = case makeKey bs of
                        Left e -> error ("invalid key " ++ show bs ++ " for " ++ show (cipherName c) ++ " " ++ show e)
                        Right k  -> k

cipherMakeIV :: BlockCipher cipher => cipher -> ByteString -> IV cipher
cipherMakeIV _ bs = fromJust $ makeIV bs


maybeGroup :: (String -> t -> [Test]) -> TestName -> [t] -> [Test]
maybeGroup mkTest groupName l
    | null l    = []
    | otherwise = [testGroup groupName (concatMap (\(i, d) -> mkTest (show i) d) $ zip nbs l)]
  where nbs :: [Int]
        nbs = [0..]
