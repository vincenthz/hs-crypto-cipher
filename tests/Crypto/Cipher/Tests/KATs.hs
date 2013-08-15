module Crypto.Cipher.Tests.KATs
    where

import Data.ByteString (ByteString)

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.HUnit (testCase)
import Test.HUnit ((@?=))
import Crypto.Cipher.Types
import Data.Maybe

-- | ECB KAT
data KAT_ECB = KAT_ECB
    { ecbKey        :: ByteString
    , ecbPlaintext  :: ByteString
    , ecbCiphertext :: ByteString
    } deriving (Show,Eq)

-- | CBC KAT
data KAT_CBC = KAT_CBC
    { cbcKey        :: ByteString
    , cbcIV         :: ByteString
    , cbcPlaintext  :: ByteString
    , cbcCiphertext :: ByteString
    } deriving (Show,Eq)

-- | CTR KAT
data KAT_CTR = KAT_CTR
    { ctrKey        :: ByteString
    , ctrIV         :: ByteString
    , ctrPlaintext  :: ByteString
    , ctrCiphertext :: ByteString
    } deriving (Show,Eq)

-- | XTS KAT
data KAT_XTS = KAT_XTS
    { xtsKey1       :: ByteString
    , xtsKey2       :: ByteString
    , xtsIV         :: ByteString
    , xtsPlaintext  :: ByteString
    , xtsCiphertext :: ByteString
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

data KATs = KATs
    { kat_ECB  :: [KAT_ECB]
    , kat_CBC  :: [KAT_CBC]
    , kat_CTR  :: [KAT_CTR]
    , kat_XTS  :: [KAT_XTS]
    , kat_AEAD :: [KAT_AEAD]
    } deriving (Show,Eq)

defaultKATs :: KATs
defaultKATs = KATs
    { kat_ECB  = []
    , kat_CBC  = []
    , kat_CTR  = []
    , kat_XTS  = []
    , kat_AEAD = []
    }

testKATs :: BlockCipher cipher => KATs -> cipher -> Test
testKATs kats cipher = testGroup "KAT"
    (   maybeGroup makeECBTest "ECB" (kat_ECB kats)
     ++ maybeGroup makeCBCTest "CBC" (kat_CBC kats)
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
               
        maybeGroup mkTest groupName l
            | null l    = []
            | otherwise = [testGroup groupName (concatMap (\(i, d) -> mkTest (show i) d) $ zip nbs l)]
        nbs :: [Int]
        nbs = [0..]
        
        cipherMakeKey :: BlockCipher cipher => cipher -> ByteString -> Key cipher
        cipherMakeKey c bs = case makeKey bs of
                                Nothing -> error ("invalid key " ++ show bs ++ " for " ++ show (cipherName c))
                                Just k  -> k

        cipherMakeIV :: BlockCipher cipher => cipher -> ByteString -> IV cipher
        cipherMakeIV _ bs = fromJust $ makeIV bs
