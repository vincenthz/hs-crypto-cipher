{-# LANGUAGE OverloadedStrings #-}

import Test.Framework (Test, defaultMain, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Test.QuickCheck
import Test.QuickCheck.Test
import System.IO (hFlush, stdout)

import Control.Monad
import Control.Arrow (first)
import Control.Applicative ((<$>))

import Data.List (intercalate)
import Data.Char
import Data.Bits
import Data.Word
import Data.Maybe (fromJust)
import qualified Data.Vector.Unboxed as V
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
-- for DSA
import qualified Crypto.Hash.SHA1 as SHA1

-- ciphers/Kexch
import qualified Crypto.Cipher.TripleDES as TripleDES
import qualified Crypto.Classes as CryptoAPI
import qualified Crypto.Types as CryptoTypes
import Crypto.Random
import KAT

prop_ecb_valid encrypt decrypt k msg = decrypt k (encrypt k msg) == msg

{-----------------------------------------------------------------------------------------------}
{- testing 3DES -}
{-----------------------------------------------------------------------------------------------}

data DESEEE3Message = DESEEE3Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)
data DESEDE3Message = DESEDE3Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)
data DESEEE2Message = DESEEE2Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)
data DESEDE2Message = DESEDE2Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)

commonTripleDesMessage construct keysNumber = do
                key <- replicateM (8 * keysNumber) (choose (0, 255) :: Gen Int)
                sz <- choose (1, 12)
                ws <- replicateM (sz * 16) (choose (0, 255) :: Gen Int)
                iv  <- replicateM 8 (choose (0,255) :: Gen Int)
                return $ construct (B.pack $ map fromIntegral key)
                                   (B.pack $ map fromIntegral ws)
                                   (B.pack $ map fromIntegral iv)

instance Arbitrary DESEEE3Message where
        arbitrary = commonTripleDesMessage DESEEE3Message 3

instance Arbitrary DESEDE3Message where
        arbitrary = commonTripleDesMessage DESEDE3Message 3

instance Arbitrary DESEEE2Message where
        arbitrary = commonTripleDesMessage DESEEE2Message 2

instance Arbitrary DESEDE2Message where
        arbitrary = commonTripleDesMessage DESEDE2Message 2

prop_3des_valid encrypt decrypt key iv msg =
    (fst $ decrypt key (CryptoTypes.IV iv) (fst $ encrypt key (CryptoTypes.IV iv) msg)) == msg

tripleDesCipherKey :: (CryptoAPI.BlockCipher c) => B.ByteString -> c
tripleDesCipherKey = fromJust . CryptoAPI.buildKey

-- 3DES ECB section

prop_des_eee3_ecb_valid (DESEEE3Message key _ msg) =
        prop_ecb_valid CryptoAPI.ecb
                       CryptoAPI.unEcb
                       (tripleDesCipherKey key :: TripleDES.DesEee3Key)
                       msg

prop_des_ede3_ecb_valid (DESEDE3Message key _ msg) =
        prop_ecb_valid CryptoAPI.ecb
                       CryptoAPI.unEcb
                       (tripleDesCipherKey key :: TripleDES.DesEde3Key)
                       msg

prop_des_eee2_ecb_valid (DESEEE2Message key _ msg) =
        prop_ecb_valid CryptoAPI.ecb
                       CryptoAPI.unEcb
                       (tripleDesCipherKey key :: TripleDES.DesEee2Key)
                       msg

prop_des_ede2_ecb_valid (DESEDE2Message key _ msg) =
        prop_ecb_valid CryptoAPI.ecb
                       CryptoAPI.unEcb
                       (tripleDesCipherKey key :: TripleDES.DesEde2Key)
                       msg

-- 3DES CBC section

prop_des_eee3_cbc_valid (DESEEE3Message key iv msg) =
        prop_3des_valid CryptoAPI.cbc
                        CryptoAPI.unCbc
                        (tripleDesCipherKey key :: TripleDES.DesEee3Key)
                        iv
                        msg

prop_des_ede3_cbc_valid (DESEDE3Message key iv msg) =
        prop_3des_valid CryptoAPI.cbc
                        CryptoAPI.unCbc
                        (tripleDesCipherKey key :: TripleDES.DesEde3Key)
                        iv
                        msg

prop_des_eee2_cbc_valid (DESEEE2Message key iv msg) =
        prop_3des_valid CryptoAPI.cbc
                        CryptoAPI.unCbc
                        (tripleDesCipherKey key :: TripleDES.DesEee2Key)
                        iv
                        msg

prop_des_ede2_cbc_valid (DESEDE2Message key iv msg) =
        prop_3des_valid CryptoAPI.cbc
                        CryptoAPI.unCbc
                        (tripleDesCipherKey key :: TripleDES.DesEde2Key)
                        iv
                        msg

-- 3DES CTR section

prop_des_eee3_ctr_valid (DESEEE3Message key iv msg) =
        prop_3des_valid CryptoAPI.ctr
                        CryptoAPI.unCtr
                        (tripleDesCipherKey key :: TripleDES.DesEee3Key)
                        iv
                        msg

prop_des_ede3_ctr_valid (DESEDE3Message key iv msg) =
        prop_3des_valid CryptoAPI.ctr
                        CryptoAPI.unCtr
                        (tripleDesCipherKey key :: TripleDES.DesEde3Key)
                        iv
                        msg

prop_des_eee2_ctr_valid (DESEEE2Message key iv msg) =
        prop_3des_valid CryptoAPI.ctr
                        CryptoAPI.unCtr
                        (tripleDesCipherKey key :: TripleDES.DesEee2Key)
                        iv
                        msg

prop_des_ede2_ctr_valid (DESEDE2Message key iv msg) =
        prop_3des_valid CryptoAPI.ctr
                        CryptoAPI.unCtr
                        (tripleDesCipherKey key :: TripleDES.DesEde2Key)
                        iv
                        msg

-- 3DES CFB section

prop_des_eee3_cfb_valid (DESEEE3Message key iv msg) =
        prop_3des_valid CryptoAPI.cfb
                        CryptoAPI.unCfb
                        (tripleDesCipherKey key :: TripleDES.DesEee3Key)
                        iv
                        msg

prop_des_ede3_cfb_valid (DESEDE3Message key iv msg) =
        prop_3des_valid CryptoAPI.cfb
                        CryptoAPI.unCfb
                        (tripleDesCipherKey key :: TripleDES.DesEde3Key)
                        iv
                        msg

prop_des_eee2_cfb_valid (DESEEE2Message key iv msg) =
        prop_3des_valid CryptoAPI.cfb
                        CryptoAPI.unCfb
                        (tripleDesCipherKey key :: TripleDES.DesEee2Key)
                        iv
                        msg

prop_des_ede2_cfb_valid (DESEDE2Message key iv msg) =
        prop_3des_valid CryptoAPI.cfb
                        CryptoAPI.unCfb
                        (tripleDesCipherKey key :: TripleDES.DesEde2Key)
                        iv
                        msg

-- 3DES OFB section

prop_des_eee3_ofb_valid (DESEEE3Message key iv msg) =
        prop_3des_valid CryptoAPI.ofb
                        CryptoAPI.unOfb
                        (tripleDesCipherKey key :: TripleDES.DesEee3Key)
                        iv
                        msg

prop_des_ede3_ofb_valid (DESEDE3Message key iv msg) =
        prop_3des_valid CryptoAPI.ofb
                        CryptoAPI.unOfb
                        (tripleDesCipherKey key :: TripleDES.DesEde3Key)
                        iv
                        msg

prop_des_eee2_ofb_valid (DESEEE2Message key iv msg) =
        prop_3des_valid CryptoAPI.ofb
                        CryptoAPI.unOfb
                        (tripleDesCipherKey key :: TripleDES.DesEee2Key)
                        iv
                        msg

prop_des_ede2_ofb_valid (DESEDE2Message key iv msg) =
        prop_3des_valid CryptoAPI.ofb
                        CryptoAPI.unOfb
                        (tripleDesCipherKey key :: TripleDES.DesEde2Key)
                        iv
                        msg

{-----------------------------------------------------------------------------------------------}
{- main -}
{-----------------------------------------------------------------------------------------------}

symCipherExpectedTests = testGroup "symmetric cipher KAT" katTests

symCipherMarshallTests = testGroup "symmetric cipher marshall"
	[ testProperty "DES-EEE3 (ECB)" prop_des_eee3_ecb_valid
	, testProperty "DES-EEE3 (CBC)" prop_des_eee3_cbc_valid
	, testProperty "DES-EEE3 (CTR)" prop_des_eee3_ctr_valid
	, testProperty "DES-EEE3 (CFB)" prop_des_eee3_cfb_valid
	, testProperty "DES-EEE3 (OFB)" prop_des_eee3_ofb_valid
	, testProperty "DES-EDE3 (ECB)" prop_des_ede3_ecb_valid
	, testProperty "DES-EDE3 (CBC)" prop_des_ede3_cbc_valid
	, testProperty "DES-EDE3 (CTR)" prop_des_ede3_ctr_valid
	, testProperty "DES-EDE3 (CFB)" prop_des_ede3_cfb_valid
	, testProperty "DES-EDE3 (OFB)" prop_des_ede3_ofb_valid
	, testProperty "DES-EEE2 (ECB)" prop_des_eee2_ecb_valid
	, testProperty "DES-EEE2 (CBC)" prop_des_eee2_cbc_valid
	, testProperty "DES-EEE2 (CTR)" prop_des_eee2_ctr_valid
	, testProperty "DES-EEE2 (CFB)" prop_des_eee2_cfb_valid
	, testProperty "DES-EEE2 (OFB)" prop_des_eee2_ofb_valid
	, testProperty "DES-EDE2 (ECB)" prop_des_ede2_ecb_valid
	, testProperty "DES-EDE2 (CBC)" prop_des_ede2_cbc_valid
	, testProperty "DES-EDE2 (CTR)" prop_des_ede2_ctr_valid
	, testProperty "DES-EDE2 (CFB)" prop_des_ede2_cfb_valid
	, testProperty "DES-EDE2 (OFB)" prop_des_ede2_ofb_valid
	]

tests :: [Test]
tests =
	[ symCipherExpectedTests
	, symCipherMarshallTests
	]

main = defaultMain tests
