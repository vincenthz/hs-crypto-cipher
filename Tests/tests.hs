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
import qualified Data.Vector.Unboxed as V
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
-- for DSA
import qualified Crypto.Hash.SHA1 as SHA1

-- ciphers/Kexch
import AES (aesTests)
import qualified Crypto.Cipher.AES as AES
import Crypto.Random
import KAT

{-----------------------------------------------------------------------------------------------}
{- testing AES -}
{-----------------------------------------------------------------------------------------------}
data AES128Message = AES128Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)
data AES192Message = AES192Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)
data AES256Message = AES256Message B.ByteString B.ByteString B.ByteString deriving (Show, Eq)

arbitraryAES keysize = do
	sz <- choose (1, 12)
	ws <- replicateM (sz*16) (choose (0,255) :: Gen Int)
	key <- replicateM keysize (choose (0,255) :: Gen Int)
	iv  <- replicateM 16 (choose (0,255) :: Gen Int)
	return (ws, key, iv)

instance Arbitrary AES128Message where
	arbitrary = do
		(ws, key, iv) <- arbitraryAES 16
		return $ AES128Message (B.pack $ map fromIntegral key)
		                       (B.pack $ map fromIntegral iv)
		                       (B.pack $ map fromIntegral ws)

instance Arbitrary AES192Message where
	arbitrary = do
		(ws, key, iv) <- arbitraryAES 24
		return $ AES192Message (B.pack $ map fromIntegral key)
		                       (B.pack $ map fromIntegral iv)
		                       (B.pack $ map fromIntegral ws)

instance Arbitrary AES256Message where
	arbitrary = do
		(ws, key, iv) <- arbitraryAES 32
		return $ AES256Message (B.pack $ map fromIntegral key)
		                       (B.pack $ map fromIntegral iv)
		                       (B.pack $ map fromIntegral ws)


prop_ecb_valid k msg = AES.decryptECB k (AES.encryptECB k msg) == msg
prop_cbc_valid k iv msg = AES.decryptCBC k (AES.IV iv) (AES.encryptCBC k (AES.IV iv) msg) == msg

prop_aes128_ecb_valid (AES128Message key _ msg) =
	let k = AES.initKey key in
	prop_ecb_valid k msg

prop_aes192_ecb_valid (AES192Message key _ msg) =
	let k = AES.initKey key in
	prop_ecb_valid k msg

prop_aes256_ecb_valid (AES256Message key _ msg) =
	let k = AES.initKey key in
	prop_ecb_valid k msg

prop_aes128_cbc_valid (AES128Message key iv msg) =
	let k = AES.initKey key in
	prop_cbc_valid k iv msg

prop_aes192_cbc_valid (AES192Message key iv msg) =
	let k = AES.initKey key in
	prop_cbc_valid k iv msg

prop_aes256_cbc_valid (AES256Message key iv msg) =
	let k = AES.initKey key in
	prop_cbc_valid k iv msg

{-----------------------------------------------------------------------------------------------}
{- main -}
{-----------------------------------------------------------------------------------------------}

symCipherExpectedTests = testGroup "symmetric cipher KAT" katTests

symCipherMarshallTests = testGroup "symmetric cipher marshall"
	[ testProperty "AES128 (ECB)" prop_aes128_ecb_valid
	, testProperty "AES128 (CBC)" prop_aes128_cbc_valid
	, testProperty "AES192 (ECB)" prop_aes192_ecb_valid
	, testProperty "AES192 (CBC)" prop_aes192_cbc_valid
	, testProperty "AES256 (ECB)" prop_aes256_ecb_valid
	, testProperty "AES256 (CBC)" prop_aes256_cbc_valid
	]

tests :: [Test]
tests =
	[ symCipherExpectedTests
	, symCipherMarshallTests
	, testGroup "AES" aesTests
	]

main = defaultMain tests
{-
	-- Number Tests
	run_test "gcde binary valid" prop_gcde_binary_valid
	run_test "exponantiation RTL valid" prop_modexp_rtl_valid
	run_test "inverse valid" prop_modinv_valid
	run_test "sqrt integer valid" prop_sqrti_valid
	run_test "primality test Miller Rabin" prop_miller_rabin_valid
	run_test "Generate prime" prop_generate_prime_valid
	-}
