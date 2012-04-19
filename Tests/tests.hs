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

-- numbers
{-
import Number.ModArithmetic
import Number.Basic
import Number.Prime
import Number.Serialize
-}
-- ciphers/Kexch
import qualified Crypto.Cipher.AES.Haskell as AES
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA
import qualified Crypto.Cipher.DH as DH
import Crypto.Random
import KAT

{-
prop_gcde_binary_valid (Positive a, Positive b) =
	let (x,y,v)    = gcde_binary a b in
	let (x',y',v') = gcde a b in
	and [v==v', a*x' + b*y' == v', a*x + b*y == v, gcd a b == v]

prop_modexp_rtl_valid (NonNegative a, NonNegative b, Positive m) =
	exponantiation_rtl_binary a b m == ((a ^ b) `mod` m)

prop_modinv_valid (Positive a, Positive m)
	| m > 1 =
		case inverse a m of
			Just ainv -> (ainv * a) `mod` m == 1
			Nothing   -> True
	| otherwise       = True

prop_sqrti_valid (Positive i) = l*l <= i && i <= u*u where (l, u) = sqrti i

prop_generate_prime_valid i =
	-- becuase of the next naive test, we can't generate easily number above 32 bits
	-- otherwise it slows down the tests to uselessness. when AKS or ECPP is implemented
	-- we can revisit the number here
	let p = withAleasInteger rng i (\g -> generatePrime g 32) in
	-- FIXME test if p is around 32 bits
	primalityTestNaive p

prop_miller_rabin_valid i
	| i <= 3    = True
	| otherwise =
		-- miller rabin only returns with certitude that the integer is composite.
		let b = withAleasInteger rng i (\g -> isProbablyPrime g i) in
		(b == False && primalityTestNaive i == False) || b == True

withAleasInteger rng i f = case reseed (i2osp (if i < 0 then -i else i)) rng of
	Left _     -> error "impossible"
	Right rng' -> case f rng' of
		Left _  -> error "impossible"
		Right v -> fst v
-}

newtype RSAMessage = RSAMessage B.ByteString deriving (Show, Eq)

instance Arbitrary RSAMessage where
	arbitrary = do
		sz <- choose (0, 128 - 11)
		ws <- replicateM sz (choose (0,255) :: Gen Int)
		return $ RSAMessage $ B.pack $ map fromIntegral ws

{- this is a just test rng. this is absolutely not a serious RNG. DO NOT use elsewhere -}
data Rng = Rng (Int, Int)

getByte :: Rng -> (Word8, Rng)
getByte (Rng (mz, mw)) =
	let mz2 = 36969 * (mz `mod` 65536) in
	let mw2 = 18070 * (mw `mod` 65536) in
	(fromIntegral (mz2 + mw2), Rng (mz2, mw2))

getBytes 0 rng = ([], rng)
getBytes n rng =
	let (b, rng')  = getByte rng in
	let (l, rng'') = getBytes (n-1) rng' in
	(b:l, rng'')

instance CryptoRandomGen Rng where
	newGen _       = Right (Rng (2,3))
	genSeedLength  = 0
	genBytes len g = Right $ first B.pack $ getBytes len g
	reseed bs (Rng (a,b)) = Right $ Rng (fromIntegral a', b) where
		a' = ((fromIntegral a) + i * 36969) `mod` 65536
		i = B.head bs

rng = Rng (1,2) 

{-----------------------------------------------------------------------------------------------}
{- testing RSA -}
{-----------------------------------------------------------------------------------------------}

{-
prop_rsa_generate_valid (Positive i, RSAMessage msgz) =
	let keysz = 64 in
	let (pub,priv) = withAleasInteger rng i (\g -> RSA.generate g keysz 65537) in
	let msg = B.take (keysz - 11) msgz in
	(RSA.private_p priv * RSA.private_q priv == RSA.private_n priv) &&
	((RSA.private_d priv * RSA.public_e pub) `mod` ((RSA.private_p priv - 1) * (RSA.private_q priv - 1)) == 1) &&
	(either Left (RSA.decrypt priv . fst) $ RSA.encrypt rng pub msg) == Right msg
-}

prop_rsa_valid fast (RSAMessage msg) =
	(either Left (RSA.decrypt pk . fst) $ RSA.encrypt rng rsaPublickey msg) == Right msg
	where pk       = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }

prop_rsa_fast_valid  = prop_rsa_valid True
prop_rsa_slow_valid  = prop_rsa_valid False

prop_rsa_sign_valid fast (RSAMessage msg) = (either Left (\smsg -> verify msg smsg) $ sign msg) == Right True
	where
		verify   = RSA.verify (SHA1.hash) sha1desc rsaPublickey
		sign     = RSA.sign (SHA1.hash) sha1desc pk
		sha1desc = B.pack [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03, 0x02,0x1a,0x05,0x00,0x04,0x14]
		pk       = if fast then rsaPrivatekey else rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }

prop_rsa_sign_fast_valid = prop_rsa_sign_valid True
prop_rsa_sign_slow_valid = prop_rsa_sign_valid False

rsaPrivatekey = RSA.PrivateKey
	{ RSA.private_size = 128
	, RSA.private_n    = 140203425894164333410594309212077886844966070748523642084363106504571537866632850620326769291612455847330220940078873180639537021888802572151020701352955762744921926221566899281852945861389488419179600933178716009889963150132778947506523961974222282461654256451508762805133855866018054403911588630700228345151
	, RSA.private_d    = 133764127300370985476360382258931504810339098611363623122953018301285450176037234703101635770582297431466449863745848961134143024057267778947569638425565153896020107107895924597628599677345887446144410702679470631826418774397895304952287674790343620803686034122942606764275835668353720152078674967983573326257
	, RSA.private_p    = 12909745499610419492560645699977670082358944785082915010582495768046269235061708286800087976003942261296869875915181420265794156699308840835123749375331319
	, RSA.private_q    = 10860278066550210927914375228722265675263011756304443428318337179619069537063135098400347475029673115805419186390580990519363257108008103841271008948795129
	, RSA.private_dP   = 5014229697614831746694710412330921341325464081424013940131184365711243776469716106024020620858146547161326009604054855316321928968077674343623831428796843
	, RSA.private_dQ   = 3095337504083058271243917403868092841421453478127022884745383831699720766632624326762288333095492075165622853999872779070009098364595318242383709601515849
	, RSA.private_qinv = 11136639099661288633118187183300604127717437440459572124866697429021958115062007251843236337586667012492941414990095176435990146486852255802952814505784196
	}

rsaPublickey = RSA.PublicKey
	{ RSA.public_size = 128
	, RSA.public_n    = 140203425894164333410594309212077886844966070748523642084363106504571537866632850620326769291612455847330220940078873180639537021888802572151020701352955762744921926221566899281852945861389488419179600933178716009889963150132778947506523961974222282461654256451508762805133855866018054403911588630700228345151
	, RSA.public_e    = 65537
	}

{-----------------------------------------------------------------------------------------------}
{- testing DSA -}
{-----------------------------------------------------------------------------------------------}


dsaParams = (p,g,q)
	where
		p = 0x00a8c44d7d0bbce69a39008948604b9c7b11951993a5a1a1fa995968da8bb27ad9101c5184bcde7c14fb79f7562a45791c3d80396cefb328e3e291932a17e22edd
		g = 0x0bf9fe6c75d2367b88912b2252d20fdcad06b3f3a234b92863a1e30a96a123afd8e8a4b1dd953e6f5583ef8e48fc7f47a6a1c8f24184c76dba577f0fec2fcd1c
		q = 0x0096674b70ef58beaaab6743d6af16bb862d18d119

dsaPrivatekey = DSA.PrivateKey
	{ DSA.private_params = dsaParams
	, DSA.private_x      = 0x229bac7aa1c7db8121bfc050a3426eceae23fae8
	}

dsaPublickey = DSA.PublicKey
	{ DSA.public_params = dsaParams
	, DSA.public_y      = 0x4fa505e86e32922f1fa1702a120abdba088bb4be801d4c44f7fc6b9094d85cd52c429cbc2b39514e30909b31e2e2e0752b0fc05c1a7d9c05c3e52e49e6edef4c
	}

prop_dsa_valid (RSAMessage msg) =
	case DSA.verify signature (SHA1.hash) dsaPublickey msg of
		Left err -> False
		Right b  -> b
	where
		Right (signature, rng') = DSA.sign rng (SHA1.hash) dsaPrivatekey msg

{-----------------------------------------------------------------------------------------------}
{- testing DH -}
{-----------------------------------------------------------------------------------------------}
instance Arbitrary DH.PrivateNumber where
	arbitrary = fromIntegral <$> (suchThat (arbitrary :: Gen Integer) (\x -> x >= 1))

prop_dh_valid (xa, xb) = sa == sb
	where
		sa = DH.getShared dhparams xa yb
		sb = DH.getShared dhparams xb ya
		yb = DH.generatePublic dhparams xb
		ya = DH.generatePublic dhparams xa
		dhparams = (11, 7)

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


prop_ecb_valid k msg = AES.decrypt k (AES.encrypt k msg) == msg
prop_cbc_valid k iv msg = AES.decryptCBC k iv (AES.encryptCBC k iv msg) == msg

prop_aes128_ecb_valid (AES128Message key _ msg) =
	let (Right k) = AES.initKey128 key in
	prop_ecb_valid k msg

prop_aes192_ecb_valid (AES192Message key _ msg) =
	let (Right k) = AES.initKey192 key in
	prop_ecb_valid k msg

prop_aes256_ecb_valid (AES256Message key _ msg) =
	let (Right k) = AES.initKey256 key in
	prop_ecb_valid k msg

prop_aes128_cbc_valid (AES128Message key iv msg) =
	let (Right k) = AES.initKey128 key in
	prop_cbc_valid k iv msg

prop_aes192_cbc_valid (AES192Message key iv msg) =
	let (Right k) = AES.initKey192 key in
	prop_cbc_valid k iv msg

prop_aes256_cbc_valid (AES256Message key iv msg) =
	let (Right k) = AES.initKey256 key in
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

asymEncryptionTests = testGroup "assymmetric cipher encryption"
	[ testProperty "RSA (slow)" prop_rsa_slow_valid
	, testProperty "RSA (fast)" prop_rsa_fast_valid
	]

asymSignatureTests = testGroup "assymmetric cipher signature"
	[ testProperty "RSA (slow)" prop_rsa_sign_slow_valid
	, testProperty "RSA (fast)" prop_rsa_sign_fast_valid
	, testProperty "DSA" prop_dsa_valid
	]

asymOtherTests = testGroup "assymetric other tests"
	[ testProperty "DH valid" prop_dh_valid
	]

arithmeticTests = testGroup "arithmetic"
	[]

{- run_test "RSA generate" prop_rsa_generate_valid -}

tests :: [Test]
tests =
	[ symCipherExpectedTests
	, symCipherMarshallTests
	, arithmeticTests
	, asymEncryptionTests
	, asymSignatureTests
	, asymOtherTests
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
