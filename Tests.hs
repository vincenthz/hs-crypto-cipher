{-# LANGUAGE OverloadedStrings #-}

import Test.HUnit ((~:), (~=?))
import qualified Test.HUnit as Unit

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
import Number.ModArithmetic
import Number.Basic
import Number.Prime
import Number.Serialize
-- ciphers/Kexch
import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Cipher.RC4 as RC4
import qualified Crypto.Cipher.Camellia as Camellia
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA
import qualified Crypto.Cipher.DH as DH
import Crypto.Random

encryptStream fi fc key plaintext = B.unpack $ snd $ fc (fi key) plaintext

encryptBlock fi fc key plaintext =
	let e = fi (B.pack key) in
	case e of
		Right k -> B.unpack $ fc k plaintext
		Left  e -> error e

wordify :: [Char] -> [Word8]
wordify = map (toEnum . fromEnum)

vectors_aes128_enc =
	[
	  ( [0x10, 0xa5, 0x88, 0x69, 0xd7, 0x4b, 0xe5, 0xa3,0x74,0xcf,0x86,0x7c,0xfb,0x47,0x38,0x59]
	  , B.replicate 16 0
	  , [0x6d,0x25,0x1e,0x69,0x44,0xb0,0x51,0xe0,0x4e,0xaa,0x6f,0xb4,0xdb,0xf7,0x84,0x65]
	  )
	, ( replicate 16 0
	  , B.replicate 16 0
	  , [0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e]
	  )
	, ( replicate 16 0
	  , B.replicate 16 1
	  , [0xe1,0x4d,0x5d,0x0e,0xe2,0x77,0x15,0xdf,0x08,0xb4,0x15,0x2b,0xa2,0x3d,0xa8,0xe0]
	  )
	, ( replicate 16 1
	  , B.replicate 16 2
	  , [0x17,0xd6,0x14,0xf3,0x79,0xa9,0x35,0x90,0x77,0xe9,0x55,0x77,0xfd,0x31,0xc2,0x0a]
	  )
	, ( replicate 16 2
	  , B.replicate 16 1
	  , [0x8f,0x42,0xc2,0x4b,0xee,0x6e,0x63,0x47,0x2b,0x16,0x5a,0xa9,0x41,0x31,0x2f,0x7c]
	  )
	, ( replicate 16 3
	  , B.replicate 16 2
	  , [0x90,0x98,0x85,0xe4,0x77,0xbc,0x20,0xf5,0x8a,0x66,0x97,0x1d,0xa0,0xbc,0x75,0xe3]
	  )
	]

vectors_aes192_enc =
	[
	  ( replicate 24 0
	  , B.replicate 16 0
	  , [0xaa,0xe0,0x69,0x92,0xac,0xbf,0x52,0xa3,0xe8,0xf4,0xa9,0x6e,0xc9,0x30,0x0b,0xd7]
	  )
	, ( replicate 24 0
	  , B.replicate 16 1
	  , [0xcf,0x1e,0xce,0x3c,0x44,0xb0,0x78,0xfb,0x27,0xcb,0x0a,0x3e,0x07,0x1b,0x08,0x20]
	  )
	, ( replicate 24 1
	  , B.replicate 16 2
	  , [0xeb,0x8c,0x17,0x30,0x90,0xc7,0x5b,0x77,0xd6,0x72,0xb4,0x57,0xa7,0x78,0xd9,0xd0]
	  )
	, ( replicate 24 2
	  , B.replicate 16 1
	  , [0xf2,0xf0,0xae,0xd8,0xcd,0xc9,0x21,0xca,0x4b,0x55,0x84,0x5d,0xa4,0x15,0x21,0xc2]
	  )
	, ( replicate 24 3
	  , B.replicate 16 2
	  , [0xca,0xcc,0x30,0x79,0xe4,0xb7,0x95,0x27,0x63,0xd2,0x55,0xd6,0x34,0x10,0x46,0x14]
	  )
	]

vectors_aes256_enc =
	[ ( replicate 32 0
	  , B.replicate 16 0
	  , [0xdc,0x95,0xc0,0x78,0xa2,0x40,0x89,0x89,0xad,0x48,0xa2,0x14,0x92,0x84,0x20,0x87]
	  )
	, ( replicate 32 0
	  , B.replicate 16 1
	  , [0x7b,0xc3,0x02,0x6c,0xd7,0x37,0x10,0x3e,0x62,0x90,0x2b,0xcd,0x18,0xfb,0x01,0x63]
	  )
	, ( replicate 32 1
	  , B.replicate 16 2
	  , [0x62,0xae,0x12,0xf3,0x24,0xbf,0xea,0x08,0xd5,0xf6,0x75,0xb5,0x13,0x02,0x6b,0xbf]
	  )
	, ( replicate 32 2
	  , B.replicate 16 1
	  , [0x00,0xf9,0xc7,0x44,0x4b,0xb0,0xcc,0x80,0x6c,0x7c,0x39,0xee,0x22,0x11,0xf1,0x46]
	  )
	, ( replicate 32 3
	  , B.replicate 16 2
	  , [0xb4,0x05,0x87,0x3e,0xa0,0x76,0x1b,0x9c,0xa9,0x9f,0x70,0xb0,0x16,0x16,0xce,0xb1]
	  )
	]

vectors_aes128_dec =
	[ ( replicate 16 0
	  , B.replicate 16 0
	  , [0x14,0x0f,0x0f,0x10,0x11,0xb5,0x22,0x3d,0x79,0x58,0x77,0x17,0xff,0xd9,0xec,0x3a]
	  )
	, ( replicate 16 0
	  , B.replicate 16 1
	  , [0x15,0x6d,0x0f,0x85,0x75,0xd5,0x33,0x07,0x52,0xf8,0x4a,0xf2,0x72,0xff,0x30,0x50]
	  )
	, ( replicate 16 1
	  , B.replicate 16 2
	  , [0x34,0x37,0xd6,0xe2,0x31,0xd7,0x02,0x41,0x9b,0x51,0xb4,0x94,0x72,0x71,0xb6,0x11]
	  )
	, ( replicate 16 2
	  , B.replicate 16 1
	  , [0xe3,0xcd,0xe2,0x37,0xc8,0xf2,0xd9,0x7b,0x8d,0x79,0xf9,0x17,0x1d,0x4b,0xda,0xc1]
	  )
	, ( replicate 16 3
	  , B.replicate 16 2
	  , [0x5b,0x94,0xaa,0xed,0xd7,0x83,0x99,0x8c,0xd5,0x15,0x35,0x35,0x18,0xcc,0x45,0xe2]
	  )
	]

vectors_aes192_dec =
	[
	  ( replicate 24 0
	  , B.replicate 16 0
	  , [0x13,0x46,0x0e,0x87,0xa8,0xfc,0x02,0x3e,0xf2,0x50,0x1a,0xfe,0x7f,0xf5,0x1c,0x51]
	  )
	, ( replicate 24 0
	  , B.replicate 16 1
	  , [0x92,0x17,0x07,0xc3,0x3d,0x1c,0xc5,0x96,0x7d,0xa5,0x1d,0xbb,0xb0,0x66,0xb2,0x6c]
	  )
	, ( replicate 24 1
	  , B.replicate 16 2
	  , [0xee,0x92,0x97,0xc6,0xba,0xe8,0x26,0x4d,0xff,0x08,0x0e,0xbb,0x1e,0x74,0x11,0xc1]
	  )
	, ( replicate 24 2
	  , B.replicate 16 1
	  , [0x49,0x67,0xdf,0x70,0xd2,0x9e,0x9a,0x7f,0x5d,0x7c,0xb9,0xc1,0x20,0xc3,0x8a,0x71]
	  )
	, ( replicate 24 3
	  , B.replicate 16 2
	  , [0x74,0x38,0x62,0x42,0x6b,0x56,0x7f,0xd5,0xf0,0x1d,0x1b,0x59,0x56,0x01,0x26,0x29]
	  )
	]

vectors_aes256_dec =
	[ ( replicate 32 0
	  , B.replicate 16 0
	  , [0x67,0x67,0x1c,0xe1,0xfa,0x91,0xdd,0xeb,0x0f,0x8f,0xbb,0xb3,0x66,0xb5,0x31,0xb4]
	  )
	, ( replicate 32 0
	  , B.replicate 16 1
	  , [0xcc,0x09,0x21,0xa3,0xc5,0xca,0x17,0xf7,0x48,0xb7,0xc2,0x7b,0x73,0xba,0x87,0xa2]
	  )
	, ( replicate 32 1
	  , B.replicate 16 2
	  , [0xc0,0x4b,0x27,0x90,0x1a,0x50,0xcf,0xfa,0xf1,0xbb,0x88,0x9f,0xc0,0x92,0x5e,0x14]
	  )
	, ( replicate 32 2
	  , B.replicate 16 1
	  , [0x24,0x61,0x53,0x5d,0x16,0x1c,0x15,0x39,0x88,0x32,0x77,0x29,0xc5,0x8c,0xc0,0x3a]
	  )
	, ( replicate 32 3
	  , B.replicate 16 2
	  , [0x30,0xc9,0x1c,0xce,0xfe,0x89,0x30,0xcf,0xff,0x31,0xdb,0xcc,0xfc,0x11,0xc5,0x23]
	  )
	]

aes128InitKey = AES.initKey128
aes192InitKey = AES.initKey192
aes256InitKey = AES.initKey256

vectors_rc4 =
	[ (wordify "Key", "Plaintext", [ 0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3 ])
	, (wordify "Wiki", "pedia", [ 0x10,0x21,0xBF,0x04,0x20 ])
	, (wordify "Secret", "Attack at dawn", [ 0x45,0xA0,0x1F,0x64,0x5F,0xC3,0x5B,0x38,0x35,0x52,0x54,0x4B,0x9B,0xF5 ])
	]

vectors_camellia128 =
	[ 
	  ( replicate 16 0
	  , B.replicate 16 0
	  , [0x3d,0x02,0x80,0x25,0xb1,0x56,0x32,0x7c,0x17,0xf7,0x62,0xc1,0xf2,0xcb,0xca,0x71]
	  )
	, ( [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]
	  , B.pack [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]
	  , [0x67,0x67,0x31,0x38,0x54,0x96,0x69,0x73,0x08,0x57,0x06,0x56,0x48,0xea,0xbe,0x43]
	  )
	]

vectors_camellia192 =
	[
	  ( [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77]
	  , B.pack [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]
	  ,[0xb4,0x99,0x34,0x01,0xb3,0xe9,0x96,0xf8,0x4e,0xe5,0xce,0xe7,0xd7,0x9b,0x09,0xb9]
	  )
	]

vectors_camellia256 =
	[
	  ( [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
	    ,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff]
	  , B.pack [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10]
	  , [0x9a,0xcc,0x23,0x7d,0xff,0x16,0xd7,0x6c,0x20,0xef,0x7c,0x91,0x9e,0x3a,0x75,0x09]
	  )
	]

vectors =
	[ ("RC4",        vectors_rc4,         encryptStream RC4.initCtx RC4.encrypt)
	, ("AES128 Enc", vectors_aes128_enc,  encryptBlock aes128InitKey AES.encrypt)
	, ("AES192 Enc", vectors_aes192_enc,  encryptBlock aes192InitKey AES.encrypt)
	, ("AES256 Enc", vectors_aes256_enc,  encryptBlock aes256InitKey AES.encrypt)
	, ("AES128 Dec", vectors_aes128_dec,  encryptBlock aes128InitKey AES.decrypt)
	, ("AES192 Dec", vectors_aes192_dec,  encryptBlock aes192InitKey AES.decrypt)
	, ("AES256 Dec", vectors_aes256_dec,  encryptBlock aes256InitKey AES.decrypt)
	, ("Camellia",   vectors_camellia128, encryptBlock Camellia.initKey Camellia.encrypt)
	]

utests :: [Unit.Test]
utests = concatMap (\(name, v, f) -> map (\(k,p,e) -> name ~: name ~: e ~=? f k p) v) vectors

{- end of units tests -}
{- start of QuickCheck verification -}

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
		i = os2ip bs

rng = Rng (1,2) 

{-----------------------------------------------------------------------------------------------}
{- testing RSA -}
{-----------------------------------------------------------------------------------------------}

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
	{ RSA.private_sz   = 128
	, RSA.private_n    = 140203425894164333410594309212077886844966070748523642084363106504571537866632850620326769291612455847330220940078873180639537021888802572151020701352955762744921926221566899281852945861389488419179600933178716009889963150132778947506523961974222282461654256451508762805133855866018054403911588630700228345151
	, RSA.private_d    = 133764127300370985476360382258931504810339098611363623122953018301285450176037234703101635770582297431466449863745848961134143024057267778947569638425565153896020107107895924597628599677345887446144410702679470631826418774397895304952287674790343620803686034122942606764275835668353720152078674967983573326257
	, RSA.private_p    = 12909745499610419492560645699977670082358944785082915010582495768046269235061708286800087976003942261296869875915181420265794156699308840835123749375331319
	, RSA.private_q    = 10860278066550210927914375228722265675263011756304443428318337179619069537063135098400347475029673115805419186390580990519363257108008103841271008948795129
	, RSA.private_dP   = 5014229697614831746694710412330921341325464081424013940131184365711243776469716106024020620858146547161326009604054855316321928968077674343623831428796843
	, RSA.private_dQ   = 3095337504083058271243917403868092841421453478127022884745383831699720766632624326762288333095492075165622853999872779070009098364595318242383709601515849
	, RSA.private_qinv = 11136639099661288633118187183300604127717437440459572124866697429021958115062007251843236337586667012492941414990095176435990146486852255802952814505784196
	}

rsaPublickey = RSA.PublicKey
	{ RSA.public_sz = 128
	, RSA.public_n  = 140203425894164333410594309212077886844966070748523642084363106504571537866632850620326769291612455847330220940078873180639537021888802572151020701352955762744921926221566899281852945861389488419179600933178716009889963150132778947506523961974222282461654256451508762805133855866018054403911588630700228345151
	, RSA.public_e  = 65537
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

args = stdArgs
	{ replay     = Nothing
	, maxSuccess = 200
	, maxDiscard = 1000
	, maxSize    = 200
	}

run_test n t = putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith args t

main = do
	Unit.runTestTT (Unit.TestList utests)

	-- Number Tests
	run_test "gcde binary valid" prop_gcde_binary_valid
	run_test "exponantiation RTL valid" prop_modexp_rtl_valid
	run_test "inverse valid" prop_modinv_valid
	run_test "sqrt integer valid" prop_sqrti_valid
	run_test "primality test Miller Rabin" prop_miller_rabin_valid
	run_test "Generate prime" prop_generate_prime_valid

	-- AES Tests
	run_test "AES128 (ECB) decrypt.encrypt = id" prop_aes128_ecb_valid
	run_test "AES128 (CBC) decrypt.encrypt = id" prop_aes128_cbc_valid

	run_test "AES192 (ECB) decrypt.encrypt = id" prop_aes192_ecb_valid
	run_test "AES192 (CBC) decrypt.encrypt = id" prop_aes192_cbc_valid

	run_test "AES256 (ECB) decrypt.encrypt = id" prop_aes256_ecb_valid
	run_test "AES256 (CBC) decrypt.encrypt = id" prop_aes256_cbc_valid

	-- DH Tests
	run_test "DH test" prop_dh_valid

	-- RSA Tests
	run_test "RSA verify . sign(slow) = true" prop_rsa_sign_slow_valid
	run_test "RSA verify . sign(fast) = true" prop_rsa_sign_fast_valid

	run_test "RSA decrypt(slow).encrypt = id" prop_rsa_slow_valid
	run_test "RSA decrypt(fast).encrypt = id" prop_rsa_fast_valid

	-- DSA Tests
	run_test "DSA verify . sign = true" prop_dsa_valid
