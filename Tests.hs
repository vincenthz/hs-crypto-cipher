{-# LANGUAGE OverloadedStrings, CPP #-}

import Test.HUnit ((~:), (~=?))
import qualified Test.HUnit as Unit

import Test.QuickCheck
import Test.QuickCheck.Test
import System.IO (hFlush, stdout)

import Control.Monad
import Control.Arrow (first)

import Data.List (intercalate)
import Data.Char
import Data.Bits
import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
-- for DSA
import qualified Crypto.Hash.SHA1 as SHA1

-- numbers
import Number.ModArithmetic
-- ciphers
import qualified Crypto.Cipher.RC4 as RC4
import qualified Crypto.Cipher.Camellia as Camellia
import qualified Crypto.Cipher.RSA as RSA
import qualified Crypto.Cipher.DSA as DSA
import Crypto.Random

encryptStream fi fc key plaintext = B.unpack $ snd $ fc (fi key) plaintext

encryptBlock fi fc key plaintext =
	let e = fi key in
	case e of
		Right k -> B.unpack $ fc k plaintext
		Left  e -> error e

wordify :: [Char] -> [Word8]
wordify = map (toEnum . fromEnum)

vectors_rc4 =
	[ (wordify "Key", "Plaintext", [ 0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3 ])
	, (wordify "Wiki", "pedia", [ 0x10,0x21,0xBF,0x04,0x20 ])
	, (wordify "Secret", "Attack at dawn", [ 0x45,0xA0,0x1F,0x64,0x5F,0xC3,0x5B,0x38,0x35,0x52,0x54,0x4B,0x9B,0xF5 ])
	]

vectors_camellia128 =
	[ 
	  ( [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
	  , B.pack [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
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
	[ ("RC4",      vectors_rc4,         encryptStream RC4.initCtx RC4.encrypt)
	, ("Camellia", vectors_camellia128, encryptBlock Camellia.initKey Camellia.encrypt)
	]

utests :: [Unit.Test]
utests = concatMap (\(name, v, f) -> map (\(k,p,e) -> name ~: name ~: e ~=? f k p) v) vectors

{- end of units tests -}
{- start of QuickCheck verification -}

-- FIXME better to tweak the property to generate positive integer instead of this.

prop_gcde_binary_valid (a, b)
	| a > 0 && b >= 0 =
		let (x,y,v) = gcde_binary a b in
		and [a*x + b*y == v, gcd a b == v]
	| otherwise          = True

prop_modexp_rtl_valid (a, b, m)
	| m > 0 && a >= 0 && b >= 0 = exponantiation_rtl_binary a b m == ((a ^ b) `mod` m)
	| otherwise                 = True

prop_modinv_valid (a, m)
	| m > 1 && a > 0 =
		case inverse a m of
			Just ainv -> (ainv * a) `mod` m == 1
			Nothing   -> True
	| otherwise       = True

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
	let mw2 = 18000 * (mw `mod` 65536) in
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

rng = Rng (1,2) 


prop_rsa_fast_valid (RSAMessage msg) =
	(either Left (RSA.decrypt rsaPrivatekey . fst) $ RSA.encrypt rng rsaPublickey msg) == Right msg

prop_rsa_slow_valid (RSAMessage msg) =
	(either Left (RSA.decrypt pk . fst) $ RSA.encrypt rng rsaPublickey msg) == Right msg
	where pk = rsaPrivatekey { RSA.private_p = 0, RSA.private_q = 0 }

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
{- main -}
{-----------------------------------------------------------------------------------------------}

args = Args
	{ replay     = Nothing
	, maxSuccess = 1000
	, maxDiscard = 4000
	, maxSize    = 1000
#if MIN_VERSION_QuickCheck(2,3,0)
	, chatty     = True
#endif
	}

run_test n t = putStr ("  " ++ n ++ " ... ") >> hFlush stdout >> quickCheckWith args t

main = do
	Unit.runTestTT (Unit.TestList utests)

	run_test "gcde binary valid" prop_gcde_binary_valid
	run_test "exponantiation RTL valid" prop_modexp_rtl_valid
	run_test "inverse valid" prop_modinv_valid

	run_test "RSA decrypt(slow).encrypt = id" prop_rsa_slow_valid
	run_test "RSA decrypt(fast).encrypt = id" prop_rsa_fast_valid

	run_test "DSA verify . sign = valid" prop_dsa_valid
