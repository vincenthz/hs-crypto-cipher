{-# LANGUAGE OverloadedStrings #-}

import Test.HUnit ((~:), (~=?))
import qualified Test.HUnit as Unit
import Data.Char
import Data.Bits
import Data.Word
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import qualified Crypto.Cipher.RC4 as RC4
import qualified Crypto.Cipher.Camellia as Camellia

{- CAMELLIA test vectors -}
{-
   Here are test data for Camellia in hexadecimal form.

   128-bit key
       Key       : 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
       Plaintext : 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
       Ciphertext: 67 67 31 38 54 96 69 73 08 57 06 56 48 ea be 43

   192-bit key
       Key       : 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
                 : 00 11 22 33 44 55 66 77
       Plaintext : 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
       Ciphertext: b4 99 34 01 b3 e9 96 f8 4e e5 ce e7 d7 9b 09 b9

   256-bit key
       Key       : 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
                 : 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
       Plaintext : 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
       Ciphertext: 9a cc 23 7d ff 16 d7 6c 20 ef 7c 91 9e 3a 75 09
-}

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
	  ([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	   B.pack [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
	   [0x3d,0x02,0x80,0x25,0xb1,0x56,0x32,0x7c,0x17,0xf7,0x62,0xc1,0xf2,0xcb,0xca,0x71]),
	  ([0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10],
	   B.pack [0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10],
           [0x67,0x67,0x31,0x38,0x54,0x96,0x69,0x73,0x08,0x57,0x06,0x56,0x48,0xea,0xbe,0x43])
	]

vectors =
	[ ("RC4",      vectors_rc4,         encryptStream RC4.initCtx RC4.encrypt)
	, ("Camellia", vectors_camellia128, encryptBlock Camellia.initKey Camellia.encrypt)
	]

utests :: [Unit.Test]
utests = concatMap (\(name, v, f) -> map (\(k,p,e) -> name ~: name ~: e ~=? f k p) v) vectors

main = Unit.runTestTT (Unit.TestList utests)
