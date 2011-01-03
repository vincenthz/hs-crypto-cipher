-- |
-- Module      : Crypto.Cipher.DSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--

module Crypto.Cipher.DSA
	( Error(..)
	, PublicKey(..)
	, PrivateKey(..)
	, sign
	, verify
	) where

import Control.Arrow (first)
import Crypto.Random
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Number.ModArithmetic (exponantiation_rtl_binary)

data Error = 
	  KeyInternalError
	deriving (Show,Eq)

type DSAparams = (Integer,Integer,Integer) {- P, G, Q -}

data PublicKey = PublicKey
	{ public_params :: DSAparams {- P, G, Q -}
	, public_y      :: Integer
	} deriving (Show)

data PrivateKey = PrivateKey
	{ private_params :: DSAparams {- P, G, Q -}
	, private_x      :: Integer
	} deriving (Show)

{-| sign message using the private key. -}
sign :: CryptoRandomGen g => g -> PrivateKey -> ByteString -> Either Error (ByteString, g)
sign rng pk c = undefined
{-
	Let H be the hashing function and m the message:
	- Generate a random per-message value k where 0 < k < q
	- Calculate r = (g^k mod p) mod q
	- Calculate s = (k^(−1) (H(m) + x*r)) mod q
	- Recalculate the signature in the unlikely case that r = 0 or s = 0
	- The signature is (r, s)
-}

{- | verify a bytestring using the public key. -}
verify :: PublicKey -> ByteString -> Either Error (ByteString, g)
verify pk m = undefined
{-
	- Reject the signature if either 0 < r <q or 0 < s < q is not satisfied.
	- Calculate w = (s)−1 mod q
	- Calculate u1 = (H(m)*w) mod q
	- Calculate u2 = (r*w) mod q
	- Calculate v = ((g^u1*y^u2) mod p) mod q
	- The signature is valid if v = r
-}
