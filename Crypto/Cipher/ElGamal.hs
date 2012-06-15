-- |
-- Module      : Crypto.Cipher.ElGamal
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- This module is a work in progress. do not use:
-- it might eat your dog, your data or even both.
--
-- TODO: provide a mapping between integer and ciphertext
--       generate numbers correctly
--
module Crypto.Cipher.ElGamal
	( Params
	, PublicNumber
	, PrivateNumber
	, SharedKey
    , generatePrivate
    , generatePublic
    , encryptWith
    , encrypt
    , decrypt
{-
    , sign
    , verify
-}
    ) where

import Number.ModArithmetic (exponantiation, inverse)
import Number.Generate (generateOfSize)
import Crypto.Types.PubKey.DH
import Crypto.Random
import Control.Arrow (first)
import Control.Applicative ((<$>))
import Data.Maybe (fromJust)

-- | generate a private number with no specific property
-- this number is usually called a.
-- 
-- FIXME replace generateOfSize by generateBetween [0, q-1]
generatePrivate :: CryptoRandomGen g => g -> Int -> Either GenError (PrivateNumber, g)
generatePrivate rng bits = either Left (Right . first PrivateNumber) $ generateOfSize rng bits

-- | generate a public number that is for the other party benefits.
-- this number is usually called h=g^a
generatePublic :: Params -> PrivateNumber -> PublicNumber
generatePublic (p,g) (PrivateNumber a) = PublicNumber $ exponantiation g a p

-- | encrypt with a specified ephemeral key
-- do not reuse ephemeral key.
encryptWith :: PrivateNumber -> Params -> PublicNumber -> Integer -> (Integer,Integer)
encryptWith (PrivateNumber b) (p,g) (PublicNumber h) m = (c1,c2)
    where s  = exponantiation h b p
          c1 = exponantiation g b p
          c2 = (s * m) `mod` p

-- | encrypt a message using params and public keys
-- will generate b (called the ephemeral key)
encrypt :: CryptoRandomGen g => g -> Params -> PublicNumber -> Integer -> Either GenError ((Integer,Integer), g)
encrypt rng params public m = (\(b,rng') -> (encryptWith b params public m,rng')) <$> generatePrivate rng 1024

-- | decrypt message
decrypt :: Params -> PrivateNumber -> (Integer, Integer) -> Integer
decrypt (p,_) (PrivateNumber a) (c1,c2) = (c2 * sm1) `mod` p
    where s   = exponantiation c1 a p
          sm1 = fromJust $ inverse s p -- always inversible in Zp

{-
sign = undefined

verify = undefined
-}
