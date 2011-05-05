-- |
-- Module      : Crypto.Cipher.RSA
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Cipher.RSA
	( Error(..)
	, PublicKey(..)
	, PrivateKey(..)
	, HashF
	, HashASN1
	, generate
	, decrypt
	, encrypt
	, sign
	, verify
	) where

import Control.Monad.Error ()
import Control.Arrow (first)
import Crypto.Random
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Number.ModArithmetic (exponantiation_rtl_binary, inverse)
import Number.Prime (generatePrime)
import Number.Serialize
import Data.Maybe (fromJust)

data Error =
	  MessageSizeIncorrect      -- ^ the message to decrypt is not of the correct size (need to be == private_size)
	| MessageTooLong            -- ^ the message to encrypt is too long (>= private_size - 11)
	| MessageNotRecognized      -- ^ the message decrypted doesn't have a PKCS15 structure (0 2 .. 0 msg)
	| SignatureTooLong          -- ^ the signature generated through the hash is too long to process with this key
	| RandomGenFailure GenError -- ^ the random generator returns an error. give the opportunity to reseed for example.
	| KeyInternalError          -- ^ the whole key is probably not valid, since the message is bigger than the key size
	deriving (Show,Eq)

data PublicKey = PublicKey
	{ public_sz :: Int      -- ^ size of key in bytes
	, public_n  :: Integer  -- ^ public p*q
	, public_e  :: Integer  -- ^ public exponant e
	} deriving (Show)

data PrivateKey = PrivateKey
	{ private_sz   :: Int     -- ^ size of key in bytes
	, private_n    :: Integer -- ^ private p*q
	, private_d    :: Integer -- ^ private exponant d
	, private_p    :: Integer -- ^ p prime number
	, private_q    :: Integer -- ^ q prime number
	, private_dP   :: Integer -- ^ d mod (p-1)
	, private_dQ   :: Integer -- ^ d mod (q-1)
	, private_qinv :: Integer -- ^ q^(-1) mod p
	} deriving (Show)

type HashF = ByteString -> ByteString
type HashASN1 = ByteString

padPKCS1 :: CryptoRandomGen g => g -> Int -> ByteString -> Either Error (ByteString, g)
padPKCS1 rng len m = do
	(padding, rng') <- getRandomBytes rng (len - B.length m - 3)
	return (B.concat [ B.singleton 0, B.singleton 2, padding, B.singleton 0, m ], rng')

unpadPKCS1 :: ByteString -> Either Error ByteString
unpadPKCS1 packed
	| signal_error = Left MessageNotRecognized
	| otherwise    = Right m
	where
		(zt, ps0m)   = B.splitAt 2 packed
		(ps, zm)     = B.span (/= 0) ps0m
		(z, m)       = B.splitAt 1 zm
		signal_error = (B.unpack zt /= [0, 2]) || (B.unpack z /= [0]) || (B.length ps < 8)

{- dpSlow computes the decrypted message not using any precomputed cache value.
   only n and d need to valid. -}
dpSlow :: PrivateKey -> ByteString -> Either Error ByteString
dpSlow pk c = i2ospOf (private_sz pk) $ expmod (os2ip c) (private_d pk) (private_n pk)

{- dpFast computes the decrypted message more efficiently if the
   precomputed private values are available. mod p and mod q are faster
   to compute than mod pq -}
dpFast :: PrivateKey -> ByteString -> Either Error ByteString
dpFast pk c = i2ospOf (private_sz pk) (m2 + h * (private_q pk))
	where
		iC = os2ip c
		m1 = expmod iC (private_dP pk) (private_p pk)
		m2 = expmod iC (private_dQ pk) (private_q pk)
		h  = ((private_qinv pk) * (m1 - m2)) `mod` (private_p pk)

{-| decrypt message using the private key. -}
decrypt :: PrivateKey -> ByteString -> Either Error ByteString
decrypt pk c
	| B.length c /= (private_sz pk) = Left MessageSizeIncorrect
	| otherwise                     = dp pk c >>= unpadPKCS1
		where dp = if private_p pk /= 0 && private_q pk /= 0 then dpFast else dpSlow

{- | encrypt a bytestring using the public key and a CryptoRandomGen random generator.
 - the message need to be smaller than the key size - 11
 -}
encrypt :: CryptoRandomGen g => g -> PublicKey -> ByteString -> Either Error (ByteString, g)
encrypt rng pk m
	| B.length m > public_sz pk - 11 = Left MessageTooLong
	| otherwise                      = do
		(em, rng') <- padPKCS1 rng (public_sz pk) m
		c          <- i2ospOf (public_sz pk) $ expmod (os2ip em) (public_e pk) (public_n pk)
		return (c, rng')

{-| sign message using private key, a hash and its ASN1 description -}
sign :: HashF -> HashASN1 -> PrivateKey -> ByteString -> Either Error ByteString
sign hash hashdesc pk m = makeSignature hash hashdesc (private_sz pk) m >>= d pk
	where d = if private_p pk /= 0 && private_q pk /= 0 then dpFast else dpSlow

{-| verify message with the signed message -}
verify :: HashF -> HashASN1 -> PublicKey -> ByteString -> ByteString -> Either Error Bool
verify hash hashdesc pk m sm = do
	s  <- makeSignature hash hashdesc (public_sz pk) m
	em <- i2ospOf (public_sz pk) $ expmod (os2ip sm) (public_e pk) (public_n pk)
	Right (s == em)

-- | generate a pair of (private, public) key of size in bytes.
generate :: CryptoRandomGen g => g -> Int -> Integer -> Either GenError ((PublicKey, PrivateKey), g)
generate rng size e = do
	((p,q), rng') <- generatePQ rng
	let n   = p * q
	let phi = (p-1)*(q-1)
	case inverse e phi of
		Nothing -> generate rng' size e
		Just d  -> do
			let priv = PrivateKey
				{ private_sz   = size
				, private_n    = n
				, private_d    = d
				, private_p    = p
				, private_q    = q
				, private_dP   = d `mod` (p-1)
				, private_dQ   = d `mod` (q-1)
				, private_qinv = fromJust $ inverse q p -- q and p are coprime, so fromJust is safe.
				}
			let pub = PublicKey
				{ public_sz = size
				, public_n  = n
				, public_e  = e
				}
			return ((pub, priv), rng')
	where
		generatePQ g = do
			(p, g')  <- generatePrime g (8 * (size `div` 2))
			(q, g'') <- generateQ p g'
			return ((p,q), g'')
		generateQ p h = do
			(q, h') <- generatePrime h (8 * (size - (size `div` 2)))
			if p == q then generateQ p h' else return (q, h')

{- makeSignature for sign and verify -}
makeSignature :: HashF -> HashASN1 -> Int -> ByteString -> Either Error ByteString
makeSignature hash descr klen m
	| klen < siglen+1 = Left SignatureTooLong
	| otherwise       = Right $ B.concat [B.singleton 0,B.singleton 1,padding,B.singleton 0,signature]
	where
		signature = descr `B.append` hash m
		siglen    = B.length signature
		padding   = B.replicate (klen - siglen - 3) 0xff

{- get random non-null bytes for encryption padding. -}
getRandomBytes :: CryptoRandomGen g => g -> Int -> Either Error (ByteString, g)
getRandomBytes rng n = do
	gend <- either (Left . RandomGenFailure) Right $ genBytes n rng
	let (bytes, rng') = first (B.pack . filter (/= 0) . B.unpack) gend
	let left          = (n - B.length bytes)
	if left == 0
		then return (bytes, rng')
		else getRandomBytes rng' left >>= return . first (B.append bytes)

{- convert a positive integer into a bytestring of specific size.
   if the number is too big, this will returns an error, otherwise it will pad
   the bytestring of 0 -}
i2ospOf :: Int -> Integer -> Either Error ByteString
i2ospOf len m 
	| lenbytes < len  = Right $ B.replicate (len - lenbytes) 0 `B.append` bytes
	| lenbytes == len = Right bytes
	| otherwise       = Left KeyInternalError
	where
		lenbytes = B.length bytes
		bytes    = i2osp m

expmod :: Integer -> Integer -> Integer -> Integer
expmod = exponantiation_rtl_binary
