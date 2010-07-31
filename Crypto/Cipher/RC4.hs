-- |
-- Module      : Crypto.Cipher.RC4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--

module Crypto.Cipher.RC4 (
	Ctx,
	initCtx,
	encrypt,
	decrypt,
	encryptlazy,
	decryptlazy
	) where

import Data.Vector.Unboxed
import Data.Bits (xor)
import Data.Word
import Control.Arrow (second)
import Data.Maybe (fromJust)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Prelude hiding (length)

type Ctx = (Vector Word8, Word8, Word8)

swap :: Vector Word8 -> Int -> Int -> Vector Word8
swap arr x y
	| x == y    = arr
	| otherwise = arr // [(x, arr ! y), (y, arr ! x)]

setKey :: Vector Word8 -> Int -> Word8 -> Int -> Vector Word8 -> Vector Word8
setKey _   _  _  256 arr = arr
setKey key ki si i   arr = setKey key ki' si' (i + 1) (swap arr (fromIntegral si') i)
	where
		si' = si + (key ! ki) + (arr ! i)
		ki' = (ki + 1) `mod` (length key)

{- | initCtx initialize the Ctx with the key as parameter.
   the key can be of any size but not empty -}
initCtx :: [Word8] -> Ctx
initCtx key = (setKey (fromList key) 0 0 0 initialArray, 0, 0)
	where
		initialArray = generate 256 (\i -> fromIntegral i)

getNextChar :: Ctx -> (Word8, Ctx)
getNextChar (arr, x, y) = (c, (na, x', y'))
	where
		na = swap arr (fromIntegral x') (fromIntegral y')
		x' = x + 1
		y' = sx + y
		sx = arr ! (fromIntegral x')
		c  = na ! (fromIntegral (sx + (arr ! (fromIntegral y'))))

genstream :: Ctx -> Int -> (B.ByteString, Ctx)
genstream ctx len = second fromJust $ B.unfoldrN len (\c -> Just $ getNextChar c) ctx

{- | encrypt with the current context a bytestring and returns a new context
   and the resulted encrypted bytestring -}
encrypt :: Ctx -> B.ByteString -> (Ctx, B.ByteString)
encrypt ctx d = (ctx', B.pack $ B.zipWith xor d rc4stream)
	where
		(rc4stream, ctx') = genstream ctx (B.length d)

{- | decrypt with the current context a bytestring and returns a new context
   and the resulted decrypted bytestring -}
decrypt :: Ctx -> B.ByteString -> (Ctx, B.ByteString)
decrypt = encrypt

{- | encrypt with the current context a lazy bytestring and returns a new context
   and the resulted lencrypted lazy bytestring -}
encryptlazy :: Ctx -> L.ByteString -> (Ctx, L.ByteString)
encryptlazy ctx d = (ctx', L.pack $ L.zipWith xor d (L.fromChunks [ rc4stream ]))
	where
		(rc4stream, ctx') = genstream ctx (fromIntegral $ L.length d)

{- | decrypt with the current context a lazy bytestring and returns a new context
   and the resulted decrypted lazy bytestring -}
decryptlazy :: Ctx -> L.ByteString -> (Ctx, L.ByteString)
decryptlazy = encryptlazy
