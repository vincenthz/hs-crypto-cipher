module Number.Generate
	( generateMax
	, generateBetween
	, generateOfSize
	) where

import Number.Serialize
import Crypto.Random
import qualified Data.ByteString as B
import Data.Bits ((.|.))

-- | generate a positive integer between 0 and m.
-- using as many bytes as necessary to the same size as m, that are converted to integer.
generateMax :: CryptoRandomGen g => g -> Integer -> Either GenError (Integer, g)
generateMax rng m = case genBytes (logiBytes m) rng of
	Left err         -> Left err
	Right (bs, rng') -> Right (os2ip bs `mod` m, rng')

-- | generate a number between the inclusive bound [low,high].
generateBetween :: CryptoRandomGen g => g -> Integer -> Integer -> Either GenError (Integer, g)
generateBetween rng low high = case generateMax rng (high - low + 1) of
	Left err        -> Left err
	Right (v, rng') -> Right (low + v, rng')

-- | generate a positive integer of a specific size in bits.
-- the number of bits need to be multiple of 8. It will always returns
-- an integer that is close 2^(1+bits/8) by setting the 2 highest bits to 1.
generateOfSize :: CryptoRandomGen g => g -> Int -> Either GenError (Integer, g)
generateOfSize rng bits = case genBytes (bits `div` 8) rng of
	Left err         -> Left err
	Right (bs, rng') -> Right (os2ip $ snd $ B.mapAccumL (\acc w -> (0, w .|. acc)) 0xc0 bs, rng')

logiBytes :: Integer -> Int
logiBytes n
	| n < 256   = 1
	| otherwise = 1 + logiBytes (n `div` 256)
