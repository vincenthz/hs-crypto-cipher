module Number.Generate
	( generateMax
	, generateOfSize
	) where

import Number.Serialize
import Crypto.Random
import qualified Data.ByteString as B

{- a bit too simplitic and probably not very good. need to have a serious look
 - on how to generate random integer. -}
generateMax :: CryptoRandomGen g => g -> Integer -> Either GenError (Integer, g)
generateMax rng m =
	let nbbytes = nbBytes m in
	case genBytes nbbytes rng of
		Left err         -> Left err
		Right (bs, rng') ->
			let n = os2ip bs in
			if n < m then Right (n, rng') else generateMax rng' m

-- | generate a positive integer of a specific size in bits.
-- the number of bits need to be multiple of 8. It will always returns
-- an integer that is close 2^(1+bits/8) by setting the 2 highest bits to 1.
generateOfSize :: CryptoRandomGen g => g -> Int -> Either GenError (Integer, g)
generateOfSize rng bits = case genBytes (bits `div` 8) rng of
	Left err         -> Left err
	Right (bs, rng') -> Right (os2ip $ snd $ B.mapAccumL (\acc w -> (0, w .|. acc)) 0xc0 bs, rng')

nbBytes :: Integer -> Int
nbBytes n
	| n < 256   = 1
	| otherwise = 1 + nbBytes (n `div` 256)
