module Number.Generate
	( generateMax
	) where

import Number.Serialize
import Crypto.Random

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

nbBytes :: Integer -> Int
nbBytes n
	| n < 256   = 1
	| otherwise = 1 + nbBytes (n `div` 256)
