{-# LANGUAGE BangPatterns #-}
module Number.Basic
	(
	  gcde_binary
	, areEven
	) where

import Data.Bits

-- | get the extended GCD of two integer using the extended binary algorithm (HAC 14.61)
-- get (x,y,d) where d = gcd(a,b) and x,y satisfying ax + by = d
gcde_binary :: Integer -> Integer -> (Integer, Integer, Integer)
gcde_binary a' b'
	| b' == 0   = (1,0,a')
	| a' >= b'  = compute a' b'
	| otherwise = (\(x,y,d) -> (y,x,d)) $ compute b' a'
	where
		getEvenMultiplier !g !x !y
			| areEven [x,y] = getEvenMultiplier (g `shiftL` 1) (x `shiftR` 1) (y `shiftR` 1)
			| otherwise     = (x,y,g)
		halfLoop !x !y !u !i !j
			| areEven [u,i,j] = halfLoop x y (u `shiftR` 1) (i `shiftR` 1) (j `shiftR` 1)
			| even u          = halfLoop x y (u `shiftR` 1) ((i + y) `shiftR` 1) ((j - x) `shiftR` 1)
			| otherwise       = (u, i, j)
		compute a b =
			let (x,y,g) = getEvenMultiplier 1 a b in
			loop g x y x y 1 0 0 1

		loop g _ _ 0  !v _  _  !c !d = (c, d, g * v)
		loop g x y !u !v !a !b !c !d =
			let (u2,a2,b2) = halfLoop x y u a b in
			let (v2,c2,d2) = halfLoop x y v c d in
			if u2 >= v2
				then loop g x y (u2 - v2) v2 (a2 - c2) (b2 - d2) c2 d2
				else loop g x y u2 (v2 - u2) a2 b2 (c2 - a2) (d2 - b2)

-- | check if a list of integer are all even
areEven :: [Integer] -> Bool
areEven = and . map even
