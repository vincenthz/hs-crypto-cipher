{-# LANGUAGE BangPatterns #-}
module Number.ModArithmetic
	( exponantiation_rtl_binary
	, inverse
	, gcde_binary
	) where

import Data.Bits

-- note on exponantiation: 0^0 is treated as 1 for mimicking the standard library;
-- the mathematic debate is still open on whether or not this is true, but pratically
-- in computer science it shouldn't be useful for anything anyway.

-- | exponantiation_rtl_binary computes modular exponantiation as b^e mod m
-- using the right-to-left binary exponentiation algorithm (HAC 14.79)
exponantiation_rtl_binary :: Integer -> Integer -> Integer -> Integer
exponantiation_rtl_binary 0 0 m = 1 `mod` m
exponantiation_rtl_binary b e m = loop e b 1
	where
		sq x          = (x * x) `mod` m
		loop !0 _  !a = a `mod` m
		loop !i !s !a = loop (i `shiftR` 1) (sq s) (if odd i then a * s else a)

-- | inverse computes the modular inverse as in g^(-1) mod m
inverse :: Integer -> Integer -> Maybe Integer
inverse g m = if d > 1 then Nothing else Just x
	where (x,_,d) = gcde_binary g m

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

areEven :: [Integer] -> Bool
areEven = and . map even
