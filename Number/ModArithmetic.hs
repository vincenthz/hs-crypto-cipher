{-# LANGUAGE BangPatterns #-}
module Number.ModArithmetic
	( exponantiation_rtl_binary
	, inverse
	) where

import Number.Basic (gcde_binary)
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
