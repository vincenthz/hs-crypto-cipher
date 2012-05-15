{-# LANGUAGE BangPatterns #-}
-- |
-- Module      : Number.ModArithmetic
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good

module Number.ModArithmetic
	( exponantiation_rtl_binary
	, exponantiation
	, multiplication
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

-- | exponantiation computes modular exponantiation as b^e mod m
-- using repetitive squaring.
exponantiation :: Integer -> Integer -> Integer -> Integer
exponantiation b e m
             | b == 1    = b
             | e == 0    = 1
             | e == 1    = b `mod` m
             | even e    = let p = (exponantiation b (e `div` 2) m) `mod` m
                           in  (p^(2::Integer)) `mod` m
             | otherwise = (b * exponantiation b (e-1) m) `mod` m

-- | multiply 2 integers in Zm only performing the modulo operation if necessary
multiplication :: Integer -> Integer -> Integer -> Integer
multiplication a b m
             | a == 1    = b
             | b == 1    = a
             | otherwise = (a * b) `mod` m

-- | inverse computes the modular inverse as in g^(-1) mod m
inverse :: Integer -> Integer -> Maybe Integer
inverse g m = if d > 1 then Nothing else Just (x `mod` m)
	where (x,_,d) = gcde_binary g m
