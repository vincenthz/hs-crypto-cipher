module Number.Prime
	( generatePrime
	, generateSafePrime
	, isProbablyPrime
	, findPrimeFrom
	, findPrimeFromWith
	, primalityTestNaive
	-- , primalityTestAKS
	, primalityTestMillerRabin
	, isCoprime
	) where

import Crypto.Random
import Data.Bits
import Number.Generate
import Number.Basic (sqrti, gcde_binary)
import Number.ModArithmetic (exponantiation_rtl_binary)

-- | returns if the number is probably prime.
-- first a list of small primes are implicitely tested for divisibility,
-- then the Miller Rabin algorithm is used with an accuracy of 30 recursions
isProbablyPrime :: CryptoRandomGen g => g -> Integer -> Either GenError (Bool, g)
isProbablyPrime rng n
	| any (\p -> p `divides` n) (filter (< n) smallPrimes) = Right (False, rng)
	| otherwise                                            = primalityTestMillerRabin rng 30 n

-- | generate a prime number of the required bitsize
generatePrime :: CryptoRandomGen g => g -> Int -> Either GenError (Integer, g)
generatePrime rng bits = case generateOfSize rng bits of
	Left err         -> Left err
	Right (sp, rng') -> findPrimeFrom rng' sp

-- | generate a prime number of the form 2p+1 where p is also prime.
-- it is also know as a Sophie Germaine prime or safe prime.
--
-- The number of safe prime is significantly smaller to the number of prime,
-- as such it shouldn't be used if this number is supposed to be kept safe.
generateSafePrime :: CryptoRandomGen g => g -> Int -> Either GenError (Integer, g)
generateSafePrime rng bits = case generateOfSize rng bits of
	Left err         -> Left err
	Right (sp, rng') -> case findPrimeFromWith rng' (\g i -> isProbablyPrime g (2*i+1)) (sp `div` 2) of
		Left err         -> Left err
		Right (p, rng'') -> Right (2*p+1, rng'')

-- | find a prime from a starting point where the property hold.
findPrimeFromWith :: CryptoRandomGen g => g -> (g -> Integer -> Either GenError (Bool,g)) -> Integer -> Either GenError (Integer, g)
findPrimeFromWith rng prop n
	| even n        = findPrimeFromWith rng prop (n+1)
	| otherwise     = case isProbablyPrime rng n of
		Left err               -> Left err
		Right (False, rng')    -> findPrimeFromWith rng' prop (n+2)
		Right (True, rng')     ->
			case prop rng' n of
				Left err             -> Left err
				Right (False, rng'') -> findPrimeFromWith rng'' prop (n+2)
				Right (True, rng'')  -> Right (n, rng'')

-- | find a prime from a starting point with no specific property.
findPrimeFrom :: CryptoRandomGen g => g -> Integer -> Either GenError (Integer, g)
findPrimeFrom rng n = findPrimeFromWith rng (\g _ -> Right (True, g)) n

-- | Miller Rabin algorithm return if the number is probably prime or composite.
-- the tries parameter is the number of recursion, that determines the accuracy of the test.
primalityTestMillerRabin :: CryptoRandomGen g => g -> Int -> Integer -> Either GenError (Bool, g)
primalityTestMillerRabin rng tries n
	| n <= 3     = error "Miller-Rabin requires tested value to be > 3"
	| even n     = Right (False, rng)
	| tries <= 0 = error "Miller-Rabin tries need to be > 0"
	| otherwise  = loop rng (factorise 0 (n-1)) tries where
		-- factorise n-1 into the form 2^s*d
		factorise :: Integer -> Integer -> (Integer, Integer)
		factorise s v
			| v `testBit` 0 = (s, v)
			| otherwise     = factorise (s+1) (v `shiftR` 1)
		expmod = exponantiation_rtl_binary
		-- when iteration reach zero, we have a probable prime
		loop g _     0 = Right (True, g)
		loop g (s,d) k = case generateBetween g 2 (n-2) of
			Left err      -> Left err
			Right (a, g') ->
				let x = expmod a d n in
				if x == (1 :: Integer) || x == (n-1)
					then loop g' (s,d) (k-1)
					else loop' g' (s,d) (k-1) ((x*x) `mod` n) 1
		-- loop from 1 to s-1. if we reach the end then it's composite
		loop' g o@(s,_) km1 x2 r
			| r == s      = Right (False, g)
			| x2 == 1     = Right (False, g)
			| x2 /= (n-1) = loop' g o km1 ((x2*x2) `mod` n) (r+1)
			| otherwise   = loop g o km1
			
-- | AKS primality test return if the number is prime or composite
-- it uses the following algorithm:
--   Input: integer n > 1.
--   If n = ab for integers a > 0 and b > 1, output composite.
--   Find the smallest r such that o_r(n) > log2(n).
--   If 1 < gcd(a,n) < n for some a ≤ r, output composite.
--   If n <= r, output prime.
--   For a = 1 to lower-bound(sqrt(phi(n)) * log2(n)) do
--     if (X+a)n ≠ Xn+a (mod Xr − 1,n), output composite;
--   Output prime.
primalityTestAKS :: Integer -> Bool
primalityTestAKS n = undefined
	where
		-- for p prime, the euler totient (# of coprime to n) is clearly n -1
		totient = n-1
		ubound = (fst $ sqrti totient) * (logi n)
		logi z
			| z == 0    = 0
			| otherwise = 1 + logi (z `shiftR` 1)

-- | Test naively is integer is prime.
-- while naive, we skip even number and stop iteration at i > sqrt(n)
primalityTestNaive :: Integer -> Bool
primalityTestNaive n
	| n <= 1    = False
	| n == 2    = True
	| even n    = False
	| otherwise = loop 3 where
		ubound = snd $ sqrti n
		loop i
			| i > ubound    = True
			| i `divides` n = False
			| otherwise     = loop (i+2)

-- | Test is two integer are coprime to each other
isCoprime :: Integer -> Integer -> Bool
isCoprime m n = case gcde_binary m n of (_,_,d) -> d == 1

-- | list of the first primes till 2903..
smallPrimes :: [Integer]
smallPrimes =
	[ 2    , 3    , 5    , 7    , 11   , 13   , 17   , 19   , 23   , 29
	, 31   , 37   , 41   , 43   , 47   , 53   , 59   , 61   , 67   , 71
	, 73   , 79   , 83   , 89   , 97   , 101  , 103  , 107  , 109  , 113
	, 127  , 131  , 137  , 139  , 149  , 151  , 157  , 163  , 167  , 173
	, 179  , 181  , 191  , 193  , 197  , 199  , 211  , 223  , 227  , 229
	, 233  , 239  , 241  , 251  , 257  , 263  , 269  , 271  , 277  , 281
	, 283  , 293  , 307  , 311  , 313  , 317  , 331  , 337  , 347  , 349
	, 353  , 359  , 367  , 373  , 379  , 383  , 389  , 397  , 401  , 409
	, 419  , 421  , 431  , 433  , 439  , 443  , 449  , 457  , 461  , 463
	, 467  , 479  , 487  , 491  , 499  , 503  , 509  , 521  , 523  , 541
	, 547  , 557  , 563  , 569  , 571  , 577  , 587  , 593  , 599  , 601
	, 607  , 613  , 617  , 619  , 631  , 641  , 643  , 647  , 653  , 659
	, 661  , 673  , 677  , 683  , 691  , 701  , 709  , 719  , 727  , 733
	, 739  , 743  , 751  , 757  , 761  , 769  , 773  , 787  , 797  , 809
	, 811  , 821  , 823  , 827  , 829  , 839  , 853  , 857  , 859  , 863
	, 877  , 881  , 883  , 887  , 907  , 911  , 919  , 929  , 937  , 941
	, 947  , 953  , 967  , 971  , 977  , 983  , 991  , 997  , 1009 , 1013
	, 1019 , 1021 , 1031 , 1033 , 1039 , 1049 , 1051 , 1061 , 1063 , 1069
	, 1087 , 1091 , 1093 , 1097 , 1103 , 1109 , 1117 , 1123 , 1129 , 1151
	, 1153 , 1163 , 1171 , 1181 , 1187 , 1193 , 1201 , 1213 , 1217 , 1223
	, 1229 , 1231 , 1237 , 1249 , 1259 , 1277 , 1279 , 1283 , 1289 , 1291
	, 1297 , 1301 , 1303 , 1307 , 1319 , 1321 , 1327 , 1361 , 1367 , 1373
	, 1381 , 1399 , 1409 , 1423 , 1427 , 1429 , 1433 , 1439 , 1447 , 1451
	, 1453 , 1459 , 1471 , 1481 , 1483 , 1487 , 1489 , 1493 , 1499 , 1511
	, 1523 , 1531 , 1543 , 1549 , 1553 , 1559 , 1567 , 1571 , 1579 , 1583
	, 1597 , 1601 , 1607 , 1609 , 1613 , 1619 , 1621 , 1627 , 1637 , 1657
	, 1663 , 1667 , 1669 , 1693 , 1697 , 1699 , 1709 , 1721 , 1723 , 1733
	, 1741 , 1747 , 1753 , 1759 , 1777 , 1783 , 1787 , 1789 , 1801 , 1811
	, 1823 , 1831 , 1847 , 1861 , 1867 , 1871 , 1873 , 1877 , 1879 , 1889
	, 1901 , 1907 , 1913 , 1931 , 1933 , 1949 , 1951 , 1973 , 1979 , 1987
	, 1993 , 1997 , 1999 , 2003 , 2011 , 2017 , 2027 , 2029 , 2039 , 2053
	, 2063 , 2069 , 2081 , 2083 , 2087 , 2089 , 2099 , 2111 , 2113 , 2129
	, 2131 , 2137 , 2141 , 2143 , 2153 , 2161 , 2179 , 2203 , 2207 , 2213
	, 2221 , 2237 , 2239 , 2243 , 2251 , 2267 , 2269 , 2273 , 2281 , 2287
	, 2293 , 2297 , 2309 , 2311 , 2333 , 2339 , 2341 , 2347 , 2351 , 2357
	, 2371 , 2377 , 2381 , 2383 , 2389 , 2393 , 2399 , 2411 , 2417 , 2423
	, 2437 , 2441 , 2447 , 2459 , 2467 , 2473 , 2477 , 2503 , 2521 , 2531
	, 2539 , 2543 , 2549 , 2551 , 2557 , 2579 , 2591 , 2593 , 2609 , 2617
	, 2621 , 2633 , 2647 , 2657 , 2659 , 2663 , 2671 , 2677 , 2683 , 2687
	, 2689 , 2693 , 2699 , 2707 , 2711 , 2713 , 2719 , 2729 , 2731 , 2741
	, 2749 , 2753 , 2767 , 2777 , 2789 , 2791 , 2797 , 2801 , 2803 , 2819
	, 2833 , 2837 , 2843 , 2851 , 2857 , 2861 , 2879 , 2887 , 2897 , 2903
	]

{-# INLINE divides #-}
divides :: Integer -> Integer -> Bool
divides i n = n `mod` i == 0
