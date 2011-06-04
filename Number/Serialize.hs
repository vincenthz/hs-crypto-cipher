module Number.Serialize
	( i2osp
	, os2ip
	, lengthBytes
	) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Bits

-- | os2ip converts a byte string into a positive integer
os2ip :: ByteString -> Integer
os2ip = B.foldl' (\a b -> (256 * a) .|. (fromIntegral b)) 0

-- | i2osp converts a positive integer into a byte string
i2osp :: Integer -> ByteString
i2osp m = B.reverse $ B.unfoldr divMod256 m
	where
		divMod256 0 = Nothing
		divMod256 n = Just (fromIntegral a,b) where (b,a) = n `divMod` 256

-- | returns the number of bytes to store an integer with i2osp
lengthBytes :: Integer -> Int
lengthBytes n
	| n < 256   = 1
	| otherwise = 1 + lengthBytes (n `div` 256)
