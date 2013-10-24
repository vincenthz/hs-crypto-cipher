-- |
-- Module      : Crypto.Cipher.Types.Modes
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- block cipher modes immutable interfaces
--
module Crypto.Cipher.Types.OfIO
    (
    -- * ECB
      ecbEncryptOfIO
    , ecbDecryptOfIO
{-
    -- * CBC
    , cbcEncryptOfIO
    , cbcDecryptOfIO
    -- * CFB
    , cfbEncryptOfIO
    , cfbDecryptOfIO
    , cfb8EncryptOfIO
    , cfb8DecryptOfIO
    -- * CTR
    , ctrCombineOfIO
    -- * XTS
    , xtsEncryptOfIO
    , xtsDecryptOfIO
-}
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import Data.Byteable
--import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.Block
import Crypto.Cipher.Types.BlockIO
--import Foreign.Storable (poke)
--import Foreign.Ptr

isBlockSized :: (BlockCipher cipher, BlockCipherIO cipher) => cipher -> Int -> Bool
isBlockSized cipher bsLen = (bsLen `mod` blockSize cipher) == 0

notBlockSized :: (BlockCipher cipher, BlockCipherIO cipher) => cipher -> a
notBlockSized = undefined

withDest :: BlockCipherIO cipher
         => cipher
         -> ByteString
         -> (PtrDest -> PtrSource -> BufferLength -> IO ())
         -> ByteString
withDest cipher bs f
    | B.null bs                     = B.empty
    | not (isBlockSized cipher len) = notBlockSized cipher
    | otherwise                     =
        B.unsafeCreate len $ \dst ->
        withBytePtr bs     $ \src ->
        f dst src (fromIntegral len)
  where len = B.length bs

{-
withDestIV :: BlockCipherIO cipher
           => cipher
           -> IV cipher
           -> ByteString
           -> (PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ())
           -> ByteString
withDestIV cipher (IV iv) bs f
    | B.null bs                     = B.empty
    | not (isBlockSized cipher len) = notBlockSized cipher
    | otherwise                     =
        B.unsafeCreate len $ \dst   ->
        withBytePtr iv     $ \ivPtr ->
        withBytePtr bs     $ \src   ->
        f ivPtr dst src (fromIntegral len)
  where len = B.length bs

withDestIVAnySize :: BlockCipherIO cipher
                  => IV cipher
                  -> ByteString
                  -> (PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ())
                  -> ByteString
withDestIVAnySize (IV iv) bs f
    | B.null bs = B.empty
    | otherwise =
        B.unsafeCreate len $ \dst   ->
        withBytePtr iv     $ \ivPtr ->
        withBytePtr bs     $ \src   ->
        f ivPtr dst src (fromIntegral len)
  where len = B.length bs
-}

-- | Encrypt using the ECB mode.
--
-- input need to be a multiple of the blocksize
ecbEncryptOfIO :: BlockCipherIO cipher => cipher -> ByteString -> ByteString
ecbEncryptOfIO cipher bs = withDest cipher bs $ ecbEncryptMutable cipher

-- | Decrypt using the ECB mode.
--
-- input need to be a multiple of the blocksize
ecbDecryptOfIO :: BlockCipherIO cipher => cipher -> ByteString -> ByteString
ecbDecryptOfIO cipher bs = withDest cipher bs $ ecbEncryptMutable cipher

{-
-- | encrypt using the CBC mode.
--
-- input need to be a multiple of the blocksize
cbcEncryptOfIO :: BlockCipherIO cipher => cipher -> IV cipher -> ByteString -> ByteString
cbcEncryptOfIO cipher iv bs = withDestIV cipher iv bs $ cbcEncryptMutable cipher

-- | decrypt using the CBC mode.
--
-- input need to be a multiple of the blocksize
cbcDecryptOfIO :: BlockCipherIO cipher => cipher -> IV cipher -> ByteString -> ByteString
cbcDecryptOfIO cipher iv bs = withDestIV cipher iv bs $ cbcDecryptMutable cipher

-- | encrypt using the CFB mode.
--
-- input need to be a multiple of the blocksize
cfbEncryptOfIO :: BlockCipherIO cipher => cipher -> IV cipher -> ByteString -> ByteString
cfbEncryptOfIO cipher iv bs = withDestIV cipher iv bs $ cfbEncryptMutable cipher

-- | decrypt using the CFB mode.
--
-- input need to be a multiple of the blocksize
cfbDecryptOfIO :: BlockCipherIO cipher => cipher -> IV cipher -> ByteString -> ByteString
cfbDecryptOfIO cipher iv bs = withDestIV cipher iv bs $ cfbDecryptMutable cipher

-- | combine using the CTR mode.
--
-- CTR mode produce a stream of randomized data that is combined
-- (by XOR operation) with the input stream.
--
-- encryption and decryption are the same operation.
--
-- input can be of any size
ctrCombineOfIO :: BlockCipherIO cipher => cipher -> IV cipher -> ByteString -> ByteString
ctrCombineOfIO cipher iv bs = withDestIVAnySize iv bs $ cfbDecryptMutable cipher
 
-- | encrypt using the XTS mode.
--
-- input need to be a multiple of the blocksize
xtsEncryptOfIO :: BlockCipherIO cipher => (cipher, cipher) -> IV cipher -> DataUnitOffset -> ByteString -> ByteString
xtsEncryptOfIO ciphers@(c1,_) iv ofs bs = withDestIV c1 iv bs $ \ivPtr -> xtsEncryptMutable ciphers ivPtr ofs

-- | decrypt using the XTS mode.
--
-- input need to be a multiple of the blocksize
xtsDecryptOfIO :: BlockCipherIO cipher => (cipher, cipher) -> IV cipher -> DataUnitOffset -> ByteString -> ByteString
xtsDecryptOfIO ciphers@(c1,_) iv ofs bs = withDestIV c1 iv bs $ \ivPtr -> xtsDecryptMutable ciphers ivPtr ofs

-- | Encrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8EncryptOfIO :: BlockCipherIO a => a -> IV a -> B.ByteString -> B.ByteString
cfb8EncryptOfIO ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbEncryptOfIO ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` out)

-- | Decrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8DecryptOfIO :: BlockCipherIO a => a -> IV a -> B.ByteString -> B.ByteString
cfb8DecryptOfIO ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbDecryptOfIO ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` B.head m')
-}
