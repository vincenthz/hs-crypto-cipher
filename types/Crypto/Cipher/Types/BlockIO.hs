-- |
-- Module      : Crypto.Cipher.Types.Block
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- block cipher basic types
--
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Types.BlockIO
    ( BlockCipherIO(..)
    , PtrDest
    , PtrSource
    , PtrIV
    , BufferLength
    , onBlock
    ) where

import Control.Applicative
import Data.Word
import Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as B (fromForeignPtr, memcpy)
import Data.Byteable
import Data.Bits (xor, Bits)
import Foreign.Storable (poke, peek, Storable)
--import Foreign.Ptr (plusPtr, Ptr, castPtr, nullPtr)
import Crypto.Cipher.Types.Block
import Foreign.Ptr
import Foreign.ForeignPtr (newForeignPtr_)

-- | pointer to the destination data
type PtrDest   = Ptr Word8

-- | pointer to the source data
type PtrSource = Ptr Word8

-- | pointer to the IV data
type PtrIV     = Ptr Word8

-- | Length of the pointed data
type BufferLength = Word32

-- | Symmetric block cipher class, mutable API
class BlockCipher cipher => BlockCipherIO cipher where
    -- | Encrypt using the ECB mode.
    --
    -- input need to be a multiple of the blocksize
    ecbEncryptMutable :: cipher -> PtrDest -> PtrSource -> BufferLength -> IO ()

    -- | Decrypt using the ECB mode.
    --
    -- input need to be a multiple of the blocksize
    ecbDecryptMutable :: cipher -> PtrDest -> PtrSource -> BufferLength -> IO ()

    -- | encrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcEncryptMutable :: cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
    cbcEncryptMutable = cbcEncryptGeneric

    -- | decrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcDecryptMutable :: cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
    cbcDecryptMutable = cbcDecryptGeneric

{-
    -- | encrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbEncryptMutable :: cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
    cfbEncryptMutable = cfbEncryptGeneric

    -- | decrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbDecryptMutable :: cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
    cfbDecryptMutable = cfbDecryptGeneric

    -- | combine using the CTR mode.
    --
    -- CTR mode produce a stream of randomized data that is combined
    -- (by XOR operation) with the input stream.
    --
    -- encryption and decryption are the same operation.
    --
    -- input can be of any size
    ctrCombineMutable :: cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
    ctrCombineMutable = ctrCombineGeneric

    -- | encrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize
    xtsEncryptMutable :: (cipher, cipher) -> PtrIV -> DataUnitOffset -> PtrDest -> PtrSource -> BufferLength -> IO ()
    xtsEncryptMutable = xtsEncryptGeneric
    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize
    xtsDecryptMutable :: (cipher, cipher) -> PtrIV -> DataUnitOffset -> PtrDest -> PtrSource -> BufferLength -> IO ()
    xtsDecryptMutable = xtsDecryptGeneric
-}

cbcEncryptGeneric :: BlockCipherIO cipher => cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
cbcEncryptGeneric cipher = loopBS cipher encrypt
  where encrypt bs iv d s = do
            mutableXor d iv s bs
            ecbEncryptMutable cipher d d (fromIntegral bs)
            return s

cbcDecryptGeneric :: BlockCipherIO cipher => cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
cbcDecryptGeneric cipher = loopBS cipher decrypt
  where decrypt bs iv d s = do
            ecbEncryptMutable cipher d s (fromIntegral bs)
            -- FIXME only work if s != d
            mutableXor d iv d bs
            return d

{-
cfbEncryptGeneric :: BlockCipherIO cipher => cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
cfbEncryptGeneric cipher = loopBS cipher encrypt
  where encrypt bs iv d s = do
            ecbEncryptMutable cipher d iv (fromIntegral bs)
            mutableXor d d s bs
            return d


cfbDecryptGeneric :: BlockCipherIO cipher => cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
cfbDecryptGeneric cipher = loopBS cipher decrypt
  where decrypt bs iv d s = do
            ecbEncryptMutable cipher d iv (fromIntegral bs)
            mutableXor d d s bs
            return s

ctrCombineGeneric :: BlockCipherIO cipher => cipher -> PtrIV -> PtrDest -> PtrSource -> BufferLength -> IO ()
ctrCombineGeneric cipher ivini dst src len = return () {-B.concat $ doCnt ivini $ chunk (blockSize cipher) input
  where doCnt _  [] = []
        doCnt iv (i:is) =
            let ivEnc = ecbEncrypt cipher (toBytes iv)
             in bxor i ivEnc : doCnt (ivAdd iv 1) is-}
-}

-- | Helper to use a purer interface
onBlock :: BlockCipherIO cipher
        => cipher
        -> (ByteString -> ByteString)
        -> PtrDest
        -> PtrSource
        -> BufferLength
        -> IO ()
onBlock cipher f dst src len = loopBS cipher wrap nullPtr dst src len
  where wrap bs fakeIv d s = do
            fSrc <- newForeignPtr_ s
            let res = f (B.fromForeignPtr fSrc 0 bs)
            withBytePtr res $ \r -> B.memcpy d r (fromIntegral bs)
            return fakeIv

loopBS :: BlockCipherIO cipher
       => cipher
       -> (Int -> PtrIV -> PtrDest -> PtrSource -> IO PtrIV)
       -> PtrIV -> PtrDest -> PtrSource -> BufferLength
       -> IO ()
loopBS cipher f iv dst src len = loop iv dst src len
  where bs = blockSize cipher
        loop _ _ _ 0 = return ()
        loop i d s n = do
            newIV <- f bs i d s
            loop newIV (d `plusPtr` bs) (s `plusPtr` bs) (n - fromIntegral bs)

mutableXor :: PtrDest -> PtrSource -> PtrIV -> Int -> IO ()
mutableXor (to64 -> dst) (to64 -> src) (to64 -> iv) 16 = do
    peeksAndPoke dst src iv
    peeksAndPoke (dst `plusPtr` 8) (src `plusPtr` 8) ((iv `plusPtr` 8) :: Ptr Word64)
mutableXor (to64 -> dst) (to64 -> src) (to64 -> iv) 8 = do
    peeksAndPoke dst src iv
mutableXor dst src iv len = loop dst src iv len
  where loop _ _ _ 0 = return ()
        loop d s i n = peeksAndPoke d s i >> loop (d `plusPtr` 1) (s `plusPtr` 1) (i `plusPtr` 1) (n-1)

to64 :: Ptr Word8 -> Ptr Word64
to64 = castPtr

peeksAndPoke :: (Bits a, Storable a) => Ptr a -> Ptr a -> Ptr a -> IO ()
peeksAndPoke dst a b = (xor <$> peek a <*> peek b) >>= poke dst
