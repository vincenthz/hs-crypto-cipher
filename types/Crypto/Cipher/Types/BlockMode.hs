-- |
-- Module      : Crypto.Cipher.Types.BlockMode
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- block cipher modes basic types
--
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Types.BlockMode
    ( BlockCipherModes(..)
    , AEAD(..)
    , AEADState(..)
    , AEADModeImpl(..)
    -- * CFB 8 bits
    , cfb8Encrypt
    , cfb8Decrypt
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B (unsafeCreate)
import Data.Byteable
import Crypto.Cipher.Types.GF
import Crypto.Cipher.Types.Base
import Crypto.Cipher.Types.Block
import Crypto.Cipher.Types.Utils
import Foreign.Ptr
import Foreign.Storable

class BlockCipher cipher => BlockCipherModes cipher where
    -- | encrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcEncrypt :: cipher -> IV cipher -> ByteString -> ByteString
    cbcEncrypt = cbcEncryptGeneric
    -- | decrypt using the CBC mode.
    --
    -- input need to be a multiple of the blocksize
    cbcDecrypt :: cipher -> IV cipher -> ByteString -> ByteString
    cbcDecrypt = cbcDecryptGeneric

    -- | encrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbEncrypt :: cipher -> IV cipher -> ByteString -> ByteString
    cfbEncrypt = cfbEncryptGeneric
    -- | decrypt using the CFB mode.
    --
    -- input need to be a multiple of the blocksize
    cfbDecrypt :: cipher -> IV cipher -> ByteString -> ByteString
    cfbDecrypt = cfbDecryptGeneric

    -- | combine using the CTR mode.
    --
    -- CTR mode produce a stream of randomized data that is combined
    -- (by XOR operation) with the input stream.
    --
    -- encryption and decryption are the same operation.
    --
    -- input can be of any size
    ctrCombine :: cipher -> IV cipher -> ByteString -> ByteString
    ctrCombine = ctrCombineGeneric

    -- | encrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize.
    xtsEncrypt :: (cipher, cipher)
               -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
               -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
               -> ByteString       -- ^ Plaintext
               -> ByteString       -- ^ Ciphertext
    xtsEncrypt = xtsEncryptGeneric

    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize
    xtsDecrypt :: (cipher, cipher)
               -> IV cipher        -- ^ Usually represent the Data Unit (e.g. disk sector)
               -> DataUnitOffset   -- ^ Offset in the data unit in number of blocks
               -> ByteString       -- ^ Ciphertext
               -> ByteString       -- ^ Plaintext
    xtsDecrypt = xtsDecryptGeneric

    -- | Initialize a new AEAD State
    --
    -- When Nothing is returns, it means the mode is not handled.
    aeadInit :: Byteable iv => AEADMode -> cipher -> iv -> Maybe (AEAD cipher)
    aeadInit _ _ _ = Nothing

-- | Authenticated Encryption with Associated Data algorithms
data AEAD cipher = AEAD cipher (AEADState cipher)

-- | Wrapper for any AEADState
data AEADState cipher = forall st . AEADModeImpl cipher st => AEADState st

-- | Class of AEAD Mode implementation
class BlockCipher cipher => AEADModeImpl cipher state where
    aeadStateAppendHeader :: cipher -> state -> ByteString -> state
    aeadStateEncrypt      :: cipher -> state -> ByteString -> (ByteString, state)
    aeadStateDecrypt      :: cipher -> state -> ByteString -> (ByteString, state)
    aeadStateFinalize     :: cipher -> state -> Int -> AuthTag

cbcEncryptGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
cbcEncryptGeneric cipher (IV ivini) input = B.concat $ doEnc ivini $ chunk (blockSize cipher) input
  where doEnc _  []     = []
        doEnc iv (i:is) =
            let o = ecbEncrypt cipher $ bxor iv i
             in o : doEnc o is

cbcDecryptGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
cbcDecryptGeneric cipher (IV ivini) input = B.concat $ doDec ivini $ chunk (blockSize cipher) input
  where doDec _  []     = []
        doDec iv (i:is) =
            let o = bxor iv $ ecbDecrypt cipher i
             in o : doDec i is

cfbEncryptGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
cfbEncryptGeneric cipher (IV ivini) input = B.concat $ doEnc ivini $ chunk (blockSize cipher) input
  where doEnc _  []     = []
        doEnc iv (i:is) =
            let o = bxor i $ ecbEncrypt cipher iv
             in o : doEnc o is

cfbDecryptGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
cfbDecryptGeneric cipher (IV ivini) input = B.concat $ doDec ivini $ chunk (blockSize cipher) input
  where doDec _  []     = []
        doDec iv (i:is) =
            let o = bxor i $ ecbEncrypt cipher iv
             in o : doDec i is

ctrCombineGeneric :: BlockCipher cipher => cipher -> IV cipher -> ByteString -> ByteString
ctrCombineGeneric cipher ivini input = B.concat $ doCnt ivini $ chunk (blockSize cipher) input
  where doCnt _  [] = []
        doCnt iv (i:is) =
            let ivEnc = ecbEncrypt cipher (toBytes iv)
             in bxor i ivEnc : doCnt (ivAdd iv 1) is

xtsEncryptGeneric :: BlockCipher cipher => (cipher,cipher) -> IV cipher -> DataUnitOffset -> ByteString -> ByteString
xtsEncryptGeneric = xtsGeneric ecbEncrypt

xtsDecryptGeneric :: BlockCipher cipher => (cipher,cipher) -> IV cipher -> DataUnitOffset -> ByteString -> ByteString
xtsDecryptGeneric = xtsGeneric ecbDecrypt

xtsGeneric :: BlockCipher cipher
           => (cipher -> B.ByteString -> B.ByteString)
           -> (cipher,cipher)
           -> IV cipher
           -> DataUnitOffset
           -> ByteString
           -> ByteString
xtsGeneric f (cipher, tweakCipher) iv sPoint input
    | blockSize cipher /= 128 = error "XTS mode is only available with cipher that have a block size of 128 bits"
    | otherwise = B.concat $ doXts iniTweak $ chunk (blockSize cipher) input
  where encTweak = ecbEncrypt tweakCipher (toBytes iv)
        iniTweak = iterate xtsGFMul encTweak !! fromIntegral sPoint
        doXts _     []     = []
        doXts tweak (i:is) =
            let o = bxor (f cipher $ bxor i tweak) tweak
             in o : doXts (xtsGFMul tweak) is

-- | Encrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Encrypt :: BlockCipherModes a => a -> IV a -> B.ByteString -> B.ByteString
cfb8Encrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbEncrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` out)

-- | Decrypt using CFB mode in 8 bit output
--
-- Effectively turn a Block cipher in CFB mode into a Stream cipher
cfb8Decrypt :: BlockCipherModes a => a -> IV a -> B.ByteString -> B.ByteString
cfb8Decrypt ctx origIv msg = B.unsafeCreate (B.length msg) $ \dst -> loop dst origIv msg
  where loop d iv@(IV i) m
            | B.null m  = return ()
            | otherwise = poke d out >> loop (d `plusPtr` 1) ni (B.drop 1 m)
          where m'  = if B.length m < blockSize ctx
                            then m `B.append` B.replicate (blockSize ctx - B.length m) 0
                            else B.take (blockSize ctx) m
                r   = cfbDecrypt ctx iv m'
                out = B.head r
                ni  = IV (B.drop 1 i `B.snoc` B.head m')
