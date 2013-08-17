-- |
-- Module      : Crypto.Cipher.Types
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- symmetric cipher basic types
--
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ExistentialQuantification #-}
module Crypto.Cipher.Types
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , StreamCipher(..)
    , DataUnitOffset
    , KeySizeSpecifier(..)
    , KeyError(..)
    , AEAD(..)
    , AEADState(..)
    , AEADMode(..)
    , AEADModeImpl(..)
    -- * AEAD
    , aeadAppendHeader
    , aeadEncrypt
    , aeadDecrypt
    , aeadFinalize
    , aeadSimpleEncrypt
    , aeadSimpleDecrypt
    -- * Key type and constructor
    , Key
    , makeKey
    -- * Initial Vector type and constructor
    , IV
    , makeIV
    , nullIV
    , ivAdd
    -- * Authentification Tag
    , AuthTag(..)
    ) where

import Data.SecureMem
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.Byteable
import Data.Word
import Data.Bits (shiftR, xor)
import Crypto.Cipher.Types.GF

-- | Offset inside an XTS data unit, measured in block size.
type DataUnitOffset = Word32

-- | Possible Error that can be reported when initializating a key
data KeyError =
      KeyErrorTooSmall
    | KeyErrorTooBig
    | KeyErrorInvalid String
    deriving (Show,Eq)

-- | Different specifier for key size in bytes
data KeySizeSpecifier =
      KeySizeRange Int Int -- ^ in the range [min,max]
    | KeySizeEnum  [Int]   -- ^ one of the specified values
    | KeySizeFixed Int     -- ^ a specific size
    deriving (Show,Eq)

-- | Symmetric cipher class.
class Cipher cipher where
    -- | Initialize a cipher context from a key
    cipherInit    :: Key cipher -> cipher
    -- | Cipher name
    cipherName    :: cipher -> String
    -- | return the size of the key required for this cipher.
    -- Some cipher accept any size for key
    cipherKeySize :: cipher -> KeySizeSpecifier

-- | Symmetric stream cipher class
class Cipher cipher => StreamCipher cipher where
    -- | Encrypt using the stream cipher
    streamEncrypt :: cipher -> ByteString -> (ByteString, cipher)
    -- | Decrypt using the stream cipher
    streamDecrypt :: cipher -> ByteString -> (ByteString, cipher)

-- | Symmetric block cipher class
class Cipher cipher => BlockCipher cipher where
    -- | Return the size of block required for this block cipher
    blockSize    :: cipher -> Int

    -- | Encrypt using the ECB mode.
    --
    -- input need to be a multiple of the blocksize
    ecbEncrypt :: cipher -> ByteString -> ByteString
    -- | Decrypt using the ECB mode.
    --
    -- input need to be a multiple of the blocksize
    ecbDecrypt :: cipher -> ByteString -> ByteString

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
    -- input need to be a multiple of the blocksize
    xtsEncrypt :: (cipher, cipher) -> IV cipher -> DataUnitOffset -> ByteString -> ByteString
    xtsEncrypt = xtsEncryptGeneric
    -- | decrypt using the XTS mode.
    --
    -- input need to be a multiple of the blocksize
    xtsDecrypt :: (cipher, cipher) -> IV cipher -> DataUnitOffset -> ByteString -> ByteString
    xtsDecrypt = xtsDecryptGeneric

    -- | Initialize a new AEAD State
    --
    -- When Nothing is returns, it means the mode is not handled.
    aeadInit :: Byteable iv => AEADMode -> cipher -> iv -> Maybe (AEAD cipher)
    aeadInit _ _ _ = Nothing

-- | AEAD Mode
data AEADMode =
      AEAD_OCB
    | AEAD_CCM
    | AEAD_EAX
    | AEAD_CWC
    | AEAD_GCM
    deriving (Show,Eq)

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

-- | Append associated data into the AEAD state
aeadAppendHeader :: BlockCipher a => AEAD a -> ByteString -> AEAD a
aeadAppendHeader (AEAD cipher (AEADState state)) bs =
    AEAD cipher $ AEADState (aeadStateAppendHeader cipher state bs)

-- | Encrypt input and append into the AEAD state
aeadEncrypt :: BlockCipher a => AEAD a -> ByteString -> (ByteString, AEAD a)
aeadEncrypt (AEAD cipher (AEADState state)) input = (output, AEAD cipher (AEADState nst))
  where (output, nst) = aeadStateEncrypt cipher state input

-- | Decrypt input and append into the AEAD state
aeadDecrypt :: BlockCipher a => AEAD a -> ByteString -> (ByteString, AEAD a)
aeadDecrypt (AEAD cipher (AEADState state)) input = (output, AEAD cipher (AEADState nst))
  where (output, nst) = aeadStateDecrypt cipher state input

-- | Finalize the AEAD state and create an authentification tag
aeadFinalize :: BlockCipher a => AEAD a -> Int -> AuthTag
aeadFinalize (AEAD cipher (AEADState state)) len =
    aeadStateFinalize cipher state len

-- | Simple AEAD encryption
aeadSimpleEncrypt :: BlockCipher a
                  => AEAD a        -- ^ A new AEAD Context
                  -> B.ByteString  -- ^ Optional Authentified Header
                  -> B.ByteString  -- ^ Optional Plaintext
                  -> Int           -- ^ Tag length
                  -> (AuthTag, B.ByteString) -- ^ Authentification tag and ciphertext
aeadSimpleEncrypt aeadIni header input taglen = (tag, output)
  where aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadEncrypt aead input
        tag                 = aeadFinalize aeadFinal taglen

-- | Simple AEAD decryption
aeadSimpleDecrypt :: BlockCipher a
                  => AEAD a        -- ^ A new AEAD Context
                  -> B.ByteString  -- ^ Optional Authentified Header
                  -> B.ByteString  -- ^ Optional Plaintext
                  -> AuthTag       -- ^ Tag length
                  -> Maybe B.ByteString -- ^ Plaintext
aeadSimpleDecrypt aeadIni header input authTag
    | tag == authTag = Just output
    | otherwise      = Nothing
  where aead                = aeadAppendHeader aeadIni header
        (output, aeadFinal) = aeadDecrypt aead input
        tag                 = aeadFinalize aeadFinal (byteableLength authTag)

-- | a Key parametrized by the cipher
newtype Key c = Key SecureMem deriving (Eq)

instance ToSecureMem (Key c) where
    toSecureMem (Key sm) = sm
instance Byteable (Key c) where
    toBytes (Key sm) = toBytes sm

-- | an IV parametrized by the cipher
newtype IV c = IV ByteString deriving (Eq)

instance Byteable (IV c) where
    toBytes (IV sm) = sm

-- | Authentification Tag for AE cipher mode
newtype AuthTag = AuthTag ByteString
    deriving (Show)

instance Eq AuthTag where
    (AuthTag a) == (AuthTag b) = constEqBytes a b
instance Byteable AuthTag where
    toBytes (AuthTag bs) = bs

-- | Create an IV for a specified block cipher
makeIV :: (Byteable b, BlockCipher c) => b -> Maybe (IV c)
makeIV b = toIV undefined
  where toIV :: BlockCipher c => c -> Maybe (IV c)
        toIV cipher
          | byteableLength b == sz = Just (IV $ toBytes b)
          | otherwise              = Nothing
          where sz = blockSize cipher

-- | Create an IV that is effectively representing the number 0
nullIV :: BlockCipher c => IV c
nullIV = toIV undefined
  where toIV :: BlockCipher c => c -> IV c
        toIV cipher = IV $ B.replicate (blockSize cipher) 0

-- | Increment an IV by a number.
--
-- Assume the IV is in Big Endian format.
ivAdd :: BlockCipher c => IV c -> Int -> IV c
ivAdd (IV b) i = IV $ snd $ B.mapAccumR addCarry i b
  where addCarry :: Int -> Word8 -> (Int, Word8)
        addCarry acc w
            | acc == 0  = (0, w)
            | otherwise = let (hi,lo) = acc `divMod` 256
                              nw      = lo + (fromIntegral w)
                           in (hi + (nw `shiftR` 8), fromIntegral nw)

-- | Create a Key for a specified cipher
makeKey :: (ToSecureMem b, Cipher c) => b -> Either KeyError (Key c)
makeKey b = toKey undefined
  where sm    = toSecureMem b
        smLen = byteableLength sm
        toKey :: Cipher c => c -> Either KeyError (Key c)
        toKey cipher = case cipherKeySize cipher of
            KeySizeRange mi ma | smLen < mi -> Left KeyErrorTooSmall
                               | smLen > ma -> Left KeyErrorTooBig
                               | otherwise  -> Right $ Key sm
            KeySizeEnum l | smLen `elem` l  -> Right $ Key sm
                          | otherwise       -> Left $ KeyErrorInvalid ("valid size: " ++ show l)
            KeySizeFixed v | smLen < v      -> Right $ Key sm
                           | otherwise      -> Left $ KeyErrorInvalid ("valid size: " ++ show v)

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
xtsGeneric f (cipher, tweakCipher) iv sPoint input = B.concat $ doXts iniTweak $ chunk (blockSize cipher) input
  where encTweak = ecbEncrypt tweakCipher (toBytes iv)
        iniTweak = iterate xtsGFMul encTweak !! fromIntegral sPoint
        doXts _     []     = []
        doXts tweak (i:is) =
            let o = bxor (f cipher $ bxor i tweak) tweak
             in o : doXts (xtsGFMul tweak) is


chunk :: Int -> ByteString -> [ByteString]
chunk sz bs = split bs
  where split b | B.length b <= sz = [b]
                | otherwise        =
                        let (b1, b2) = B.splitAt sz b
                         in b1 : split b2

bxor :: ByteString -> ByteString -> ByteString
bxor src dst = B.pack $ B.zipWith xor src dst
