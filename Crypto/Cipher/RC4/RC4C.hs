{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Wrappers for C version of the RC4 encryption functions.
module Crypto.Cipher.RC4.RC4C
    ( Ctx
    , encrypt
    , decrypt
    , initCtx
    ) where

import           Foreign hiding (unsafePerformIO)
import           Foreign.C
import           System.IO.Unsafe
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
import qualified Data.ByteString.Char8 as BC8
import Control.Applicative ((<$>))

----------------------------------------------------------------------

-- | The encryption context for RC4
data Ctx = Ctx B.ByteString

instance Show Ctx where
    show _ = "RC4.Ctx"

-- | C Call for initializing the encryptor
foreign import ccall unsafe "RC4.h initCtx"
    c_initCtx :: Ptr Word8 ->   -- ^ The encryption key
                 Word32    ->   -- ^ The key length
                 Ptr Word8 ->   -- ^ The permutation, pre-allocated
                 IO ()

-- | Haskell wrapper for initializing the permutation
initCtx :: B.ByteString -- ^ The key, a bytestring of length 40
        -> Ctx          -- ^ The encryption context
initCtx key = B.inlinePerformIO $
    Ctx <$> (B.create 264 $ \ctx -> B.useAsCStringLen key $ \(keyPtr,keyLen) -> c_initCtx (castPtr keyPtr) (fromIntegral keyLen) ctx)

foreign import ccall unsafe "RC4.h rc4"
    c_rc4 :: Ptr Ctx        -- ^ Pointer to the permutation
          -> Ptr Word8      -- ^ Pointer to the clear text
          -> Word32         -- ^ Length of the clear text
          -> Ptr Word8      -- ^ Output buffer
          -> IO ()

-- | RC4 encryption
--   Since the context is both an input and an output, this is a
--   pure computation, thus we can convert from the FFI/IO monad
--   to a pure computation using unsafePerformIO.
--
--   Supporting this argument, the C code does not do any memory
--   management.
encrypt :: Ctx                 -- ^ The encryption context
        -> B.ByteString        -- ^ The clear (red) text
        -> (Ctx, B.ByteString) -- ^ The new encryption context, and
                               --   the cipher (black) text
encrypt cctx clearText = B.inlinePerformIO $
    undefined
{-
    where len = B.length clearText
        let Ctx { permutation = perm, ival = i, jval = j } = ctx
        -- Convert permutation to pointer for the C call          
        let (perm_ptr, _perm_off, _perm_len) = B.toForeignPtr perm
        -- Pointer to the permutation used only locally
        withForeignPtr perm_ptr $ \(cperm :: Ptr Word8) -> do
          let (clear_ptr, _clear_off, _clear_len) = B.toForeignPtr clearText
          -- Pointer to the clear text used only locally
          withForeignPtr clear_ptr $ \cclear -> do
            -- Convert i and j values to pointers for the C call
            poke iptr (fromIntegral i)
            poke jptr (fromIntegral j)
            -- Actually do the encryption
            outptr' <- c_rc4 cperm iptr jptr cclear (fromIntegral len) outptr
            -- Retrieve the new i and j values
            i' <- peek iptr
            j' <- peek jptr
            -- Associate a finalizer with the cipher text
            foutptr <- newForeignPtr finalizerFree outptr'
            -- Return the output context and cipher text
            return ( Ctx perm (fromIntegral i') (fromIntegral j')
                   , B.fromForeignPtr foutptr 0 len
                   )
-}

-- | RC4 decryption. For RC4, decrypt = encrypt
--
--   See comments under the encrypt function.
--
decrypt :: Ctx -> B.ByteString -> (Ctx, B.ByteString)
decrypt = encrypt
