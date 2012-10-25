{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | Wrappers for C version of the RC4 encryption functions.
module RC4.RC4C
    ( Ctx
    , encrypt
    , decrypt
    , initCtx
    ) where

import           Foreign
import           Foreign.C.Types
import           Foreign.C
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC8

----------------------------------------------------------------------

-- | The encryption context for RC4
data Ctx = Ctx
  { -- | The permutation, or S-box, controlling the encryptor
    permutation :: B.ByteString
    -- | An index into the permutation
  , ival :: Int
    -- | Another index into the permutation
  , jval :: Int
  }

-- | C Call for initializing the encryptor
foreign import ccall unsafe "RC4.h initCtx"
    c_initCtx :: Ptr CChar ->   -- ^ The encryption key
                 Ptr CChar ->   -- ^ The permutation, pre-allocated
                 IO (Ptr CChar) -- ^ The output permutation

-- | Haskell wrapper for initializing the permutation
initCtx :: [Word8] -- ^ The key, a bytestring of length 40
        -> Ctx     -- ^ The encryption context
initCtx key =
  unsafePerformIO $ do
    allocaBytes 256 $ \perm_ptr -> do
      B.useAsCString (B.pack key) $ \key_ptr -> do
        perm <- c_initCtx key_ptr perm_ptr
        hsPerm <- peekCStringLen (perm, 256)
        return (Ctx (BC8.pack hsPerm) 0 0)

foreign import ccall unsafe "RC4.h rc4"
    c_rc4 :: Ptr CChar      -- ^ Pointer to the permutation
          -> Ptr CInt       -- ^ Pointer to the i index
          -> Ptr CInt       -- ^ Pointer to the j index
          -> Ptr CChar      -- ^ Pointer to the clear text
          -> CInt           -- ^ Length of the clear text
          -> Ptr CChar      -- ^ Pointer to the output text
          -> IO (Ptr CChar) -- ^ Returned pointer to the output text

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
encrypt ctx clearText =
  unsafePerformIO $ do
    -- Allocate an int, and obtain a pointer to it.
    alloca $ \(iptr :: Ptr CInt) -> do
      -- Allocate another int, and obtain a pointer to it.
      alloca $ \(jptr :: Ptr CInt) -> do
        let len = B.length clearText
        -- Allocate the output buffer
        allocaBytes len $ \outptr -> do
          let Ctx { permutation = perm, ival = i, jval = j } = ctx
          -- Convert the permutation to a C string (Ptr CChar)
          B.useAsCString perm $ \cperm -> do
            -- Convert the output buffer to a C string
            B.useAsCString clearText $ \cclear -> do
              -- Set the two indices
              poke iptr (fromIntegral i)
              poke jptr (fromIntegral j)
              -- Actually do the encryption
              outptr' <- c_rc4 cperm iptr jptr cclear (fromIntegral len) outptr
              -- Get the two new index values
              i' <- peek iptr
              j' <- peek jptr
              -- Convert permutation and output back to Haskell
              perm' <- peekCStringLen (cperm, 256)
              hsOutput <- peekCStringLen (outptr', len)
              -- Return the output context and cipher text              
              return ( Ctx (BC8.pack perm') (fromIntegral i') (fromIntegral j')
                     , BC8.pack hsOutput
                     )

-- | RC$ decryption. For RC4, decrypt = encrypt
--
--   See comments under the encrypt function.
--
decrypt :: Ctx -> B.ByteString -> (Ctx, B.ByteString)
decrypt = encrypt
