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
import           Foreign.C
-- import           Foreign.C.Types
import qualified Data.ByteString as B
import qualified Data.ByteString.Internal as B
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

instance Show Ctx where
    show (Ctx _perm i j) = "(" ++ show i ++ ", " ++ show j ++ ")"

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
    -- Allocate the permutation, and obtain a pointer to it.
    allocaBytes 256 $ \perm_ptr -> do
      B.useAsCString (B.pack key) $ \key_ptr -> do
        perm <- c_initCtx key_ptr perm_ptr
        haskellPerm <- peekCStringLen (perm, 256)
        return (Ctx (BC8.pack haskellPerm) 0 0)

foreign import ccall unsafe "RC4.h rc4"
    c_rc4 :: Ptr Word8      -- ^ Pointer to the permutation
          -> Ptr CInt       -- ^ Pointer to the i index
          -> Ptr CInt       -- ^ Pointer to the j index
          -> Ptr Word8      -- ^ Pointer to the clear text
          -> CInt           -- ^ Length of the clear text
          -> Ptr Word8      -- ^ Cipher text buffer
          -> IO (Ptr Word8) -- ^ Returned pointer to the output text

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
    let len = B.length clearText
    -- Allocate an int, and obtain a pointer to it.
    alloca $ \(iptr :: Ptr CInt) -> do
      -- Allocate another int, and obtain a pointer to it.
      alloca $ \(jptr :: Ptr CInt) -> do
        -- Allocate the output buffer
        allocaBytes len $ \outptr -> do
          let Ctx { permutation = perm, ival = i, jval = j } = ctx
          -- Convert permutation to pointer for the C call          
          let (perm_ptr, _perm_off, _perm_len) = B.toForeignPtr perm
          withForeignPtr perm_ptr $ \(cperm :: Ptr Word8) -> do
            let (clear_ptr, _clear_off, _clear_len) = B.toForeignPtr clearText
            withForeignPtr clear_ptr $ \cclear -> do
              -- Convert i and j values to pointers for the C call
              poke iptr (fromIntegral i)
              poke jptr (fromIntegral j)
              -- Actually do the encryption
              outptr' <- c_rc4 cperm iptr jptr cclear (fromIntegral len) outptr
              -- Retrieve the new i and j values
              i' <- peek iptr
              j' <- peek jptr
              -- Convert C pointer to bytestring for the cipher text
              foutptr <- newForeignPtr_ outptr'
              -- Return the output context and cipher text
              return ( Ctx perm (fromIntegral i') (fromIntegral j')
                     , B.fromForeignPtr foutptr 0 len
                     )

-- | RC4 decryption. For RC4, decrypt = encrypt
--
--   See comments under the encrypt function.
--
decrypt :: Ctx -> B.ByteString -> (Ctx, B.ByteString)
decrypt = encrypt
