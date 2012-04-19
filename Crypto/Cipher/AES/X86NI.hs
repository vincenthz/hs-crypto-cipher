{-# LANGUAGE ForeignFunctionInterface #-}
module Crypto.Cipher.AES.X86NI
    ( encrypt
    , decrypt
    , encryptCBC
    , decryptCBC
    , initKey128
    ) where

import Foreign.Storable
import Foreign.Marshal.Alloc (alloca, allocaBytes)
import Foreign.Ptr
import Foreign.C.String
import Foreign.C.Types
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe (unsafeUseAsCString)
import Data.ByteString.Internal (create, memcpy)
import Data.Bits (shiftR)
import qualified Data.ByteString as B

import System.IO.Unsafe

type IV = ByteString
newtype Key = Key ByteString

instance Storable Key where
    sizeOf _         = 16 * 11 * 2
    alignment _      = 16
    poke ptr (Key b) = unsafeUseAsCString b (\cs -> memcpy (castPtr ptr) (castPtr cs) (16 * 11 * 2))
    peek ptr         = Key `fmap` create (16*11*2) (\bptr -> memcpy bptr (castPtr ptr) (16 * 11 * 2))

foreign import ccall safe "aes.h aes_generate_key128"
        c_aes_generate_key128 :: Ptr Key -> CString -> IO ()

foreign import ccall safe "aes.h aes_encrypt"
        c_aes_encrypt :: CString -> Ptr Key -> CString -> CUInt -> IO ()

foreign import ccall safe "aes.h aes_decrypt"
        c_aes_decrypt :: CString -> Ptr Key -> CString -> CUInt -> IO ()

foreign import ccall safe "aes.h aes_encrypt_cbc"
        c_aes_encrypt_cbc :: CString -> Ptr Key -> CString -> CString -> CUInt -> IO ()

foreign import ccall safe "aes.h aes_decrypt_cbc"
        c_aes_decrypt_cbc :: CString -> Ptr Key -> CString -> CString -> CUInt -> IO ()

withKey :: Key -> (Ptr Key -> IO a) -> IO a
withKey k f = alloca (\ikey -> poke ikey k >> f ikey)

{-# NOINLINE initKey128 #-}
initKey128 :: ByteString -> Key
initKey128 b = unsafePerformIO $ unsafeUseAsCString b (\ikey ->
        alloca (\key -> c_aes_generate_key128 key ikey >> peek key))

{-# NOINLINE encrypt #-}
encrypt :: Key -> ByteString -> ByteString
encrypt key input = unsafePerformIO $ allocateAndMapBlocks input $ \blocks o i ->
    withKey key $ \k -> c_aes_encrypt o k i blocks

{-# NOINLINE decrypt #-}
decrypt :: Key -> ByteString -> ByteString
decrypt key input = unsafePerformIO $ allocateAndMapBlocks input $ \blocks o i ->
    withKey key $ \k -> c_aes_decrypt o k i blocks

{-# NOINLINE encryptCBC #-}
encryptCBC :: Key -> IV -> ByteString -> ByteString
encryptCBC key iv input = unsafePerformIO $ allocateAndMapBlocks input $ \blocks o i ->
    withKey key $ \k -> unsafeUseAsCString iv $ \ivptr -> c_aes_encrypt_cbc o k ivptr i blocks

{-# NOINLINE decryptCBC #-}
decryptCBC :: Key -> IV -> ByteString -> ByteString
decryptCBC key iv input = unsafePerformIO $ allocateAndMapBlocks input $ \blocks o i ->
    withKey key $ \k -> unsafeUseAsCString iv $ \ivptr -> c_aes_decrypt_cbc o k ivptr i blocks

allocateAndMapBlocks :: ByteString -> (CUInt -> Ptr CChar -> CString -> IO ()) -> IO ByteString
allocateAndMapBlocks input f = allocaBytes len (\output -> do unsafeUseAsCString input (f nbBlocks output)
                                                              B.packCStringLen (output, len))
    where len = B.length input
          nbBlocks = fromIntegral (len `shiftR` 4)

