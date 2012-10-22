-- |
-- Module      : Crypto.Cipher.RC4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Author      : Peter White <peter@janrain.com>
-- Stability   : experimental
-- Portability : Good
--

{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE EmptyDataDecls #-}

module Crypto.Cipher.RC4 (
	Ctx,
	initCtx,
	encrypt,
	decrypt
	) where

import           Foreign
import           Foreign.C.Types
import           Foreign.C.String
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC8
import           Crypto.Cipher.RC4.RC4H

----------------------------------------------------------------------
-- Crypto (RC4)
----------------------------------------------------------------------

type Ctx = Ptr CCtx

foreign import ccall unsafe "RC4.h initCtx"
    c_initCtx :: Ptr CChar -> Ptr () -> IO Ctx

initCtx :: B.ByteString -> IO Ctx
initCtx key = do
    -- Need to make a context in Haskell land
    ctx <- mkCCtx
    
    B.useAsCString key $ \key_ptr -> do
        -- Temporarily pretent the pointer to Ctx (ctx) is a pointer to ()
        ctx' <- c_initCtx key_ptr ctx
        -- state <- ctxState ctx
        return ctx'

foreign import ccall unsafe "RC4.h rc4"
    c_rc4 :: Ctx -> Ptr CChar -> CInt -> IO (Ptr CChar)
      
encrypt :: Ctx -> Int -> B.ByteString -> IO B.ByteString
encrypt ctx len clear =
    B.useAsCString clear $ \clear_ptr -> do
        out_ptr <- c_rc4 ctx clear_ptr (fromIntegral len)
        hsOutput <- peekCStringLen (out_ptr, len)
        return (BC8.pack hsOutput)

decrypt :: Ctx -> Int -> B.ByteString -> IO B.ByteString
decrypt = encrypt
