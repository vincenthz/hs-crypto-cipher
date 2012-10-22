{-# INCLUDE <pcre.h> #-}
{-# INCLUDE "RC4.h" #-}
{-# LINE 1 "RC4H.hsc" #-}
{-# LANGUAGE CPP, ForeignFunctionInterface #-}
{-# LINE 2 "RC4H.hsc" #-}
{-# LANGUAGE ScopedTypeVariables  #-}

module Crypto.Cipher.RC4.RC4H
    ( CCtx
    , mkCCtx
    , ctxI
    , ctxJ
    , ctxState
    ) where

import Foreign
import Foreign.C.Types


{-# LINE 16 "RC4H.hsc" #-}

{-# LINE 17 "RC4H.hsc" #-}

--------------------------------------------------------------------------------
-- RC4
--------------------------------------------------------------------------------

type CCtx = Ptr ()

-- | Get the "i" out of the context
ctxI :: CCtx -> IO Int 
ctxI = (\hsc_ptr -> peekByteOff hsc_ptr 0)
{-# LINE 27 "RC4H.hsc" #-}

-- | Get the "j" out of the context
ctxJ :: CCtx -> IO Int 
ctxJ = (\hsc_ptr -> peekByteOff hsc_ptr 4)
{-# LINE 31 "RC4H.hsc" #-}

-- | Get the state out of the context
ctxState :: CCtx -> IO (Ptr CChar)
ctxState = (\hsc_ptr -> peekByteOff hsc_ptr 8)
{-# LINE 35 "RC4H.hsc" #-}

-- | Make a new context, pretend it is a bytestring
mkCCtx :: IO CCtx
mkCCtx = do
    -- Needs enough to store two Int and a Pointer
    ctx  :: CCtx <- mallocBytes 100 -- Hope this is enough
    -- Needs enough to store 256 Word8
    perm :: Ptr () <- mallocBytes 2000 -- Hope this is enough
    ((\hsc_ptr -> pokeByteOff hsc_ptr 0)) ctx (0::Int)
{-# LINE 44 "RC4H.hsc" #-}
    ((\hsc_ptr -> pokeByteOff hsc_ptr 4)) ctx (0::Int)
{-# LINE 45 "RC4H.hsc" #-}
    ((\hsc_ptr -> pokeByteOff hsc_ptr 8)) ctx perm
{-# LINE 46 "RC4H.hsc" #-}
    return ctx
