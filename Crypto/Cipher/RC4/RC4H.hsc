{-# LANGUAGE CPP, ForeignFunctionInterface #-}
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

#include <pcre.h>
#include "RC4.h"

--------------------------------------------------------------------------------
-- RC4
--------------------------------------------------------------------------------

type CCtx = Ptr ()

-- | Get the "i" out of the context
ctxI :: CCtx -> IO Int 
ctxI = #peek CCtx, i

-- | Get the "j" out of the context
ctxJ :: CCtx -> IO Int 
ctxJ = #peek CCtx, j

-- | Get the state out of the context
ctxState :: CCtx -> IO (Ptr CChar)
ctxState = #peek CCtx, state

-- | Make a new context, pretend it is a bytestring
mkCCtx :: IO CCtx
mkCCtx = do
    -- Needs enough to store two Int and a Pointer
    ctx  :: CCtx <- mallocBytes 100 -- Hope this is enough
    -- Needs enough to store 256 Word8
    perm :: Ptr () <- mallocBytes 2000 -- Hope this is enough
    (#poke CCtx, i) ctx (0::Int)
    (#poke CCtx, j) ctx (0::Int)
    (#poke CCtx, state) ctx perm
    return ctx
