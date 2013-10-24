-- |
-- Module      : Crypto.Cipher.Types.Unsafe
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- mutable and unsafe interface for Block ciphers.
-- export a BlockCipherIO class
--
module Crypto.Cipher.Types.Unsafe
    ( BlockCipherIO(..)
    , BufferLength
    , PtrDest
    , PtrSource
    , PtrIV
    , onBlock
    ) where

import Crypto.Cipher.Types.BlockIO
