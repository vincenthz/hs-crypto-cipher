-- |
-- Module      : Crypto.Cipher.RC4
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- This module just re-export Crypto.Cipher.RC4 from the
-- cipher-rc4 module.
--
-- Documentation can be found at
-- <http://hackage.haskell.org/package/cipher-rc4>
--

{-# LANGUAGE PackageImports #-}
module Crypto.Cipher.RC4 (module Crypto.Cipher.RC4) where

import "cipher-rc4" Crypto.Cipher.RC4
