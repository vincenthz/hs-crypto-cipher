{-# LANGUAGE PackageImports #-}
-- |
-- Module      : Crypto.Cipher.AES
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
-- This module just re-export Crypto.Cipher.AES from the
-- cipher-aes module.
--
-- Documentation can be found at
-- <http://hackage.haskell.org/package/cipher-aes>
--

module Crypto.Cipher.AES
	( module Crypto.Cipher.AES
	) where

import "cipher-aes" Crypto.Cipher.AES
