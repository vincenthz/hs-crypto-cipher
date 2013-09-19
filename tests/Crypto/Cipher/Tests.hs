-- |
-- Module      : Crypto.Cipher.Tests
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--

{-# LANGUAGE ViewPatterns #-}
module Crypto.Cipher.Tests
    ( testBlockCipher
    , testStreamCipher
    -- * KATs
    , defaultKATs
    , defaultStreamKATs
    , KATs(..)
    , KAT_Stream(..)
    , KAT_ECB(..)
    , KAT_CBC(..)
    , KAT_CFB(..)
    , KAT_CTR(..)
    , KAT_XTS(..)
    , KAT_AEAD(..)
    ) where

import Test.Framework (Test, testGroup)

import Crypto.Cipher.Types
import Crypto.Cipher.Tests.KATs
import Crypto.Cipher.Tests.Properties

-- | Return tests for a specific blockcipher and a list of KATs
testBlockCipher :: BlockCipher a => KATs -> a -> Test
testBlockCipher kats cipher = testGroup (cipherName cipher)
    (  (if kats == defaultKATs  then [] else [testKATs kats cipher])
    ++ testModes cipher
    )

-- | Return tests for a specific streamcipher and a list of KATs
testStreamCipher :: StreamCipher a => [KAT_Stream] -> a -> Test
testStreamCipher kats cipher = testGroup (cipherName cipher)
    (  (if kats == defaultStreamKATs then [] else [testStreamKATs kats cipher])
    ++ testStream cipher
    )
