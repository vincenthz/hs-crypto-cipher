-- |
-- Module      : Crypto.Cipher
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : stable
-- Portability : good
--
-- All the cipher functionalities are available through the
-- BlockCipher and StreamCipher classes.
--
-- A simplified example (with simplified error handling):
--
-- > import Crypto.Cipher
-- > import Data.ByteString (ByteString)
-- > import qualified Data.ByteString as B
-- >
-- > initAES256 :: ByteString -> AES256
-- > initAES256 = either (error . show) cipherInit . makeKey
-- >
-- > cbcEncryption :: AES256 -> ByteString -> ByteString -> ByteString
-- > cbcEncryption ctx ivRaw plainText = cbcEncrypt ctx iv plainText
-- >   where iv = maybe (error "invalid IV") id $ ivRaw
--
module Crypto.Cipher
    (
    -- * Cipher classes
      Cipher(..)
    , BlockCipher(..)
    , StreamCipher(..)
    -- * Key
    , Key
    , makeKey
    -- * Initialization Vector (IV)
    , IV
    , makeIV
    , nullIV
    , ivAdd
    -- * Authenticated Encryption with Associated Data (AEAD)
    , AEAD
    , aeadAppendHeader
    , aeadEncrypt
    , aeadDecrypt
    , aeadFinalize
    -- * Cipher implementations
    , AES128, AES192, AES256
    , Blowfish, Blowfish64, Blowfish128, Blowfish256, Blowfish448
    , DES
    , DES_EEE3, DES_EDE3, DES_EEE2, DES_EDE2
    , Camellia128
    ) where

import Crypto.Cipher.Types
import Crypto.Cipher.AES (AES128, AES192, AES256)
import Crypto.Cipher.Blowfish
import Crypto.Cipher.DES
import Crypto.Cipher.TripleDES
import Crypto.Cipher.Camellia
