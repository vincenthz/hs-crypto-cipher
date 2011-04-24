{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Module      : Crypto.Cipher.DH
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : experimental
-- Portability : Good
--
module Crypto.Cipher.DH
	( Params
	, PublicNumber
	, PrivateNumber
	, SharedKey
	, generatePublic
	, getShared
	) where

import Number.ModArithmetic (exponantiation_rtl_binary)

type Params = (Integer,Integer) {- P prime, G generator -}

newtype PublicNumber = PublicNumber Integer {- Y -}
	deriving (Show,Read,Eq,Enum,Real,Num,Ord)

newtype PrivateNumber = PrivateNumber Integer {- X -}
	deriving (Show,Read,Eq,Enum,Real,Num,Ord)

newtype SharedKey = SharedKey Integer {- S -}
	deriving (Show,Read,Eq,Enum,Real,Num,Ord)

generatePublic :: Params -> PrivateNumber -> PublicNumber
generatePublic (p,g) (PrivateNumber x) = PublicNumber $ exponantiation_rtl_binary g x p

getShared :: Params -> PrivateNumber -> PublicNumber -> SharedKey
getShared (p,_) (PrivateNumber x) (PublicNumber y) = SharedKey $ exponantiation_rtl_binary y x p
