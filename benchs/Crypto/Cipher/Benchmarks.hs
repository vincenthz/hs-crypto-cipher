-- |
-- Module      : Crypto.Cipher.Benchmarks
-- License     : BSD-style
-- Maintainer  : Vincent Hanquez <vincent@snarc.org>
-- Stability   : Stable
-- Portability : Excellent
--
-- benchmarks for symmetric ciphers
--
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE Rank2Types #-}
module Crypto.Cipher.Benchmarks
    ( defaultMain
    , GBlockCipher(..)
    ) where

import Control.Applicative
import Criterion
import Criterion.Environment
import Criterion.Config hiding (Help)
import Criterion.Monad
import Criterion.Analysis
import Criterion.Measurement

import Text.Printf
import Text.PrettyPrint hiding (Mode, mode)

import Data.Maybe
import Control.Monad.Trans

import qualified Data.ByteString as B

import Crypto.Cipher.Types

import System.Console.GetOpt
import System.Environment
import System.Exit

import Data.Char (toUpper)

-- | Generic Block cipher that wrap a specific block cipher.
data GBlockCipher = forall a . BlockCipher a => GBlockCipher a

data Mode = ECB
          | CBC
          | CTR
          deriving (Show, Enum, Bounded)

defaultSzs :: [Int]
defaultSzs = [16,32,128,512,1024,4096,16384]

defaultModes :: [Mode]
defaultModes = [minBound..]

doCipher :: Environment -> Int -> [Int] -> (B.ByteString -> B.ByteString) -> Criterion [Double]
doCipher env nbIter szs f = mapM getMeanFromBench szs
  where getMeanFromBench sz =
            runBenchmark env (whnf f $ B.replicate sz 0) >>= \sample ->
            analyseMean sample nbIter >>= return

modeToBench :: BlockCipher cipher => cipher -> Mode -> (B.ByteString -> B.ByteString)
modeToBench cipher ECB = ecbEncrypt cipher
modeToBench cipher CBC = cbcEncrypt cipher nullIV
modeToBench cipher CTR = ctrCombine cipher nullIV

modesToBench :: BlockCipher cipher => cipher -> [Mode] -> [(Mode, B.ByteString -> B.ByteString)]
modesToBench cipher = map (\mode -> (mode, modeToBench cipher mode))

data Report = Report
    { reportSz     :: Int
    , reportMean   :: Double
    , reportSecs   :: String
    , reportSpeed  :: Double
    , reportSpeedS :: String
    } deriving (Show)

doOne :: Int -> Environment -> [Int] -> String -> (B.ByteString -> B.ByteString) -> Criterion (String, [Report])
doOne iters env szs name f = do
    means <- doCipher env iters szs f
    return (name, map toReport $ zip means szs)
  where toReport (mean, sz) = Report
            { reportSz     = sz
            , reportMean   = mean
            , reportSecs   = secs mean
            , reportSpeed  = norm sz mean
            , reportSpeedS = pn (norm sz mean)
            }

        norm :: Int -> Double -> Double
        norm n meanTime
            | n < 1024  = 1.0 / (meanTime * (1024 / fromIntegral n))
            | n == 1024 = 1.0 / meanTime
            | otherwise = 1.0 / (meanTime / (fromIntegral n / 1024))

        pn :: Double -> String
        pn val
            | val > (10 * 1024) = printf "%.1f M/s" (val / 1024)
            | otherwise         = printf "%.1f K/s" val


runBench :: Int -> [Int] -> [Mode] -> [GBlockCipher] -> Criterion ()
runBench iters szs modes ciphers = do
    env     <- measureEnvironment
    reports <- concat <$> mapM (runBenchCipher env) ciphers
    let docHeader = col1 "cipher name" <+> hsep (map (textOf 12 . show) szs)
    let doc = vcat (docHeader : map toLine reports)
           
    liftIO $ putStrLn $ show doc
    
  where runBenchCipher env (GBlockCipher cipher) = do
            let name   = cipherName cipher
                benchs = modesToBench cipher modes
            mapM (\(benchMode, benchF) -> doOne iters env szs (name ++ "-" ++ show benchMode) benchF) benchs
        toLine (name, szReports) =
            hsep (col1 name : map (textOf 12 . reportSpeedS)  szReports)
        textOf n s | len == n  = text s
                   | len < n   = text (s ++ replicate (n - len) ' ')
                   | otherwise = text (take n s)
          where len = length s
        col1 = textOf 14
        
data OptionArg = SizeArg String
               | CipherArg String
               | ModeArg String
               | Iter String
               | Help
               deriving (Show,Eq)

wordsWhen :: (Char -> Bool) -> String -> [String]
wordsWhen p s =
    case dropWhile p s of
        "" -> []
        s' -> w : wordsWhen p s''
              where (w, s'') = break p s'

instanciateCiphers :: [GBlockCipher] -> [GBlockCipher]
instanciateCiphers ciphers = map proxy ciphers
  where proxy :: GBlockCipher -> GBlockCipher
        proxy (GBlockCipher c) = GBlockCipher $ instanciate c
        instanciate :: BlockCipher a => a -> a
        instanciate c =
            let bs = case cipherKeySize c of
                            Nothing -> B.replicate 1 0
                            Just sz -> B.replicate sz 1
             in cipherInit (fromJust $ makeKey bs)

defaultMain :: [GBlockCipher] -> IO ()
defaultMain ciphers = do
    args <- getArgs
    case getOpt Permute opts args of
        (os,_,[]) | Help `elem` os -> do putStrLn (usageInfo "crypto-cipher-benchmark" opts)
                                         exitFailure
                  | otherwise -> do let (ss, ms, iters) = foldl (\(sp, mp, it) o ->
                                            case o of
                                                SizeArg s -> (map read $ wordsWhen (== ',') s, mp, it)
                                                ModeArg s -> let modes = wordsWhen (== ',') $ map toUpper s
                                                                 nm    = filter (\m -> show m `elem` modes) mp
                                                              in (sp, nm, it)
                                                Iter s      -> (sp, mp, read s)
                                                CipherArg _ -> (sp, mp, it)
                                                _           -> (sp, mp, it)
            
                                            ) (defaultSzs, defaultModes, 100) os
                                    withConfig defaultConfig $ runBench iters ss ms (instanciateCiphers ciphers)
        (_,_,err) -> error (show err)
  where opts =
            [ Option ['n'] ["iter"] (ReqArg Iter "iteration") "number of iterations per benchmarks"
            , Option [] ["size"] (ReqArg SizeArg "size") "size to run (csv)"
            , Option [] ["cipher"] (ReqArg CipherArg "cipher") "cipher to run (csv)"
            , Option [] ["mode"] (ReqArg ModeArg "mode") "mode to run (csv)"
            , Option ['h'] ["help"] (NoArg Help) "get help"
            ]
