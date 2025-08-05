{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

import Control.Applicative (optional)
import Control.Monad (when)

-- Corrected imports for HMAC and SHA512
import Crypto.Hash.Algorithms (SHA512)
import Crypto.MAC.HMAC (HMAC, hmac)
import Crypto.Random (getRandomBytes)

import Data.ByteArray qualified as BA
import Data.ByteString qualified as BS
import Data.ByteString.Char8 qualified as BS.C
import Data.Char (isAscii)
import Data.Map qualified as Map
import Options.Applicative qualified as OA
import System.Directory (
  createDirectoryIfMissing,
  doesDirectoryExist,
  doesFileExist,
  getHomeDirectory,
 )
import System.FilePath (normalise, takeDirectory, (</>))
import Text.Read (readMaybe)

-- | 定义程序的四种工作模式
data Mode = Port | Password | Id | Other deriving (Show, Eq)

-- | 定义命令行选项的数据结构
data Options = Options
  { optMode :: Maybe Mode
  , optLength :: Maybe Int
  , optKeyPath :: Maybe FilePath
  , optOutputPath :: Maybe FilePath
  , optInput :: BS.ByteString
  }
  deriving (Show)

-- | 将字符串解析为 Mode
modeReader :: OA.ReadM Mode
modeReader =
  (OA.str :: OA.ReadM BS.ByteString) >>= \case
    "port" -> return Port
    "password" -> return Password
    "id" -> return Id
    "other" -> return Other
    _ -> OA.readerError "Invalid mode. Use 'port', 'password', 'id', or 'other'."

optModeParser :: OA.Parser (Maybe Mode)
optModeParser =
  optional
    ( OA.option
        modeReader
        ( OA.long "mode"
            <> OA.short 'm'
            <> OA.metavar "MODE"
            <> OA.help "Processing mode: port, password, id, other. Default: id"
        )
    )
optLengthParser :: OA.Parser (Maybe Int)
optLengthParser =
  optional
    ( OA.option
        OA.auto
        ( OA.long "length"
            <> OA.short 'l'
            <> OA.metavar "LENGTH"
            <> OA.help "Output length (4-128)."
        )
    )
optKeyPathParser :: FilePath -> OA.Parser (Maybe FilePath)
optKeyPathParser homeDir =
  optional
    ( OA.strOption
        ( OA.long "key"
            <> OA.short 'k'
            <> OA.metavar "KEY_PATH"
            <> OA.help ("Path to the key file for hashing. Default: " ++ homeDir </> ".ssh" </> "obfuscator-key")
        )
    )
optOutputPathParser :: FilePath -> OA.Parser (Maybe FilePath)
optOutputPathParser homeDir =
  optional
    ( OA.strOption
        ( OA.long "output"
            <> OA.short 'o'
            <> OA.metavar "OUTPUT_PATH"
            <> OA.help ("Path to the output file. Default: " ++ homeDir </> "Documents" </> "obfuscator-list.txt")
        )
    )
optInputParser :: OA.Parser BS.ByteString
optInputParser =
  OA.strArgument
    ( OA.metavar "INPUT"
        <> OA.help "The input string to process (e.g., a port number, a domain name)."
    )

-- | 带有程序描述的主解析器
optMainParser :: FilePath -> OA.ParserInfo Options
optMainParser homeDir =
  OA.info
    ( Options
        <$> optModeParser
        <*> optLengthParser
        <*> optKeyPathParser homeDir
        <*> optOutputPathParser homeDir
        <*> optInputParser
          OA.<**> OA.helper
    )
    ( OA.fullDesc
        <> OA.progDesc "A tool to obfuscate inputs for privacy and security."
        <> OA.header "obfuscator - Hash and transform your secrets"
    )

-- | 获取密钥。如果未指定，则检查默认路径；如果不存在，则生成新密钥。
getKey :: FilePath -> IO BS.ByteString
getKey keyPath = do
  createDirectoryIfMissing True (takeDirectory keyPath) -- 确保读取文件目录存在，无论文件本身
  keyExists <- doesFileExist keyPath -- 检查读取文件是否存在
  if keyExists
    then do
      content <- BS.readFile keyPath
      when (BS.length content > 4096) $
        BS.putStr "Warning: Key file content exceeds 4096 bytes.\n"
      when (BS.null content) $
        fail $
          "Error: Key file is empty: " ++ keyPath
      return content
    else do
      keyPathIsDir <- doesDirectoryExist keyPath -- 检查读取文件是否为文件夹 (检查前文件夹已创建)
      let newKeyPath = if keyPathIsDir then keyPath </> "obfuscator-key" else keyPath -- 若为文件夹，则添加文件名路径
      putStrLn $ "Key file not found. Generating a new 4096-byte key at: " ++ newKeyPath
      newKey <- getRandomBytes 4096
      BS.writeFile newKeyPath newKey
      return newKey

-- | 将结果输出到控制台和文件
writeOutput :: Mode -> FilePath -> BS.ByteString -> BS.ByteString -> IO ()
writeOutput mode outputPath input result = do
  createDirectoryIfMissing True (takeDirectory outputPath) -- 确保写入文件目录存在，无论文件本身
  outputPathIsDir <- doesDirectoryExist outputPath -- 检查写入文件是否为文件夹 (检查前文件夹已创建)
  -- 不用检查写入文件存在
  let newOutputPath = if outputPathIsDir then outputPath </> "obfuscator-list.txt" else outputPath -- 若为文件夹，则添加文件名路径
  let content = BS.concat ["Mode: ", BS.C.pack . show $ mode, ", Input: ", input, ", Output: ", result, "\n"]
  BS.appendFile newOutputPath content
  putStrLn $ "Result appended to: " ++ newOutputPath

-- | 【重写】模式实现：生成安全端口号 (1024-65535)
generatePort :: BS.ByteString -> BS.ByteString -> IO BS.ByteString
generatePort input hashedInput = do
  let maybePort = readMaybe . BS.C.unpack $ input :: Maybe Int
  case maybePort of
    Just p | p < 0 || p > 65535 -> fail "Error: Port number must be between 0 and 65535."
    Just _ -> do
      let largeInteger :: Int = BS.foldl' (\acc w -> acc * 256 + fromIntegral w) 0 (BS.take 8 hashedInput)
      let portRange = 65535 - 1024 + 1
      let newPort = 1024 + (largeInteger `mod` portRange)
      return . BS.C.pack . show $ newPort
    _ -> fail "Error: Port input must be a valid number."

-- | 【新增】为 Other 模式生成纯字母数字字符串
generateAlphaNumString :: Int -> BS.ByteString -> BS.ByteString
generateAlphaNumString len hashedInput =
  let
    alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" :: BS.ByteString
    hashLen = BS.length hashedInput
    -- 安全地从字节生成字符，使用取模来模拟循环，防止越界
    byteToChar idx =
      let byte = hashedInput `BS.index` (idx `mod` hashLen)
       in alphaNum `BS.index` (fromIntegral byte `mod` BS.length alphaNum)
   in
    BS.pack [byteToChar i | i <- [0 .. len - 1]]

-- | 【新增】为 Password 模式生成包含2个特殊字符的密码
generatePasswordString :: Int -> BS.ByteString -> BS.ByteString
generatePasswordString len rawHashedInput =
  let
    specialChars = "!@#$%^&*()-+/" :: BS.ByteString
    alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" :: BS.ByteString
    hashLen = BS.length rawHashedInput

    -- 辅助函数，用于安全地从哈希字节中获取一个值
    getByte :: Int -> Int
    getByte idx = fromIntegral $ rawHashedInput `BS.index` (idx `mod` hashLen)

    -- 1. 确定两个不重复的、用于插入特殊字符的位置
    pos1 = getByte 0 `mod` len
    -- 为了保证 pos2 不等于 pos1，我们在 len-1 的范围内取值，然后进行调整
    pos2' = getByte 1 `mod` (len - 1)
    pos2 = if pos2' >= pos1 then pos2' + 1 else pos2'

    -- 2. 确定要使用的两个特殊字符
    specialChar1 = specialChars `BS.index` (getByte 2 `mod` BS.length specialChars)
    specialChar2 = specialChars `BS.index` (getByte 3 `mod` BS.length specialChars)

    -- 3. 将特殊字符和它们的位置放入一个Map中，便于查找
    specialMap = Map.fromList [(pos1, specialChar1), (pos2, specialChar2)]

    -- 4. 生成最终的密码字符串
    -- 我们从哈希字节索引4开始为字母数字字符获取随机性，避免与位置和特殊字符的选择冲突
    generateChar i =
      case Map.lookup i specialMap of
        Just spChar -> spChar -- 如果当前位置是特殊字符位，则使用Map中的特殊字符
        Nothing -> alphaNum `BS.index` (getByte (i + 4) `mod` BS.length alphaNum) -- 否则，生成一个字母数字字符
   in
    BS.pack [generateChar i | i <- [0 .. len - 1]]

-- | 【修正】为 Id 模式生成专用字符串，确保前两位是字母
generateIdString :: Int -> BS.ByteString -> BS.ByteString
generateIdString len rawHashedInput =
  let
    letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" :: BS.ByteString
    alphaNum = BS.append letters "0123456789"
    hashLen = BS.length rawHashedInput

    -- 安全地从字节生成字符，使用取模来模拟循环，防止越界
    byteToChar charSet idx =
      let byte = rawHashedInput `BS.index` (idx `mod` hashLen)
       in charSet `BS.index` (fromIntegral byte `mod` BS.length charSet)

    -- 生成ID的各个部分
    char1 = byteToChar letters 0
    char2 = byteToChar letters 1
    rest = [byteToChar alphaNum i | i <- [2 .. len - 1]]
   in
    BS.pack $ char1 : char2 : rest

-- | 【重写】根据模式处理哈希值并生成最终结果
mainGenerator :: Mode -> Int -> BS.ByteString -> BS.ByteString -> IO BS.ByteString
mainGenerator Port _ input hashedInput = generatePort input hashedInput
mainGenerator Password len _ hashedInput = return $ generatePasswordString len hashedInput
mainGenerator Id len _ hashedInput = return $ generateIdString len hashedInput
mainGenerator Other len _ hashedInput = return $ generateAlphaNumString len hashedInput

-- | 主函数
main :: IO ()
main = do
  homeDir <- getHomeDirectory
  opts <- OA.execParser (optMainParser homeDir)

  finalMode <- case optMode opts of
    Just x -> return x
    Nothing -> return Id

  finalLength <- case optLength opts of
    Just _ | finalMode == Port -> fail "Error: Cannot specify length for 'Port'"
    Just x | x < 4 || x > 128 -> fail "Error: Length must be between 4 and 128."
    Just x -> return x
    Nothing -> case finalMode of
      Port -> return 4 -- Port模式不使用此长度，仅为占位
      Password -> return 16
      Id -> return 8
      Other -> return 16

  finalKeyPath <- case optKeyPath opts of
    Just x -> return . normalise $ x
    Nothing -> return $ homeDir </> ".ssh" </> "obfuscator-key"

  finalOutputPath <- case optOutputPath opts of
    Just x -> return . normalise $ x
    Nothing -> return $ homeDir </> "Documents" </> "obfuscator-list.txt"

  finalInput <- case optInput opts of
    x | all isAscii (BS.C.unpack x) -> case finalMode of
      Password -> return $ BS.append x "-password"
      _ -> return x
    _ -> fail "Error: INPUT is not ASCII character."

  key <- getKey finalKeyPath

  let hashedInput = BA.convert (hmac key finalInput :: HMAC SHA512)
  result <- mainGenerator finalMode finalLength finalInput hashedInput

  BS.putStr . BS.concat $ ["Mode: ", BS.C.pack . show $ finalMode, "\nInput: ", optInput opts, "\nOutput: ", result, "\n\n"]
  writeOutput finalMode finalOutputPath (optInput opts) result
