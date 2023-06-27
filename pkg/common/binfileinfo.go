package common

import (
    "crypto/md5"
    "encoding/hex"
    "io"
    "os"
    "path/filepath"

    "github.com/neumannlyu/golog"
)

type BinFileInfo struct {
    Name string
    Dir  string
    MD5  string
}

func (f BinFileInfo) GetMD5() string {
    // 打开要计算 MD5 的文件
    file, err := os.Open(filepath.Join(f.Dir, f.Name))
    if golog.CheckError(err) {
        panic(err)
    }
    defer file.Close()

    // 创建一个新的 MD5 hasher
    hasher := md5.New()
    // 将文件内容写入 hasher
    if _, err := io.Copy(hasher, file); golog.CheckError(err) {
        panic(err)
    }

    // 计算校验和并将其转换为十六进制字符串
    return hex.EncodeToString(hasher.Sum(nil))
}
