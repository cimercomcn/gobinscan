package scan

import (
    "errors"
    "os"

    "github.com/h2non/filetype"
    "github.com/neumannlyu/golog"
)

// 检查ELF文件格式。如果标明的类型是elf但是检测不是elf，或者相反，都将加分
//  @param kfile 文件结构
//  @return bool 结果。
func isElf(filepath string) (bool, error) {
    // 如果是目录
    fileInfo, _ := os.Stat(filepath)
    if fileInfo.Mode().IsDir() {
        return true, errors.New("directory skip")
    }
    // 手动修复"github.com/h2non/filetype"
    if fileInfo.Name() == "console" {
        return true, errors.New("console skip")
    }

    // 尝试打开文件
    file, err := os.Open(filepath)
    if golog.CatchError(err) {
        return false, err
    }
    defer file.Close()

    // 获取文件的类型
    kind, err := filetype.MatchReader(file)
    if golog.CatchError(err) {
        return false, err
    }

    // 代码校验为 elf
    if kind.Extension == "elf" {
        return true, nil
    } else {
        return false, nil
    }
}
