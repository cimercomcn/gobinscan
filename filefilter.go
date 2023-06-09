package gobinscan

import (
	"os"
	"path/filepath"

	"github.com/neumannlyu/golog"
)

// IgnoreAlias 忽略法则1: 忽略Alisa文件
//  @param pkfile 未过滤前的文件数组
//  @return []KnownFile 过滤后的文件数组
func runAliasFilter(files []ExtractedFile) (ret []ExtractedFile) {
    for _, f := range files {
        filepath := filepath.Join(f.Dir, f.Name)
        if isAliasFile(filepath) {
            defaultLog.Info("ignore " + filepath + "." + "\n")
        } else {
            ret = append(ret, f)
        }
    }
    return
}

// RunElfFilter 过滤出类型为elf的文件
//  @param files
//  @return ret
func runElfFilter(files []ExtractedFile) (ret []ExtractedFile) {
    for _, f := range files {
        if f.TypeIndex == FILETYPE_ELF {
            ret = append(ret, f)
        }
    }
    return ret
}

// isAliasFile 判断文件是否为Alisa类型
//  @param filepath 文件路径
//  @return bool
func isAliasFile(filepath string) bool {
    fileInfo, err := os.Lstat(filepath)
    if golog.CheckError(err) {
        return false
    }

    if fileInfo.Mode()&os.ModeSymlink != 0 {
        return true
    } else {
        return false
    }
}
