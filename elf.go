package gobinscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/h2non/filetype"
	"github.com/neumannlyu/golog"
)

// 检查当前校验的类型和数据库中登记的类型是否都为elf
// 检查目标为已知文件。如果存在出入，则会加分
func checkElfFilesType(files []ExtractedFile) (passed, warn int) {
    passed = 0
    warn = 0
    var mytag golog.LogLevel
    mytag.Tag = "PASS"
    mytag.Fgcolor = color.FgGreen
    mylog := NewLog(mytag)
    mylog.UpdateElement(mytag)
    for _, f := range files {
        ok, err := checkElfFileType(f)
        if ok {
            mylog.Logln(f.Name)
            passed++
        } else {
            defaultLog.Warn(fmt.Sprintf("%30s", f.Name) + " " + err.Error() + "\n")
            f.Score += 10
            warn++
        }
    }
    return
}

// 检查ELF文件格式。如果标明的类型是elf但是检测不是elf，或者相反，都将加分
//  @param kfile 文件结构
//  @return bool 结果。
func checkElfFileType(f ExtractedFile) (bool, error) {
    filepath := filepath.Join(f.Dir, f.Name)
    // 如果是目录
    fileInfo, _ := os.Stat(filepath)
    if fileInfo.Mode().IsDir() {
        return true, errors.New("directory skip")
    }

    // 手动修复"github.com/h2non/filetype"
    if f.Name == "console" {
        return true, errors.New("console skip")
    }

    // 尝试打开文件
    file, err := os.Open(filepath)
    if golog.CheckError(err) {
        return false, err
    }
    defer file.Close()

    // 获取文件的类型
    kind, err := filetype.MatchReader(file)
    if golog.CheckError(err) {
        return false, err
    }

    // 代码校验为 elf
    if kind.Extension == "elf" {
        if f.TypeName == "elf" {
            return true, nil
        } else {
            return false, errors.New("    [ELF] <> [NOT ELF] file_type_index_table")
        }
    } else if f.TypeName == "elf" {
        return false, errors.New("[NOT ELF] <> [ELF]     file_type_index_table")
    } else {
        return true, nil
    }
}

// CheckUnknownELf 检查在未知文件中是否有elf的文件，如果有就加20分
//  @param unknowns
//  @return ret
func checkUnknownELf(unknowns []ExtractedFile) (unknownElfFiles []ExtractedFile) {
    for _, f := range unknowns {
        // 跳过目录
        if f.TypeIndex == FILETYPE_DIR {
            continue
        }

        // 尝试打开文件
        file, err := os.Open(filepath.Join(f.Dir, f.Name))
        if golog.CheckError(err) {
            continue
        }
        defer file.Close()

        // 获取文件的类型
        // MatchReader bug:
        // 如果文件名为console，则会无限卡死。
        if f.Name == "console" {
            continue
        }

        kind, err := filetype.MatchReader(file)
        if golog.CheckError(err) {
            continue
        }
        // 代码校验为 elf
        if kind.Extension == "elf" {
            parts := strings.Split(f.Name, ".")
            if len(parts) == 1 {
                f.Score += cfg.ScoreUnknownElf
                unknownElfFiles = append(unknownElfFiles, f)
                defaultLog.Warn(f.Name + " Find Unknown Elf File!!!\n")
                continue
            }
            if !queryFileSuffixTable(&f) {
                f.Score += cfg.ScoreUnknownSuffix
            }
        }
    }
    return
}
