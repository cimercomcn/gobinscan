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
        return true, nil
        // if f.TypeName == "elf" {
        //     return true, nil
        // } else {
        //     return false, errors.New("    [ELF] <> [NOT ELF] file_type_index_table")
        // }
        // } else if f.TypeName == "elf" {
        //     return false, errors.New("[NOT ELF] <> [ELF]     file_type_index_table")
    } else {
        return false, nil
    }
}

// // CheckUnknownELf 检查在未知文件中是否有elf的文件，如果有就加20分
// //  @param unknowns
// //  @return ret
// func checkUnknownELf(unknowns []ExtractedFile) (unknownElfFiles []ExtractedFile) {
//     for _, f := range unknowns {
//         // 跳过目录
//         if f.TypeIndex == FILETYPE_DIR {
//             continue
//         }

//         // 尝试打开文件
//         file, err := os.Open(filepath.Join(f.Dir, f.Name))
//         if golog.CheckError(err) {
//             continue
//         }
//         defer file.Close()

//         // 获取文件的类型
//         // MatchReader bug:
//         // 如果文件名为console，则会无限卡死。
//         if f.Name == "console" {
//             continue
//         }

//         kind, err := filetype.MatchReader(file)
//         if golog.CheckError(err) {
//             continue
//         }
//         // 代码校验为 elf
//         if kind.Extension == "elf" {
//             parts := strings.Split(f.Name, ".")
//             if len(parts) == 1 {
//                 f.Score += _cfgPtr.ScoreUnknownElf
//                 unknownElfFiles = append(unknownElfFiles, f)
//                 defaultLog.Warn(f.Name + " Find Unknown Elf File!!!\n")
//                 continue
//             }
//             if !queryFileSuffixTable(&f) {
//                 f.Score += _cfgPtr.ScoreUnknownSuffix
//             }
//         }
//     }
//     return
// }
