package scan

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "172.16.2.38/neumannlyu/gobinscan/pkg/common"
    "172.16.2.38/neumannlyu/gobinscan/pkg/sql"
    "github.com/neumannlyu/golog"
)

// ScanExtractedFiles 分析提取出来的文件。
//  @param root 要分析的目录
//  @return knownf 已知文件信息的数组
//  @return unknownf 未知文件的信息数组
func scanExtractedFiles(root string) {
    // 天花板。筛选后剩下的文件
    // ceiling := make([]common.ExtractedFile, 0)
    // 地板。筛选出的文件
    // floor := make([]common.ExtractedFile, 0)

    // 搜索root（一般为释放的目录）下的所有文件。
    // 这里的搜索不是遍历，会根据固件的特性，避免分析某些文件和文件夹
    allfiles := scanExtractedDir(root, 1)

    // 这里是扫描分析文件的核心代码，执行的顺序分为：
    // 1. 过滤文件。根据扫描策略配置，过滤掉不关心的文件。
    for _, exfile := range allfiles {
        filepath := filepath.Join(exfile.Dir, exfile.Name)
        // 1. 过滤
        // 过滤1: 如果是别名的文件过滤。（受配置控制）
        if _cfgPtr.ScanPolicy.IsIgnoreAlias {
            if isAliasFile(filepath) {
                _cfgPtr.Logs.Ignored.Logln(
                    "ignored alias file: " + filepath + ".")
                continue
            }
        }
        //
        // 下面开始进行文件的分析。主要通过文件是否存在于已知文件表中、
        // 能不能通过文件的后缀名来进行判断，以及有没有相同名的压缩文件
        //（如.xz）来进行判断文件的左右。
        //
        // 2. 是否收录
        var isKnown bool = true
        _cfgPtr.Logs.CommonLog.Info(exfile.Name + "\n")
        // 2.1 通过文件全名来识别。在已知文件表中查找
        if sql.Isql.IsKnownFileByName(&exfile) {
            _cfgPtr.Logs.OK2.Logln(exfile.Description)
        } else if sql.Isql.IsKnownFileByType(&exfile) {
            // 2.2 通过文件的类型来进行识别。
            _cfgPtr.Logs.OK2.Logln(exfile.Description)
        } else if compressFileName, ok :=
            isDecompressed(exfile.Name, allfiles); ok {
            // 2.3 通过压缩文件来进行识别
            // ! 解压出文件
            exfile.Description = fmt.Sprintf("%s {unzip} %s",
                exfile.Name, compressFileName)
            _cfgPtr.Logs.OK2.Logln(exfile.Description)
        } else {
            isKnown = false
            _cfgPtr.Logs.Unknwon.Logln("无文件信息")
        }

        // 3. 文件类型校验
        // 3.1 elf
        //  一般情况下，从数据库中读出类型为elf，检验的结果也应该为elf，
        //  如果不一致，认为可能存在问题。
        ok, err := isElf(filepath)
        if err != nil {
            _cfgPtr.Logs.CommonLog.Error(err.Error())
        } else {
            if ok { // 该文件为elf
                if !isKnown { // 未知文件的elf
                    exfile.Rating += _cfgPtr.AddRatingUnknownElf
                    _cfgPtr.Logs.CommonLog.Warn("未知的ELF文件！！！  \n")
                } else {
                    if exfile.Flag&0x0000ffff != 3 /*elf文件类型编号*/ {
                        // 数据库不是elf
                        exfile.Rating += _cfgPtr.AddRatingCheckElf
                        _cfgPtr.Logs.CommonLog.Warn(
                            exfile.Name + "@elf != " + "database@not elf\n")
                    }
                    // 已知的elf文件统计一下，在后面程序漏洞扫描时直接使用
                    _knownElfFile = append(_knownElfFile, exfile)
                }
            } else { // 该文件不是elf
                if exfile.Flag&0x0000ffff == 3 /*elf文件类型编号*/ {
                    // 数据库是elf
                    exfile.Rating += _cfgPtr.AddRatingCheckElf
                    _cfgPtr.Logs.CommonLog.Warn(exfile.Name + "@not elf != " +
                        "database@elf\n")
                }
            }
        }

    }
}

// isDecompressed 确认是否有和该文件名相同的名字的压缩文件。
//  如果SA文件，就会查找是否有SA.xz等压缩文件
//  @param name 要查找的文件
//  @param files 查找的范围
//  @return bool 是否有同名的压缩文件
//  @return string 同名的压缩文件的名称
func isDecompressed(name string, files []common.ExtractedFile) (string, bool) {
    for _, file := range files {
        basename := strings.TrimSuffix(file.Name, filepath.Ext(file.Name))
        suffixname := filepath.Ext(file.Name)
        if len(suffixname) == 0 {
            continue
        }
        if basename == name {
            for _, suf := range _cfgPtr.CompressSuffix {
                if suf == suffixname {
                    return file.Name, true
                }
            }
        }
    }
    return "", false
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

// scanExtractedDir 根据固件文件的特性，遍历文件。
// skip dir: web http
// skip file: 以.开头的文件，一般情况下这些文件为无关的隐藏文件。
//  @param current_path 想要遍历的目录
//  @return files 文件信息数组
func scanExtractedDir(current_path string, curDepth int) (
    files []common.ExtractedFile) {
    // 获取指定目录中的所有文件和子目录
    var total int = 0
    var skip int = 0
    fs, err := os.ReadDir(current_path)
    if golog.CheckError(err) {
        return
    }

    // 遍历目录中的文件。如果遇到某些文件时，将跳过。
    for _, file := range fs {
        total++
        // 如果以.开头(隐藏文件)，也跳过
        if strings.HasPrefix(file.Name(), ".") {
            _cfgPtr.Logs.Skip.Logln("    " + file.Name())
            skip++
            continue
        }
        if file.IsDir() {
            // 1. 如果是存放网页相关的就跳过。
            if common.IsContainString(
                // 当前目录名
                strings.ToLower(file.Name()),
                // 在配置中设置的自定义跳过目录
                _cfgPtr.ScanPolicy.SkipCustomDirs) {
                _cfgPtr.Logs.Skip.Logln("    " + file.Name())
                skip++
                continue
            }

            // 2. 如果以 _开始 .extracted结束，则跳过文件夹
            if strings.HasPrefix(file.Name(), "_") &&
                strings.HasSuffix(file.Name(), ".extracted") {
                _cfgPtr.Logs.Skip.Logln("    " + file.Name())
                skip++
                continue
            }

            // !开启严格扫描策略下，只扫描 squashfs-root和相关的文件夹
            // 在第一层应该会有类似squashfs-root的目录，在严格模式下，只会分析这写文件夹
            if !strings.Contains(file.Name(), "squashfs-root") &&
                curDepth == 1 {
                _cfgPtr.Logs.Skip.Logln("    " + file.Name())
                skip++
                continue
            }

            // 如果用户需要分析目录
            if _cfgPtr.ScanPolicy.IsAnalysisDir {
                var exf common.ExtractedFile
                exf.Name = file.Name()
                exf.Dir = current_path
                exf.Flag = 0 // 文件夹的类型为0
                exf.Description = "folder"
                files = append(files, exf)
            }

            // 如果是目录，递归遍历该目录
            exfs := scanExtractedDir(
                filepath.Join(current_path, file.Name()),
                curDepth+1)
            // 保存结果
            files = append(files, exfs...)
        } else {
            // 如果是文件，进行处理
            var exf common.ExtractedFile
            exf.Name = file.Name()
            exf.Dir = current_path
            exf.Flag = 1 // 普通文件为1
            exf.Description = "common file"
            _cfgPtr.Logs.CommonLog.Info(" << " + exf.Name + "\n")
            // 保存结果
            files = append(files, exf)
        }
    }
    return
}
