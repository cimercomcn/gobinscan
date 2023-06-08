package gobinscan

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/fatih/color"
    "github.com/neumannlyu/golog"
)

const (
    // 目录
    FILETYPE_DIR int = 0
    // 泛泛指代文件，不知道具体类型
    // todo 根据已知的文件，再做一个更加细致的分裂
    FILECATEGORY_FILE int = 1
    FILETYPE_ELF      int = 3

    /*
    	文件的重要性定义。
    */
    // 可以忽略的文件
    FILEIMPORTANCE_IGNORE = 0
    // 未知的文件，也不知道重要级别
    FILEIMPORTANCE_UNKNOWN = -1
)

// 文件的结构体，描述文件的信息
type File struct {
    // 文件名
    FileName string
    // 文件所在的目录
    FileDir string
    // 文件类别。区分目录和一般文件。
    TypeIndex int
    // 文件类别名称说明。
    TypeName string
    // 该文件的重要性。如果重要性为0，在分析的时候直接忽略。
    Score int
    // 这个文件出现的次数
    Count int
    // 该文件的md5值。
    Md5 string
    // 文件的描述信息。
    Description string
}

// ScanExtractedFiles 分析提取出来的文件。
//  @param root 要分析的目录
//  @return knownf 已知文件信息的数组
//  @return unknownf 未知文件的信息数组
func scanExtractedFiles(root string) (knownfiles, unknownfiles []File) {
    // 搜索root（一般为释放的目录）下的所有文件。
    // 这里的搜索不是遍历，会根据固件的特性，避免分析某些文件和文件夹
    allfiles := walkBinExtractedDir(root)

    for _, file := range allfiles {
        if isKnownFile(&file, allfiles) {
            knownfiles = append(knownfiles, file)
        } else { // 未知文件
            file.Score = cfg.ScoreUnknown
            unknownfiles = append(unknownfiles, file)
            var tag golog.LogLevel
            tag.Tag = " UNKNOWN "
            tag.Fgcolor = color.FgHiYellow
            tag.Font = color.Underline
            NewLog(tag).Logln(file.FileName)
        }
    }
    return
}

// walkBinExtractedDir 根据固件文件的特性，遍历文件。
// skip dir: web http
// skip file: 以.开头的文件，一般情况下这些文件为无关的隐藏文件。
//  @param current_path 想要遍历的目录
//  @return files 文件信息数组
func walkBinExtractedDir(current_path string) (files []File) {
    // 获取指定目录中的所有文件和子目录
    fs, err := os.ReadDir(current_path)
    if golog.CheckError(err) {
        return
    }

    // 遍历目录中的文件。如果遇到某些文件时，将跳过。
    for _, file := range fs {
        if file.IsDir() {
            // 如果是存放网页相关的就跳过。
            if isStringArrayContain(strings.ToLower(file.Name()), cfg.SkipDir) {
                continue
            }

            var kf File
            kf.FileName = file.Name()
            kf.FileDir = current_path
            kf.TypeIndex = FILETYPE_DIR // 文件的类别为目录
            files = append(files, kf)
            // 如果是目录，递归遍历该目录
            // fas = file attributes
            fas := walkBinExtractedDir(filepath.Join(current_path, file.Name()))
            if err != nil {
                return []File{}
            }

            // 保存结果
            files = append(files, fas...)
        } else {
            // 如果以.开头，也跳过
            if strings.HasPrefix(file.Name(), ".") {
                continue
            }

            // 如果是文件，进行处理
            var kf File
            kf.FileName = file.Name()
            kf.FileDir = current_path
            kf.TypeIndex = FILECATEGORY_FILE // 文件类别为普通文件

            // 保存结果
            files = append(files, kf)
        }
    }
    return
}

// IsStringArrayContain 判断str是否在array字符串数组中
//
//	@param str
//	@param array
//	@return bool
func isStringArrayContain(str string, array []string) bool {
    for _, item := range array {
        if str == item {
            return true
        }
    }
    return false
}

// 检查文件是否是已知的文件，如果是已知文件会更新文件的重要性评分和描述信息。
// @file 待检查的文件
// @allfiles 固件中提取出所有的文件
// @return 是否是已知文件
func isKnownFile(file *File, allfiles []File) bool {
    var mytag golog.LogLevel
    mytag.Tag = "   OK    "
    mytag.Fgcolor = color.FgHiBlue
    mytag.Font = color.Underline
    mylog := NewLog(mytag)
    /*
       下面开始进行文件的分析。主要通过文件是否存在于已知文件表中、能不能通过文件的后缀名来进行判断，
       以及有没有相同名的压缩文件（如.xz）来进行判断文件的左右。
    */
    // 1.通过文件全名来识别
    if queryKnownFileTable(file) {
        mylog.Logln(file.FileName + " {=} " + file.Description)
        return true
    }

    // 2. 通过文件的后缀名来识别
    if queryFileSuffixTable(file) {
        mylog.Logln(file.FileName + " {=} " + file.Description)
        return true
    }

    // 3. 可能是压缩文件解压出来的文件
    isHava, file_name := hasSameNameCompressedFile(file.FileName, allfiles)
    if isHava {
        file.Score = 0
        file.Description = fmt.Sprintf("%s {unzip} %s", file_name, file.FileName)
        mylog.Logln(file.FileName + "{=}" + file.Description)
        return true
    }
    return false
}

// hasSameNameCompressedFile 确认是否有和该文件名相同的名字的压缩文件。如果SA文件，就会查找是否有SA.xz等压缩文件
//  @param name 要查找的文件
//  @param files 查找的范围
//  @return bool 是否有同名的压缩文件
//  @return string 同名的压缩文件的名称
func hasSameNameCompressedFile(name string, files []File) (bool, string) {
    for _, file := range files {
        basename := strings.TrimSuffix(file.FileName, filepath.Ext(file.FileName))
        suffixname := filepath.Ext(file.FileName)
        if len(suffixname) == 0 {
            continue
        }
        if basename == name {
            for _, suf := range cfg.CompressSuffix {
                if suf == suffixname {
                    return true, file.FileName
                }
            }
        }
    }
    return false, ""
}
