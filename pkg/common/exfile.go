package common

import (
    "errors"
    "fmt"
    "os/exec"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"

    "github.com/neumannlyu/golog"
)

// 文件的结构体，描述文件的信息
type ExtractedFile struct {
    ///////////////////  这部分对应known file table表///////////////////
    // 文件名
    Name string
    // 文件所在的目录
    Dir string
    // flag
    Flag uint32
    // 该文件的重要性。如果重要性为0，在分析的时候直接忽略。
    Rating int
    // 这个文件出现的次数
    Count int
    // 文件的描述信息。
    Description string
    //////////////////////////////////////////////////////////////////

    // 搜索版本信息时的关键字
    VersionSearchKey string
    // 过滤出版本信息的正则表达式
    VersionSearchRegular string
    // 版本信息
    Version Version
    // 该文件的md5值。
    Md5 string
}

// Get the version information of the binary program file.
func (exfile *ExtractedFile) GetBinaryVersion() error {
    cmd1 := exec.Command("sh", "-c", fmt.Sprintf("strings \"%s\"",
        filepath.Join(exfile.Dir, exfile.Name)))
    cmd2 := exec.Command("grep", exfile.VersionSearchKey)

    pipe, err := cmd1.StdoutPipe()
    if golog.CatchError(err) {
        return err
    }
    defer pipe.Close()

    cmd1.Start()
    cmd2.Stdin = pipe
    if output, err := cmd2.Output(); golog.CatchError(err) {
        return err
    } else {
        // 分割筛选后的字符串
        lines := strings.Split(string(output), "\n")

        for _, line := range lines {
            re := regexp.MustCompile(exfile.VersionSearchRegular)
            // 判断字符串是否匹配正则表达式
            if re.MatchString(line) {
                // 提取捕获组中的 x.y.z
                matches := re.FindStringSubmatch(line)[1:]
                if len(matches) == 2 {
                    // 将 x.y.z 转换成整数，保存到结构体中
                    exfile.Version.MajorVersion, _ = strconv.Atoi(matches[0])
                    exfile.Version.MinorVersion, _ = strconv.Atoi(matches[1])
                    exfile.Version.PatchVersion = -1
                    return nil
                } else if len(matches) == 3 {
                    // 将 x.y.z 转换成整数，保存到结构体中
                    exfile.Version.MajorVersion, _ = strconv.Atoi(matches[0])
                    exfile.Version.MinorVersion, _ = strconv.Atoi(matches[1])
                    exfile.Version.PatchVersion, _ = strconv.Atoi(matches[2])
                    return nil
                }
            } else {
                fmt.Println("else")
            }
        }
    }
    return errors.New("error version")
}
