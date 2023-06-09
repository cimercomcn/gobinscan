package gobinscan

import (
    "fmt"
    "os/exec"
    "path/filepath"
    "regexp"
    "strconv"
    "strings"

    "github.com/fatih/color"
    "github.com/neumannlyu/golog"
)

// 分析模块的运行入口，调用这个函数开始分析
//
//	@param rootdir bin文件提取后保存的路径
func analysis(rootdir string) {
    // 1. 分析提取的文件。
    // 粗略地遍历展开的所有文件，把文件分为已知和未知两大类型文件。
    knownfiles, unknwonfiles := scanExtractedFiles(rootdir)
    defaultLog.Info(
        fmt.Sprintf("\n\n\n\t\t\t\t\t[文件扫描完成]\n\t\t\t\t\t[识别率] %.2f%%\n\n",
            float64(len(knownfiles))/float64(len(knownfiles)+len(unknwonfiles))*100))

    // 2. 检查ELF文件。
    // 一般情况下，从数据库中读出类型为elf，检验的结果也应该为elf，如果不一致，认为可能存在问题，在得分上加10分
    defaultLog.Info("开始校验ELF文件...\n")
    passed, warn := checkElfFilesType(knownfiles)
    oKLog.Logln("校验ELF文件完成。")
    color.New(color.BgWhite).Print(fmt.Sprintf("                                [PASS - %d] [WARN - %d]                                ", passed, warn))
    fmt.Printf("\n\n\n")

    // 3. 未知中的elf 加20分
    defaultLog.Info("开始分析未知ELF文件...\n")
    unknwonElfFiles := checkUnknownELf(unknwonfiles)
    defaultLog.Info("分析未知ELF文件完成。\n")

    // 4. 过滤一些文件类型
    defaultLog.Info("开始过滤文件...\n\n")
    // 过滤1: 如果是别名的文件过滤。（受配置控制）
    if !cfg.IgnoreAlias {
        // 忽略
        knownfiles = runAliasFilter(knownfiles)
        unknwonfiles = runAliasFilter(unknwonfiles)
    }
    oKLog.Logln("完成过滤文件")

    // 分析内核CVE
    defaultLog.Info("开始分析内核漏洞...\n\n")
    analysisKernelCVE(rootdir)
    defaultLog.Info("内核漏洞分析完成\n\n")

    // 分析程序漏洞
    defaultLog.Info("开始分析二进制可执行程序漏洞...\n")
    // 1. 过滤出所有的elf文件，然后查找binary file table。
    elfs := runElfFilter(knownfiles)
    // * 查找数据库
    for _, elffile := range elfs {
        outinfo := elffile.Name
        searchkey, reg := queryBinaryFileList(elffile.Name)
        if searchkey != "" {
            // 2. 判断版本信息，然后和详细二进制表进行比对，提示是不是原版的文件（或者不在数据库中）
            // Get the version infomation of the binary file
            v := getBinaryVersion(filepath.Join(elffile.Dir, elffile.Name), searchkey, reg)
            outinfo += v.ToString()
            // 查找数据库中对应版本的信息
            md5 := queryBinaryFileDetailInfo(elffile.Name, v)
            if md5 != "" {
                outinfo += " " + md5
            }
            var myunknwon golog.LogLevel
            myunknwon.Tag = " WARN "
            myunknwon.Fgcolor = color.FgHiYellow
            myunknwon.Font = color.Underline
            // 默认日志对象
            l := NewLog(myunknwon)
            l.Log.Bgcolor = color.BgGreen
            l.Log.Fgcolor = color.FgBlue
            l.InfoTag = myunknwon
            l.Info(outinfo)
            // 3. 如果有的话，就去文件漏洞库中查找；没有的话就跳过
            // 在程序漏洞表进行搜索
            pv := queryBinaryProgramVulnerability(elffile.Name)

            // 添加到result
            report.Programvulnerablities = append(report.Programvulnerablities, pv)

            printf := color.New(color.BgYellow, color.FgRed, color.Bold).PrintfFunc()
            printf("\n%-80s\n%-80s\n%-80s\n%-80s\n%-80s\n%-80s\n%-80s\n%-80s",
                "!!! Found Vuln Info !!!",
                fmt.Sprintf("漏洞编号: %s", pv.ID),
                fmt.Sprintf("漏洞程序: %s", pv.TargetOfAttack),
                fmt.Sprintf("影响范围: %s", pv.AffectedVersion),
                fmt.Sprintf("漏洞类型: %s", pv.Type),
                fmt.Sprintf("危害程度: %d", pv.Severity),
                fmt.Sprintf("漏洞描述: %s", pv.Description),
                fmt.Sprintf("修复建议: %s", pv.FixSuggestion),
            )
            fmt.Println()
        } else {
            var myunknwon golog.LogLevel
            myunknwon.Tag = " PASS "
            myunknwon.Fgcolor = color.FgHiBlue
            myunknwon.Font = color.Underline
            // 默认日志对象
            l := NewLog(myunknwon)
            l.Log.Bgcolor = color.BgGreen
            l.Log.Fgcolor = color.FgHiCyan
            l.UpdateElement(myunknwon)
            l.Logln(fmt.Sprintf("%-60s", elffile.Name))
        }
    }

    // 优先分析
    // 1. 未知的elf
    if len(unknwonElfFiles) > 0 {
        for _, elffile := range unknwonElfFiles {
            printf := color.New(color.Underline, color.Bold, color.FgRed).PrintfFunc()
            defaultLog.Warn("未知ELF文件:" + elffile.Name)
            fmt.Println()
            printf("  文件路径: %s  ", elffile.Dir)
            fmt.Println()
            printf("  系统评分: %d  ", elffile.Score)
            fmt.Println()
            fmt.Println()
        }
    } else {
        color.New(color.BgWhite, color.FgHiGreen).
            Printf("\n                                未发现未知ELF文件。                                        \n")
        sortedfile := Sort(append(knownfiles, unknwonfiles...))
        outlevel := 1
        score := sortedfile[0].Score
        for i := 0; i < len(sortedfile); i++ {
            if score <= sortedfile[i].Score && outlevel > 0 {
                s := fmt.Sprintf("score=%d filename=%s %s", sortedfile[i].Score, sortedfile[i].Name, sortedfile[i].Description)
                defaultLog.Info("优先分析目标：" + s + "\n")
            } else if outlevel > 0 {
                outlevel = outlevel - 1
                score = sortedfile[i].Score
                s := fmt.Sprintf("score=%d filename=%s %s", sortedfile[i].Score, sortedfile[i].Name, sortedfile[i].Description)
                defaultLog.Info("优先分析目标：" + s + "\n")
            } else {
                break
            }
        }
    }

    printf := color.New(color.BgBlack, color.FgGreen, color.Bold).PrintfFunc()
    fmt.Println()
    printf("                                                                                                                      ")
    fmt.Println()
    printf("                                   Vulnerability analysis module completed                                            ")
    fmt.Println()
    printf("                                   The total analysis time is 52437 ms                                                ")
    fmt.Println()
    printf("                                                                                                                      ")
    fmt.Println()
    fmt.Println()
}

// Get the version information of the binary program file.
func getBinaryVersion(filepath, key, reg string) Version {
    cmd1 := exec.Command("sh", "-c", fmt.Sprintf("strings \"%s\"", filepath))
    cmd2 := exec.Command("grep", key)

    pipe, err := cmd1.StdoutPipe()
    golog.CheckError(err)
    defer pipe.Close()

    cmd1.Start()

    cmd2.Stdin = pipe
    output, err := cmd2.Output()
    golog.CheckError(err)

    // 分割筛选后的字符串
    lines := strings.Split(string(output), "\n")

    for _, line := range lines {
        re := regexp.MustCompile(reg)
        // 判断字符串是否匹配正则表达式
        if re.MatchString(line) {
            // 提取捕获组中的 x.y.z
            matches := re.FindStringSubmatch(line)[1:]
            if len(matches) == 2 {
                // 将 x.y.z 转换成整数，保存到结构体中
                var v Version
                v.MajorVersion, _ = strconv.Atoi(matches[0])
                v.MinorVersion, _ = strconv.Atoi(matches[1])
                v.PatchVersion = -1
                return v
            }

        }
    }
    return Version{MajorVersion: -1, MinorVersion: -1, PatchVersion: -1}
}

// 排序
func Sort(fs []ExtractedFile) (sorted []ExtractedFile) {
    for i := 0; i < len(fs); i++ {
        tmp := fs[i]
        for j := 0; j < len(fs); j++ {
            if tmp.Score < fs[j].Score {
                t := fs[j]
                fs[j] = tmp
                tmp = t
            }
        }
        sorted = append(sorted, tmp)
    }
    return
}
