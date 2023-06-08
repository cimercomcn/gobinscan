package gobinscan

import (
    "errors"
    "fmt"
    "os/exec"
    "regexp"
    "strconv"
    "strings"

    "github.com/fatih/color"
    "github.com/neumannlyu/golog"
)

type KernelVulnerablity struct {
    // 漏洞编号，一般为CVE或者CNVD等
    VulID string
    // 影响的内核的版本号
    AffectedKernelVer string
    // 漏洞类型
    VulType string
    // 漏洞描述
    VulDescription string
    // 漏洞严重程度，1-10评分，1不严重，10最严重
    Severity int
    // 修复建议
    FixSuggestion string
}

func (k *KernelVulnerablity) isAffected(lkv Version) bool {
    //* 字符串描述版本一般情况分为这几种形式：
    //* (1) (1.2.3,4.5.6)  	存在漏洞在这两个版本之间，不包含1.2.3版本,不包含4.5.6
    //* (2) (1.2.3,4.5.6]  	存在漏洞在这两个版本之间，不包含1.2.3版本,包含4.5.6
    //* (3) [1.2.3,4.5.6] 	存在漏洞在这两个版本之间，包含1.2.3版本,包含4.5.6
    //* (4) 1.2.3  			漏洞只存在版本1.2.3上

    // ! 只存在某个版本的情况
    if len(k.AffectedKernelVer) > 0 && k.AffectedKernelVer[0] != '(' && k.AffectedKernelVer[0] != '[' {
        // 此时只需要比较两个版本号是否一致即可
        ps := strings.Split(k.AffectedKernelVer, ".")
        var tmp Version
        tmp.MajorVersion, _ = strconv.Atoi(ps[0])
        tmp.MinorVersion, _ = strconv.Atoi(ps[1])
        tmp.PatchVersion, _ = strconv.Atoi(ps[2])
        return tmp.IsAfter(lkv) == 0
    }

    // ! 在两个版本之间的情况
    // 表明是否包括下限，上限本身
    var isIncludeLeft bool
    var isIncludeRight bool
    // 处理上下限的问题
    if strings.Contains(k.AffectedKernelVer, "(") {
        isIncludeLeft = false
    } else if strings.Contains(k.AffectedKernelVer, "[") {
        isIncludeLeft = true
    }
    if strings.Contains(k.AffectedKernelVer, ")") {
        isIncludeRight = false
    } else if strings.Contains(k.AffectedKernelVer, "]") {
        isIncludeRight = true
    }
    // 删除原有的()[]
    affected_str := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(k.AffectedKernelVer, "(", ""), ")", ""), "[", ""), "]", "")

    // 按照,进行分割
    parts := strings.Split(affected_str, ",")
    // todo 错误校验

    // 影响版本号的下限
    var lower Version
    if len(parts[0]) == 0 {
        lower.MajorVersion = 0
        lower.MinorVersion = 0
        lower.PatchVersion = 0
    } else {
        items := strings.Split(parts[0], ".")
        lower.MajorVersion, _ = strconv.Atoi(items[0])
        lower.MinorVersion, _ = strconv.Atoi(items[1])
        lower.PatchVersion, _ = strconv.Atoi(items[2])
    }
    // 影响版本号的上限
    var upper Version
    if len(parts[1]) == 0 {
        upper.MajorVersion = -1
        upper.MinorVersion = -1
        upper.PatchVersion = -1
    } else {
        items := strings.Split(parts[1], ".")
        upper.MajorVersion, _ = strconv.Atoi(items[0])
        upper.MinorVersion, _ = strconv.Atoi(items[1])
        upper.PatchVersion, _ = strconv.Atoi(items[2])
    }

    if lkv.IsAfter(lower) != 1 {
        // 比lower版本小，漏洞不触发
        return false
    }

    if lkv.IsAfter(upper) == 1 {
        // 比upper版本高，pass
        return false
    }

    afterLeft := false
    if lkv.IsAfter(lower) > 0 {
        afterLeft = true
    } else if lkv.IsAfter(lower) == 0 {
        afterLeft = isIncludeLeft
    } else {
        afterLeft = false
    }
    beginRight := false
    if lkv.IsAfter(upper) > 0 {
        beginRight = false
    } else if lkv.IsAfter(upper) == 0 {
        beginRight = isIncludeRight
    } else {
        beginRight = true
    }
    if afterLeft && beginRight {
        return true
    } else {
        return false
    }
}

// AnalysisKernelCVE 分析内核CVE
//  @param root 展开的目录
func analysisKernelCVE(root string) {
    // 获取固件中的内核信息
    lki, err := getKernelInfo(root)
    if golog.CheckError(err) {
        return
    }

    // 查询所有的内核CVE记录
    kvs := queryKernelVulnTable()
    vulCount := 0
    for _, kv := range kvs {
        if kv.isAffected(lki) {
            vulCount++
            // 如果该内核版本有问题就输出
            fmt.Printf("发现漏洞【%s】\n", kv.VulID)
            fmt.Printf("    漏洞类型【%s】\n", kv.VulType)
            fmt.Printf("    漏洞描述【%s】\n", kv.VulDescription)
            fmt.Printf("    漏洞等级【%d】\n", kv.Severity)
            fmt.Printf("    影响范围【内核 %s 】\n", kv.AffectedKernelVer)
            fmt.Printf("    修复建议【%s】\n\n", kv.FixSuggestion)
        }
    }
    color.New(color.BgYellow, color.FgRed, color.Bold).Printf("                                                 共发现%d/%d个内核漏洞                                                 ",
        vulCount, len(kvs))
    fmt.Println()
}

// 获取Linux内核版本信息。
// 在binwalk解包的路径下执行 strings * | grep Linux version 命令。
func getKernelInfo(current_dir string) (Version, error) {
    cmd1 := exec.Command("sh", "-c", fmt.Sprintf("cd %s && strings *", current_dir))
    cmd2 := exec.Command("grep", "Linux version")

    pipe, err := cmd1.StdoutPipe()
    if err != nil {
        return Version{}, err
    }
    defer pipe.Close()

    cmd1.Start()
    cmd2.Stdin = pipe
    output, err := cmd2.Output()
    if err != nil {
        return Version{}, err
    }

    // 分割筛选后的字符串
    lines := strings.Split(string(output), "\n")

    for _, line := range lines {
        re := regexp.MustCompile(`Linux version (\d+)\.(\d+)\.(\d+)`)

        // 判断字符串是否匹配正则表达式
        if re.MatchString(line) {
            fmt.Printf("\n\n\n")
            color.New(color.BgWhite, color.FgHiRed, color.Bold).Printf("        内核版本信息：%s        ", line)
            fmt.Printf("\n\n\n")

            // 提取捕获组中的 x.y.z
            matches := re.FindStringSubmatch(line)[1:]

            // 将 x.y.z 转换成整数，保存到结构体中
            var lkv Version
            lkv.MajorVersion, _ = strconv.Atoi(matches[0])
            lkv.MinorVersion, _ = strconv.Atoi(matches[1])
            lkv.PatchVersion, _ = strconv.Atoi(matches[2])
            return lkv, nil
        }
    }
    return Version{}, errors.New("not found linux kernel version info")
}
