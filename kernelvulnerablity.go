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

// AnalysisKernelCVE 分析内核CVE
//  @param root 展开的目录
func analysisKernelCVE(root string) {
    // 获取固件中的内核信息
    lki, err := getKernelInfo(root)
    if golog.CheckError(err) {
        return
    }

    // 保存Linux内核信息
    report.KernelVersion = lki.ToString()

    // 查询所有的内核CVE记录
    kvs := queryKernelVulnTable()
    vulCount := 0
    for _, kv := range kvs {
        if kv.isAffected(lki) {
            vulCount++
            // 如果该内核版本有问题就输出
            fmt.Printf("发现漏洞【%s】\n", kv.ID)
            fmt.Printf("    漏洞类型【%s】\n", kv.Type)
            fmt.Printf("    漏洞描述【%s】\n", kv.Description)
            fmt.Printf("    漏洞等级【%d】\n", kv.Severity)
            fmt.Printf("    影响范围【内核 %s 】\n", kv.AffectedVersion)
            fmt.Printf("    修复建议【%s】\n\n", kv.FixSuggestion)

            // 添加到全局结果对象中
            report.Kernelvulnerablities = append(report.Kernelvulnerablities, kv)
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

            // 保存到result对象中
            report.KernelInfo = line

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