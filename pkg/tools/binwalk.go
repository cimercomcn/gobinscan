package tools

import (
    "fmt"
    "os/exec"
)

// 利用binwalk工具提取传入的bin文件。
// binwalk的命令原型为：binwalk -Me example.bin -C out
// @param 待提取的bin文件
// @param 提取后的输出目录
// @return bool
func BinwalkMe(bin_path, out_dir string) bool {
    // 执行binwalk
    // 指定要执行的命令和参数
    cmd := exec.Command("binwalk", "-Me", "-C",
        out_dir, bin_path, "--run-as=root")

    // 执行命令并等待结果
    output, err := cmd.CombinedOutput()
    if err != nil {
        _cfgPtr.Logs.CommonLog.Fatal(
            fmt.Sprintln("error executing command:", err))
        return false
    }

    // 将结果作为字符串输出
    _cfgPtr.Logs.CommonLog.Info(
        fmt.Sprintln(string(output)))
    return true
}

// 检查系统中是否安装了binwalk。
// ! binwalk需要添加到环境变量中。
// @return bool
// @return error
func IsInstalledBinwalk() bool {
    programName := "binwalk"

    // 检查程序是否安装
    cmd := exec.Command("which", programName)
    if err := cmd.Run(); err != nil {
        return false
    } else {
        return true
    }
}
