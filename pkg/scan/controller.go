package scan

import (
    "fmt"
    "gobinscan/pkg/common"
    "gobinscan/pkg/tools"
    "os"
    "path/filepath"

    "gobinscan/pkg/sql"

    "github.com/neumannlyu/golog"
)

// 扫描从这里开始
func Start() common.Report {

    // 保存固件文件信息
    _report.Binfile.Name = filepath.Base(_cfgPtr.BinFile)
    if abs, err := filepath.Abs(_cfgPtr.BinFile); !golog.CheckError(err) {
        _report.Binfile.Dir = filepath.Dir(abs)
        _report.Binfile.MD5 = _report.Binfile.GetMD5()
    }

    // 1.提取固件
    _cfgPtr.Logs.CommonLog.Info(
        fmt.Sprintf("[开始提取] %s > %s\n",
            _cfgPtr.BinFile, _cfgPtr.BinExtractedDir))

    if !tools.BinwalkMe(_cfgPtr.BinFile, _cfgPtr.BinExtractedDir) {
        _cfgPtr.Logs.CommonLog.Fatal("提取固件文件失败")
        return _report
    } else {
        _cfgPtr.Logs.OK.Logln(
            "[提取完成] 提取的文件保存在 " + _cfgPtr.BinExtractedDir + " 目录下")
    }

    _cfgPtr.BinExtractedDir = filepath.Join(_cfgPtr.BinExtractedDir,
        "_"+filepath.Base(_cfgPtr.BinFile)+".extracted")

    // 2. 检查固件加密情况
    if isEncrypted() {
        _cfgPtr.Logs.CommonLog.Fatal("发现固件被加密，请解密后再尝试分析。\n")
        return _report
    } else {
        _cfgPtr.Logs.Pass.Logln("\n\n\n\t\t\t\t固件加密未加密\n\n\n")
    }

    // 3. 扫描提取的文件
    scanExtractedFiles(_cfgPtr.BinExtractedDir)

    // 4. 分析内核漏洞
    if !scanKernelVulnerability(_cfgPtr.BinExtractedDir) {
        return _report
    }

    // 5. 分析（中间件）程序
    scanProgramVulnerability()

    // 资源回收
    sql.Isql.Close()

    return _report
}

// 检查固件是否被加密
// true: 加密; false: 未加密
func isEncrypted() bool {
    // 判断条件1: 是否有 squashfs-root 目录
    pass1 := true
    fs, err := os.ReadDir(_cfgPtr.BinExtractedDir)
    golog.CheckError(err)

    // 遍历目录中的文件。如果遇到某些文件时，将跳过。
    for _, file := range fs {
        if file.IsDir() && file.Name() == "squashfs-root" {
            pass1 = false
            break
        }
    }

    // 判断2: 正常情况下squashfs-root目录下应该会有多个文件，如果只有一个文件应该就是加密了。
    pass2 := false
    squashfs_root := filepath.Join(_cfgPtr.BinExtractedDir, "squashfs-root")
    fs, err = os.ReadDir(squashfs_root)
    if golog.CheckError(err) || len(fs) <= 1 {
        pass2 = true
    }

    return pass1 || pass2
}
