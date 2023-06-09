package gobinscan

import (
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/fatih/color"
    "github.com/neumannlyu/golog"
)

// 需要分析bin文件的路径和提取后存放的目录。
// 这两个参数都由参数指定。
var g_bin_file_path string
var g_bin_extract_dir string

// 日志对象
var defaultLog golog.Log
var oKLog golog.Log

// 全局配置对象
var cfg CFG

// 全局结果对象
var report Result

func InitConfig(binfile string, loglevel int) *CFG {
    fmt.Println(`
    _____      ____     ______     _____      __      _    _____     ____     ____        __      _  
   / ___ \    / __ \   (_   _ \   (_   _)    /  \    / )  / ____\   / ___)   (    )      /  \    / ) 
  / /   \_)  / /  \ \    ) (_) )    | |     / /\ \  / /  ( (___    / /       / /\ \     / /\ \  / /  
 ( (  ____  ( ()  () )   \   _/     | |     ) ) ) ) ) )   \___ \  ( (       ( (__) )    ) ) ) ) ) )  
 ( ( (__  ) ( ()  () )   /  _ \     | |    ( ( ( ( ( (        ) ) ( (        )    (    ( ( ( ( ( (   
  \ \__/ /   \ \__/ /   _) (_) )   _| |__  / /  \ \/ /    ___/ /   \ \___   /  /\  \   / /  \ \/ /   
   \____/     \____/   (______/   /_____( (_/    \__/    /____/     \____) /__(  )__\ (_/    \__/ v0.0.2   
                                                                            
    `)

    g_bin_file_path = binfile
    // set log level
    setLogLevel(loglevel)
    cfg = newConfig()

    defaultLog = NewDefaultLog()

    var ok1 golog.LogLevel
    ok1.Tag = " OK "
    ok1.Bgcolor = color.BgGreen
    oKLog = NewLog(ok1)
    return &cfg
}

func CheckEnv() bool {
    // 检查运行环境
    if !checkEnv() {
        defaultLog.Fatal("检查运行环境失败，运行失败")
        return false
    }
    oKLog.Logln("检查运行环境完成")
    return true
}

func Run() Result {
    // 保存固件文件信息
    report.Binfile.Name = filepath.Base(g_bin_file_path)
    if abs, err := filepath.Abs(g_bin_file_path); !golog.CheckError(err) {
        report.Binfile.Dir = filepath.Dir(abs)
        report.Binfile.Md5 = report.Binfile.getMd5()
    }

    // 1.提取固件
    defaultLog.Info(fmt.Sprintf("[开始提取] %s > %s\n", g_bin_file_path, g_bin_extract_dir))
    if !extract(g_bin_file_path, g_bin_extract_dir) {
        defaultLog.Fatal("提取固件文件失败")
        return report
    } else {
        oKLog.Logln("[提取完成] 提取的文件保存在 " + g_bin_extract_dir + " 目录下")
    }

    // 检查固件加密情况
    if isEncrypted() {
        defaultLog.Fatal("发现固件被加密，请解密后再尝试分析。\n")
        return report
    } else {
        var mytag golog.LogLevel
        mytag.Tag = "PASS"
        mytag.Fgcolor = color.FgGreen
        mylog := NewLog(mytag)
        mylog.UpdateElement(mytag)
        mylog.Logln("固件加密未加密")
    }

    // 分析
    defaultLog.Info("\n\n\t\t\t[开始分析固件]\n\n")
    analysis(filepath.Join(g_bin_extract_dir, "_"+filepath.Base(g_bin_file_path)+".extracted"))

    // 资源回收
    closePostgresDB()

    return report
}

// 初始化。检查参数和runtime
// @return bool
func checkEnv() bool {
    // 初始化。检查参数和run time
    defaultLog.Info("开始检查运行环境...\n")

    // 读取配置文件
    defaultLog.Info("[1]正在加载配置文件...\n")
    if !checkConfig() {
        oKLog.Error("配置检查失败")
        return false
    }
    oKLog.Logln("加载配置文件完成")

    // 解析命令行参数
    defaultLog.Info("[2]正在解析命令行参数...\n")
    if !checkCmdLine() {
        defaultLog.Fatal("解析命令行参数失败\n")
        return false
    }
    oKLog.Logln("解析命令行参数完成")

    defaultLog.Info("[3]正在检查组件...\n")
    if !checkModule() {
        return false
    }
    oKLog.Logln("检查组件完成")

    return true
}

// 检查命令行参数的正确性
func checkCmdLine() bool {
    // check 1: 检查是否输入了bin文件路径，并且文件的后缀名为'.bin'
    if g_bin_file_path == "" || !strings.HasSuffix(g_bin_file_path, ".bin") {
        flag.PrintDefaults()
        return false
    }

    // check 2: 检查bin文件是否存在
    _, err := os.Stat(g_bin_file_path)
    if os.IsNotExist(err) {
        defaultLog.Fatal("bin file does not exist.")
        return false
    }

    // 如果未指定提取目录则使用当前目录为提取目录
    if len(g_bin_extract_dir) == 0 {
        g_bin_extract_dir, _ = os.Getwd()
        // 移除原有的文件夹
        if golog.CheckError(os.RemoveAll(filepath.Join(g_bin_extract_dir, "_"+filepath.Base(g_bin_file_path)+".extracted"))) {
            return false
        }
    } else { // 指定提取目录
        // 检查指定提取目录是否存在
        if _, err := os.Stat(g_bin_extract_dir); os.IsNotExist(err) {
            defaultLog.Fatal(fmt.Sprintf("Extracted directory %s does not exist.", g_bin_extract_dir))
            return false
        }

        // 目录存在
        files, err := os.ReadDir(g_bin_extract_dir)
        if err != nil {
            defaultLog.Fatal(fmt.Sprintf("Error reading directory %s: %v", g_bin_extract_dir, err))
            return false
        }
        if len(files) != 0 {
            defaultLog.Fatal(fmt.Sprintf("Extracted directory %s is not empty.\n", g_bin_extract_dir))
            return false
        }
    }
    return true
}

// 检查必要组件是否已经安装
func checkModule() bool {
    // 1. 检查binwalk是否已经安装
    if isInstalledBinwalk() {
        oKLog.Logln("binwalk")
    } else {
        defaultLog.Fatal("binwalk is not installed")
        return false
    }

    // 2. 检查数据库连接
    if openPostgresDB() {
        oKLog.Logln("连接数据库")
    } else {
        defaultLog.Fatal("连接数据库失败")
    }
    return true
}

// 检查配置文件
func checkConfig() bool {
    if cfg.DBHost == "" || cfg.DBName == "" || cfg.DBPassword == "" || cfg.DBUser == "" {
        return false
    }
    if len(cfg.SkipDir) == 0 {
        return false
    }
    if len(cfg.CompressSuffix) == 0 {
        return false
    }
    return true
}
