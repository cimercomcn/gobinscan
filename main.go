package gobinscan

import (
    "flag"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/neumannlyu/gobinscan/pkg/common"
    "github.com/neumannlyu/gobinscan/pkg/config"
    "github.com/neumannlyu/gobinscan/pkg/scan"
    "github.com/neumannlyu/gobinscan/pkg/sql"
    "github.com/neumannlyu/gobinscan/pkg/tools"
    "github.com/neumannlyu/golog"
)

// 全局配置对象
var _cfgPtr *config.CFG

// first call
// configuration initial
func InitConfig(
    binfile string,
    databasePlatform string,
    databaseHost string,
    databaseUser string,
    databasePassword string,
    databaseName string,
    loglevel int) *config.CFG {
    fmt.Println(`
    _____      ____     ______     _____      __      _    _____     ____     ____        __      _  
   / ___ \    / __ \   (_   _ \   (_   _)    /  \    / )  / ____\   / ___)   (    )      /  \    / ) 
  / /   \_)  / /  \ \    ) (_) )    | |     / /\ \  / /  ( (___    / /       / /\ \     / /\ \  / /  
 ( (  ____  ( ()  () )   \   _/     | |     ) ) ) ) ) )   \___ \  ( (       ( (__) )    ) ) ) ) ) )  
 ( ( (__  ) ( ()  () )   /  _ \     | |    ( ( ( ( ( (        ) ) ( (        )    (    ( ( ( ( ( (   
  \ \__/ /   \ \__/ /   _) (_) )   _| |__  / /  \ \/ /    ___/ /   \ \___   /  /\  \   / /  \ \/ /   
   \____/     \____/   (______/   /_____( (_/    \__/    /____/     \____) /__(  )__\ (_/    \__/ v0.0.3
                                                                            
    `)

    // 新建一个配置实例
    _cfgPtr = config.GetConfig()
    // 设置二进制固件文件的路径。展开后路径也基于这个路径设定。
    _cfgPtr.BinFile = binfile
    // 设置数据库信息
    _cfgPtr.DB.Platform = databasePlatform
    _cfgPtr.DB.Host = databaseHost
    _cfgPtr.DB.User = databaseUser
    _cfgPtr.DB.Password = databasePassword
    _cfgPtr.DB.Name = databaseName
    // set log level
    _cfgPtr.SetLogLevel(loglevel)

    // 检查运行环境
    if !checkEnv() {
        _cfgPtr.Logs.CommonLog.Fatal("检查运行环境失败，运行失败")
        os.Exit(0)
    }
    _cfgPtr.Logs.OK.Logln("检查运行环境完成")

    return _cfgPtr
}

func Run() common.Report {
    return scan.Start()
}

// 初始化。检查参数和runtime
// @return bool
func checkEnv() bool {
    // 初始化。检查参数和run time
    _cfgPtr.Logs.CommonLog.Info("开始检查运行环境...\n")

    // 读取配置文件
    _cfgPtr.Logs.CommonLog.Info("[1]正在加载配置文件...\n")
    if !checkConfig() {
        _cfgPtr.Logs.CommonLog.Error("配置检查失败")
        return false
    }
    _cfgPtr.Logs.OK.Logln("加载配置文件完成")

    // 解析命令行参数
    _cfgPtr.Logs.CommonLog.Info("[2]正在解析命令行参数...\n")
    if !checkCmdLine() {
        _cfgPtr.Logs.CommonLog.Fatal("解析命令行参数失败\n")
        return false
    }
    _cfgPtr.Logs.OK.Logln("解析命令行参数完成")

    _cfgPtr.Logs.CommonLog.Info("[3]正在检查组件...\n")
    if !checkModule() {
        return false
    }
    _cfgPtr.Logs.OK.Logln("检查组件完成")

    return true
}

// 检查命令行参数的正确性
func checkCmdLine() bool {
    // check 1: 检查是否输入了bin文件路径，并且文件的后缀名为'.bin'
    if _cfgPtr.BinFile == "" || !strings.HasSuffix(_cfgPtr.BinFile, ".bin") {
        flag.PrintDefaults()
        return false
    }

    // check 2: 检查bin文件是否存在
    _, err := os.Stat(_cfgPtr.BinFile)
    if os.IsNotExist(err) {
        _cfgPtr.Logs.CommonLog.Fatal("bin file does not exist.")
        return false
    }

    // 如果未指定提取目录则使用当前目录为提取目录
    if len(_cfgPtr.BinExtractedDir) == 0 {
        _cfgPtr.BinExtractedDir, _ = os.Getwd()
        // 移除原有的文件夹
        if golog.CheckError(os.RemoveAll(
            filepath.Join(_cfgPtr.BinExtractedDir,
                "_"+filepath.Base(_cfgPtr.BinFile)+".extracted"))) {
            return false
        }
    } else { // 指定提取目录
        // 检查指定提取目录是否存在
        if _, err := os.Stat(_cfgPtr.BinExtractedDir); os.IsNotExist(err) {
            _cfgPtr.Logs.CommonLog.Fatal(
                fmt.Sprintf("Extracted directory %s does not exist.",
                    _cfgPtr.BinExtractedDir))
            return false
        }

        // 目录存在
        files, err := os.ReadDir(_cfgPtr.BinExtractedDir)
        if err != nil {
            _cfgPtr.Logs.CommonLog.Fatal(
                fmt.Sprintf("Error reading directory %s: %v",
                    _cfgPtr.BinExtractedDir, err))
            return false
        }
        if len(files) != 0 {
            _cfgPtr.Logs.CommonLog.Fatal(
                fmt.Sprintf("Extracted directory %s is not empty.\n",
                    _cfgPtr.BinExtractedDir))
            return false
        }
    }
    return true
}

// 检查必要组件是否已经安装
func checkModule() bool {
    // 1. 检查binwalk是否已经安装
    if tools.IsInstalledBinwalk() {
        _cfgPtr.Logs.OK.Logln("binwalk")
    } else {
        _cfgPtr.Logs.CommonLog.Fatal("binwalk is not installed")
        return false
    }

    // 2. 检查数据库连接
    switch _cfgPtr.DB.Platform {
    case "postgresql":
        sql.Isql = &sql.PostgresSQL{
            DBPtr: nil,
        }
        // 打开数据库
        if !sql.Isql.Open(
            _cfgPtr.DB.Host,
            _cfgPtr.DB.User,
            _cfgPtr.DB.Password,
            _cfgPtr.DB.Name) {
            _cfgPtr.Logs.CommonLog.Fatal("连接数据库失败")
            return false
        }
    case "mysql":
        sql.Isql = &sql.MySQL{
            DBPtr: nil,
        }
        // 打开数据库
        if !sql.Isql.Open(
            _cfgPtr.DB.Host,
            _cfgPtr.DB.User,
            _cfgPtr.DB.Password,
            _cfgPtr.DB.Name) {
            _cfgPtr.Logs.CommonLog.Fatal("连接数据库失败")
            return false
        }
    default:
        _cfgPtr.Logs.CommonLog.Fatal("No Suppoted Platform!!!")
        return false
    }

    _cfgPtr.Logs.OK.Logln("连接数据库")
    return true
}

// 检查配置文件
func checkConfig() bool {
    if _cfgPtr.DB.Host == "" || _cfgPtr.DB.Name == "" ||
        _cfgPtr.DB.Password == "" || _cfgPtr.DB.User == "" {
        return false
    }
    if len(_cfgPtr.ScanPolicy.SkipCustomDirs) == 0 {
        return false
    }
    if len(_cfgPtr.CompressSuffix) == 0 {
        return false
    }
    return true
}
