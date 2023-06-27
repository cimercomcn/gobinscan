package config

import "github.com/neumannlyu/golog"

// 导出的配置实例对象
var configInstance *CFG = nil

type ScanPolicyCFG struct {
    // 是否忽略别名文件
    IsIgnoreAlias bool
    // 需要跳过分析的目录
    IsSkipCustomDir bool
    SkipCustomDirs  []string
    // 是否跳过 extracted 目录
    IsSkipExtractedDir bool
    // 是否只扫描squashfs-root目录
    IsOnlySquashfsRoot bool
    // 是否需要分析目录，默认不分析目录
    IsAnalysisDir bool
}

// 使用严格模式。只扫描squashfs-root，跳过所有能跳过的目录
func (s *ScanPolicyCFG) setStrictMode() {
    s.IsIgnoreAlias = true
    s.IsSkipCustomDir = true
    s.IsSkipExtractedDir = true
    s.IsOnlySquashfsRoot = true
    s.IsAnalysisDir = false
}

// 使用默认模式。跳过别名，跳过自定义目录，跳过展开目录
func (s *ScanPolicyCFG) setDefaultMode() {
    s.IsIgnoreAlias = true
    s.IsSkipCustomDir = true
    s.IsSkipExtractedDir = true
    s.IsOnlySquashfsRoot = false
    s.IsAnalysisDir = false
}

type CFG struct {
    // 预分析的bin文件路径
    BinFile string
    // 与分析的bin展开目录
    BinExtractedDir string
    // 数据库配置
    DB DBCFG
    // 设置日志显示等级
    LogLevel int
    // 日志对象配置
    Logs LogSet
    // 扫描策略
    ScanPolicy ScanPolicyCFG
    // 常见的压缩文件后缀名
    CompressSuffix []string
    // 文件类型[类型]ID的映射表
    // FileTypeMap map[string]int `json:"file type map"`

    // 校验出不同类型的elf
    AddRatingCheckElf int
    // 未知elf文件加分
    AddRatingUnknownElf int
    // 未知文件后缀名
    ScoreUnknownSuffix int
    // 默认加分分值：发现在已知文件中elf类型不一致的情况
    // AddScoreKnownFileElfTypeNotSame int `json:"add scores of the elf type
    // not same in known files"`
    // 默认加分分值：在未知文件中发现elf文件
    // AddScoreUnknownElf int `json:"add scores of the
    // elf type in unknown files"`
}

// 新建一个配置实例
func GetConfig() *CFG {
    if configInstance == nil {
        configInstance = new(CFG)

        // BinFile
        configInstance.BinFile = ""

        // BinExtractedDir
        configInstance.BinExtractedDir = ""

        // DB
        configInstance.DB.Host = ""
        configInstance.DB.Name = ""
        configInstance.DB.Password = ""
        configInstance.DB.Platform = ""
        configInstance.DB.User = ""

        // Log
        configInstance.LogLevel = golog.LOGLEVEL_ALL
        configInstance.Logs.applyDefault()

        // ScanPolicy 设置扫描策略
        configInstance.ScanPolicy.SkipCustomDirs =
            append(configInstance.ScanPolicy.SkipCustomDirs, "web", "html")
        configInstance.ScanPolicy.setStrictMode()

        // 常用的压缩文件后缀名
        configInstance.CompressSuffix =
            append(configInstance.CompressSuffix, ".xz", ".zip", ".7z")

        // 校验出不同类型的elf
        configInstance.AddRatingCheckElf = 5
        configInstance.AddRatingUnknownElf = 20
        configInstance.ScoreUnknownSuffix = 7
    }

    return configInstance
}

// 设置日志集中所有的日志对象的日志等级
func (cfg *CFG) SetLogLevel(level int) {
    cfg.LogLevel = level
    cfg.Logs.setLevel(level)
}
