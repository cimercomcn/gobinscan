package gobinscan

type DBCFG struct {
    // 数据库厂家，目前仅支持“postgres”和“mysql”
    Platform string
    // 数据库服务器的IP地址
    Host string
    // 数据库服务器的用户名
    User string
    // 数据库服务器的用户名对应的密码
    Password string
    // 数据库名
    Name string
}

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
    // 数据库配置
    DB DBCFG
    // 扫描策略
    ScanPolicy ScanPolicyCFG
    // 常见的压缩文件后缀名
    CompressSuffix []string
    // 文件类型[类型]ID的映射表
    // FileTypeMap map[string]int `json:"file type map"`

    // 未知文件加分
    ScoreUnknown int
    // 未知elf文件加分
    ScoreUnknownElf int
    // 未知文件后缀名
    ScoreUnknownSuffix int
    // 默认加分分值：发现在已知文件中elf类型不一致的情况
    // AddScoreKnownFileElfTypeNotSame int `json:"add scores of the elf type not same in known files"`
    // 默认加分分值：在未知文件中发现elf文件
    // AddScoreUnknownElf int `json:"add scores of the elf type in unknown files"`

}

func newConfig() CFG {
    var c CFG
    c.CompressSuffix = append(c.CompressSuffix, ".xz", ".zip", ".7z")

    // 设置扫描策略
    c.ScanPolicy.SkipCustomDirs = append(c.ScanPolicy.SkipCustomDirs, "web", "html")
    c.ScanPolicy.setStrictMode()

    c.ScoreUnknown = 5
    c.ScoreUnknownElf = 20
    c.ScoreUnknownSuffix = 7
    return c
}
