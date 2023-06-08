package gobinscan

type CFG struct {
    // 预分析的bin文件路径
    BinFile string
    // 数据库服务器的IP地址
    DBHost string
    // 数据库服务器的用户名
    DBUser string
    // 数据库服务器的用户名对应的密码
    DBPassword string
    // 数据库名
    DBName string

    // 常见的压缩文件后缀名
    CompressSuffix []string
    // 文件类型[类型]ID的映射表
    // FileTypeMap map[string]int `json:"file type map"`
    // 是否忽略别名文件
    IgnoreAlias bool
    // 需要跳过分析的目录
    SkipDir []string
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
    c.SkipDir = append(c.SkipDir, "web", "html")
    c.ScoreUnknown = 5
    c.ScoreUnknownElf = 20
    c.ScoreUnknownSuffix = 7
    c.IgnoreAlias = true
    return c
}
