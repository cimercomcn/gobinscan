package gobinscan

import (
    "fmt"
    "testing"
    "time"

    "github.com/neumannlyu/golog"
)

// 在固件中squashfs-root-0/sbin 目录下nfsroot是什么文件？
func TestMain(m *testing.M) {
    start := time.Now()
    InitConfig("../zy.bin",
        "postgresql",
        "172.16.5.114",
        "ly",
        "123456",
        "lydb",
        golog.LOGLEVEL_ALL)
    // InitConfig("../zy.bin",
    //     "mysql",
    //     "172.16.2.115:30006",
    //     "root",
    //     "avtNroKYeB6xXrR3",
    //     "asset_map",
    //     golog.LOGLEVEL_ALL)
    fmt.Printf("Run().ToJson(): %v\n", Run().ToJson())
    elapsed := time.Since(start)
    fmt.Printf("代码执行时间为：%s\n", elapsed)
}
