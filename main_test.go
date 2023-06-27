package gobinscan

import (
    "fmt"
    "testing"

    "github.com/neumannlyu/golog"
)

func TestMain(m *testing.M) {
    // InitConfig("../zy.bin",
    //     "postgresql",
    //     "172.16.5.114",
    //     "ly",
    //     "123456",
    //     "lydb",
    //     golog.LOGLEVEL_ALL)
    InitConfig("../zy.bin",
        "mysql",
        "172.16.2.115:30006",
        "root",
        "avtNroKYeB6xXrR3",
        "asset_map",
        golog.LOGLEVEL_ALL)
    fmt.Printf("Run().ToJson(): %v\n", Run().ToJson())
}
