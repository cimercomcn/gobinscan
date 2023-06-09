package gobinscan

import (
    "fmt"
    "testing"

    "github.com/neumannlyu/golog"
)

func TestMain(m *testing.M) {
    pcfg := InitConfig("../zy.bin", golog.LOGLEVEL_ALL)
    pcfg.DBHost = "172.16.5.114"
    pcfg.DBUser = "ly"
    pcfg.DBPassword = "123456"
    pcfg.DBName = "lydb"
    if CheckEnv() {
        fmt.Printf("Run().ToJson(): \n%s\n", Run().ToJson())
    }
}
