package gobinscan

import (
	"fmt"
	"testing"

	"github.com/neumannlyu/golog"
)

func TestMain(m *testing.M) {
    pcfg := InitConfig("../zy.bin", golog.LOGLEVEL_ALL)
    pcfg.DB.Host = "172.16.5.114"
    pcfg.DB.User = "ly"
    pcfg.DB.Password = "123456"
    pcfg.DB.Name = "lydb"
    if CheckEnv() {
        fmt.Printf("Run().ToJson(): \n%s\n", Run().ToJson())
    }
}
