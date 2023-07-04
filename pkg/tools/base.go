package tools

import "github.com/cimercomcn/gobinscan/pkg/config"

var _cfgPtr config.CFG

func init() {
    _cfgPtr = *config.GetConfig()
}
