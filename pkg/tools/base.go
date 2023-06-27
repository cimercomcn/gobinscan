package tools

import (
    "github.com/neumannlyu/gobinscan/pkg/config"
)

var _cfgPtr config.CFG

func init() {
    _cfgPtr = *config.GetConfig()
}
