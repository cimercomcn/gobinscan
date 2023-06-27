package tools

import "172.16.2.38/neumannlyu/gobinscan/pkg/config"

var _cfgPtr config.CFG

func init() {
    _cfgPtr = *config.GetConfig()
}
