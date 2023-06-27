package scan

import (
	"172.16.2.38/neumannlyu/gobinscan/pkg/common"
	"172.16.2.38/neumannlyu/gobinscan/pkg/config"
)

var _cfgPtr *config.CFG
var _report common.Report
var _knownElfFile []common.ExtractedFile

// 导入模块时运行
func init() {
    _cfgPtr = config.GetConfig()
}
