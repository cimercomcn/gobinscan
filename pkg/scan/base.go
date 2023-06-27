package scan

import (
    "gobinscan/pkg/config"

    "gobinscan/pkg/common"
)

var _cfgPtr *config.CFG
var _report common.Report
var _knownElfFile []common.ExtractedFile

// 导入模块时运行
func init() {
    _cfgPtr = config.GetConfig()
}
