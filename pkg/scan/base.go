package scan

import (
    "github.com/cimercomcn/gobinscan/pkg/common"

    "github.com/cimercomcn/gobinscan/pkg/config"
)

var _cfgPtr *config.CFG
var _report common.Report
var _knownElfFile []common.ExtractedFile

// 导入模块时运行
func init() {
    _cfgPtr = config.GetConfig()
}
