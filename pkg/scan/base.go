package scan

import (
    "github.com/neumannlyu/gobinscan/pkg/common"
    "github.com/neumannlyu/gobinscan/pkg/config"
)

var _cfgPtr *config.CFG
var _report common.Result
var _knownElfFile []common.ExtractedFile

// 导入模块时运行
func init() {
    _cfgPtr = config.GetConfig()
}
