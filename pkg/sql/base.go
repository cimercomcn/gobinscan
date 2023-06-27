package sql

import "gobinscan/pkg/config"

var _cfgPtr *config.CFG

// sql操作对象
var Isql ISQL

// 导入模块时运行
func init() {
    _cfgPtr = config.GetConfig()
}
