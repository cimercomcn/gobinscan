package gobinscan

import (
    "github.com/fatih/color"
    "github.com/neumannlyu/golog"
)

var logLevel int

// set log level. 0-7 levels. 0: all; 7slient.
func setLogLevel(level int) {
    logLevel = level
}

func NewDefaultLog() golog.Log {
    log := golog.NewDefaultLog()
    log.Level = logLevel
    log.Format = "&DT &TAG "

    var ltime golog.LogTime
    ltime.Format = "[2006-01-02 15:04:05]"
    ltime.Fgcolor = color.FgBlue

    log.UpdateElement(ltime)
    return log
}

func NewLog(tag golog.LogLevel) golog.Log {
    log := golog.NewDefaultLog()
    log.Level = logLevel
    log.Format = "&DT &TAG "
    var ltime golog.LogTime
    ltime.Format = "[2006-01-02 15:04:05]"
    ltime.Fgcolor = color.FgBlue

    log.UpdateElement(ltime)
    log.UpdateElement(tag)

    return log
}
