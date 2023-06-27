package config

import (
    "github.com/fatih/color"
    "github.com/neumannlyu/golog"
)

// 日志对象集
type LogSet struct {
    // Fg:Green
    // Tag:[ OK ]
    OK golog.SimpleLog
    // Tag: [   OK    ] FgHiBlue Underline
    OK2 golog.SimpleLog
    // Fg:Green
    // Tag:[PASS]
    Pass golog.SimpleLog
    // Fg:Green
    // Tag:[IGNORED]
    // Underline
    Ignored golog.SimpleLog
    // Fg:Blue
    // Tag:[SKIP]
    // Underline
    Skip golog.SimpleLog
    // Tag: [UNKNOWN] Fg
    Unknwon   golog.SimpleLog
    CommonLog golog.Log
}

func (ls *LogSet) applyDefault() {
    // OK
    ls.OK = golog.NewSimpleLog()
    ls.OK.Tag.Fgcolor = color.FgGreen
    ls.OK.Tag.Bgcolor = 0
    ls.OK.Tag.Tag = " OK "
    ls.OK.FormatString = "&DT &TAG "
    // OK2
    ls.OK2 = golog.NewSimpleLog()
    ls.OK2.Tag.Fgcolor = color.FgHiBlue
    ls.OK2.Tag.Bgcolor = 0
    ls.OK2.Tag.Font = color.Underline
    ls.OK2.Tag.Tag = "   OK    "
    ls.OK2.FormatString = "&DT &TAG "
    // Pass
    ls.Pass = golog.NewSimpleLog()
    ls.Pass.Tag.Fgcolor = color.FgGreen
    ls.Pass.Tag.Bgcolor = 0
    ls.Pass.Tag.Tag = "PASS"
    ls.Pass.FormatString = "&DT &TAG "
    // Ignored
    ls.Ignored = golog.NewSimpleLog()
    ls.Ignored.Tag.Fgcolor = color.FgGreen
    ls.Ignored.Tag.Bgcolor = 0
    ls.Ignored.Tag.Tag = "IGNORED"
    ls.Ignored.Tag.Font = color.Underline
    ls.Ignored.FormatString = "&DT &TAG "
    // Skip
    ls.Skip = golog.NewSimpleLog()
    ls.Skip.Tag.Fgcolor = color.FgBlue
    ls.Skip.Tag.Bgcolor = 0
    ls.Skip.Tag.Tag = "SKIP"
    ls.Skip.Tag.Font = color.Underline
    ls.Skip.Msg.Bgcolor = color.BgWhite
    ls.Skip.Msg.Fgcolor = color.FgYellow
    ls.Skip.FormatString = "&DT &TAG "
    // Unknwon
    ls.Unknwon = golog.NewSimpleLog()
    ls.Unknwon.Tag.Fgcolor = color.FgYellow
    ls.Unknwon.Tag.Bgcolor = 0
    ls.Unknwon.Tag.Tag = "UNKNOWN"
    ls.Unknwon.Tag.Font = color.Underline
    ls.Unknwon.FormatString = "&DT &TAG "
    // CommonLog
    ls.CommonLog = golog.NewDefaultLog()
    ls.CommonLog.Format = "&DT &TAG "
}

func (ls *LogSet) setLevel(level int) {
    ls.OK.Level = level
    ls.OK2.Level = level
    ls.Pass.Level = level
    ls.Ignored.Level = level
    ls.Skip.Level = level
    ls.CommonLog.Level = level
}
