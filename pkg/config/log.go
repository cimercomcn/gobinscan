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
    CommonLog golog.CommonLog
}

func (ls *LogSet) applyDefault() {
    golog.UnifiedLogData.Fgcolor = color.FgGreen
    golog.UnifiedLogData.FormatString = "[" +
        golog.UnifiedLogData.FormatString + "]"

    // OK
    ls.OK = golog.NewSimpleLog()
    ls.OK.Tag.Fgcolor = color.FgGreen
    ls.OK.Tag.Bgcolor = 0
    ls.OK.Tag.FormatString = " OK "
    ls.OK.FormatString = golog.UnifiedLogFormatString
    // OK2
    ls.OK2 = golog.NewSimpleLog()
    ls.OK2.Tag.Fgcolor = color.FgHiBlue
    ls.OK2.Tag.Bgcolor = 0
    ls.OK2.Tag.Font = color.Underline
    ls.OK2.Tag.FormatString = "      OK "
    ls.OK2.FormatString = "                     "
    // Pass
    ls.Pass = golog.NewSimpleLog()
    ls.Pass.Tag.Fgcolor = color.FgGreen
    ls.Pass.Tag.Bgcolor = 0
    ls.Pass.Tag.FormatString = "PASS"
    ls.Pass.FormatString = golog.UnifiedLogFormatString
    // Ignored
    ls.Ignored = golog.NewSimpleLog()
    ls.Ignored.Tag.Fgcolor = color.FgGreen
    ls.Ignored.Tag.Bgcolor = 0
    ls.Ignored.Tag.FormatString = "IGNORED"
    ls.Ignored.Tag.Font = color.Underline
    ls.Ignored.FormatString = golog.UnifiedLogFormatString
    // Skip
    ls.Skip = golog.NewSimpleLog()
    ls.Skip.Tag.Fgcolor = color.FgBlue
    ls.Skip.Tag.Bgcolor = 0
    ls.Skip.Tag.FormatString = "SKIP"
    ls.Skip.Tag.Font = color.Underline
    ls.Skip.Msg.Bgcolor = color.BgWhite
    ls.Skip.Msg.Fgcolor = color.FgYellow
    ls.Skip.FormatString = golog.UnifiedLogFormatString
    // Unknwon
    ls.Unknwon = golog.NewSimpleLog()
    ls.Unknwon.Tag.Fgcolor = color.FgYellow
    ls.Unknwon.Tag.Bgcolor = 0
    ls.Unknwon.Tag.FormatString = "UNKNOWN"
    ls.Unknwon.Tag.Font = color.Underline
    ls.Unknwon.FormatString = golog.UnifiedLogFormatString
    // CommonLog
    ls.CommonLog = golog.NewCommonLog()
    ls.CommonLog.Format = golog.UnifiedLogFormatString
}
