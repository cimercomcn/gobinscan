package common

import (
    "encoding/json"

    "github.com/neumannlyu/golog"
)

// 最终报告结构体
type Report struct {
    Binfile               BinFileInfo
    KernelVersion         string
    KernelInfo            string
    Kernelvulnerablities  []Vulnerablity
    Programvulnerablities []Vulnerablity
}

func (r Report) ToJson() string {
    data, err := json.Marshal(r)
    if golog.CatchError(err) {
        return ""
    }

    return string(data)
}
