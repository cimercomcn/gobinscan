package common

import (
	"encoding/json"

	"github.com/neumannlyu/golog"
)

type Result struct {
    Binfile               BinFileInfo
    KernelVersion         string
    KernelInfo            string
    Kernelvulnerablities  []Vulnerablity
    Programvulnerablities []Vulnerablity
}

func (r Result) ToJson() string {
    data, err := json.Marshal(r)
    if golog.CheckError(err) {
        return ""
    }

    return string(data)
}
