package common

import (
    "strconv"
    "strings"
)

type Vulnerablity struct {
    // 漏洞编号，一般为CVE或者CNVD等
    ID string
    // 影响的内核的版本号
    AffectedVersion string
    // 漏洞类型
    Type string
    // 漏洞描述
    Description string
    // 漏洞严重程度，1-10评分，1不严重，10最严重
    Severity int
    // 修复建议
    FixSuggestion string
    // 攻击层。
    // kernel
    // shell
    // file system
    // user applicaion
    LayerOfAttack string
    // 攻击目标
    TargetOfAttack string
}

func (v *Vulnerablity) IsAffected(ver Version) bool {
    //* 字符串描述版本一般情况分为这几种形式：
    //* (1) (1.2.3,4.5.6)  	存在漏洞在这两个版本之间，不包含1.2.3版本,不包含4.5.6
    //* (2) (1.2.3,4.5.6]  	存在漏洞在这两个版本之间，不包含1.2.3版本,包含4.5.6
    //* (3) [1.2.3,4.5.6] 	存在漏洞在这两个版本之间，包含1.2.3版本,包含4.5.6
    //* (4) 1.2.3  			漏洞只存在版本1.2.3上

    // ! 只存在某个版本的情况
    if len(v.AffectedVersion) > 0 &&
        v.AffectedVersion[0] != '(' &&
        v.AffectedVersion[0] != '[' {
        // 此时只需要比较两个版本号是否一致即可
        ps := strings.Split(v.AffectedVersion, ".")
        var tmp Version
        tmp.MajorVersion, _ = strconv.Atoi(ps[0])
        tmp.MinorVersion, _ = strconv.Atoi(ps[1])
        tmp.PatchVersion, _ = strconv.Atoi(ps[2])
        return tmp.IsAfter(ver) == 0
    }

    // ! 在两个版本之间的情况
    // 表明是否包括下限，上限本身
    var isIncludeLeft bool
    var isIncludeRight bool
    // 处理上下限的问题
    if strings.Contains(v.AffectedVersion, "(") {
        isIncludeLeft = false
    } else if strings.Contains(v.AffectedVersion, "[") {
        isIncludeLeft = true
    }
    if strings.Contains(v.AffectedVersion, ")") {
        isIncludeRight = false
    } else if strings.Contains(v.AffectedVersion, "]") {
        isIncludeRight = true
    }
    // 删除原有的()[]
    affected_str := strings.ReplaceAll(strings.ReplaceAll(
        strings.ReplaceAll(strings.ReplaceAll(
            v.AffectedVersion, "(", ""), ")", ""), "[", ""), "]", "")

    // 按照,进行分割
    parts := strings.Split(affected_str, ",")
    // todo 错误校验

    // 影响版本号的下限
    var lower Version
    if len(parts[0]) == 0 {
        lower.MajorVersion = 0
        lower.MinorVersion = 0
        lower.PatchVersion = 0
    } else {
        items := strings.Split(parts[0], ".")
        lower.MajorVersion, _ = strconv.Atoi(items[0])
        lower.MinorVersion, _ = strconv.Atoi(items[1])
        lower.PatchVersion, _ = strconv.Atoi(items[2])
    }
    // 影响版本号的上限
    var upper Version
    if len(parts[1]) == 0 {
        upper.MajorVersion = -1
        upper.MinorVersion = -1
        upper.PatchVersion = -1
    } else {
        items := strings.Split(parts[1], ".")
        upper.MajorVersion, _ = strconv.Atoi(items[0])
        upper.MinorVersion, _ = strconv.Atoi(items[1])
        upper.PatchVersion, _ = strconv.Atoi(items[2])
    }

    if ver.IsAfter(lower) != 1 {
        // 比lower版本小，漏洞不触发
        return false
    }

    if ver.IsAfter(upper) == 1 {
        // 比upper版本高，pass
        return false
    }

    afterLeft := false
    if ver.IsAfter(lower) > 0 {
        afterLeft = true
    } else if ver.IsAfter(lower) == 0 {
        afterLeft = isIncludeLeft
    } else {
        afterLeft = false
    }
    beginRight := false
    if ver.IsAfter(upper) > 0 {
        beginRight = false
    } else if ver.IsAfter(upper) == 0 {
        beginRight = isIncludeRight
    } else {
        beginRight = true
    }
    if afterLeft && beginRight {
        return true
    } else {
        return false
    }
}
