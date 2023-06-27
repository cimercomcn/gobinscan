package common

import (
    "strconv"
)

type Version struct {
    // 主版本号
    MajorVersion int
    // 次版本号
    MinorVersion int
    // 修订版本号
    PatchVersion int
}

// IsAfter 判断当前版本号是否比另一个（参数）版本号大。
// @receiver l	本身版本对象
// @param another	另一个比较对象
// @return int	返回比较结果。0: 版本一致。1: 比另一个版本大。-1: 比另一个版本小。
func (v *Version) IsAfter(another Version) int {
    if v.MajorVersion > another.MajorVersion {
        return 1
    } else if v.MajorVersion < another.MajorVersion {
        return -1
    }

    // 主版本号一致，比较次版本号
    if v.MinorVersion > another.MinorVersion {
        return 1
    } else if v.MajorVersion < another.MajorVersion {
        return -1
    }

    // 主版本号和次版本号都一致，比较修订版本号
    if v.PatchVersion > another.PatchVersion {
        return 1
    } else if v.PatchVersion < another.PatchVersion {
        return -1
    }

    // 所有的版本号都一致，版本相同。
    return 0
}

// 转成字符串
func (v *Version) ToString() string {
    var ret string
    if v.MajorVersion < 0 {
        return ""
    }
    ret += strconv.Itoa(v.MajorVersion)
    if v.MinorVersion < 0 {
        return ret
    }
    ret += "." + strconv.Itoa(v.MinorVersion)
    if v.PatchVersion < 0 {
        return ret
    }
    return ret + "." + strconv.Itoa(v.PatchVersion)
}
