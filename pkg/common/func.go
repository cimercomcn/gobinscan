package common

// IsContainString 判断str是否在array字符串数组中
//
//	@param str
//	@param array
//	@return bool
func IsContainString(str string, array []string) bool {
    for _, item := range array {
        if str == item {
            return true
        }
    }
    return false
}
