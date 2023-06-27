package scan

const (
    // 目录
    FILETYPE_DIR int = 0
    // 泛泛指代文件，不知道具体类型
    // todo 根据已知的文件，再做一个更加细致的分裂
    FILECATEGORY_FILE int = 1
    FILETYPE_ELF      int = 3

    //*************************
    // 文件的重要性定义。
    //*************************
    // 可以忽略的文件
    FILEIMPORTANCE_IGNORE = 0
    // 未知的文件，也不知道重要级别
    FILEIMPORTANCE_UNKNOWN = -1
)
