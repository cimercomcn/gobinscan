package sql

import "github.com/neumannlyu/gobinscan/pkg/common"

type ISQL interface {
    // 打开数据库连接
    // !在调用完数据库后一定要使用Close关闭连接。
    //  @param h host
    //  @param u user
    //  @param p password
    //  @param d database name
    //  @return *sql.DB db指针
    //  @return error 错误
    Open(h, u, p, d string) bool

    // 关闭数据库连接
    // !在调用完数据库后一定要关闭连接。
    Close()

    // 通过查询已知文件表（known file table)来判断文件是否已知
    // 如果是已知文件，则会填充对应的数据
    IsKnownFileByName(exfile *common.ExtractedFile) bool

    // 通过查询文件类型表（file type table)来判断文件是否已知
    // 如果是已知文件，则会填充对应的数据
    IsKnownFileByType(exfile *common.ExtractedFile) bool

    // 获取内核表中所有的数据
    // todo 根据内核版本返回符合版本的漏洞信息
    GetAllKernelVuln() []common.Vulnerablity

    // 获取该文件的漏洞列表
    GetProgramVulnerabilities(*common.ExtractedFile) (
        []common.Vulnerablity, error)

    // 搜索符合条件的程序漏洞
    SearchProgramVulnerabilityTable(common.ExtractedFile) []common.Vulnerablity
}
