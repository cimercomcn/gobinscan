package gobinscan

import (
    "database/sql"
    "fmt"
    "path/filepath"
    "strings"

    _ "github.com/lib/pq"
    "github.com/neumannlyu/golog"
)

// postgres数据库对象
// 数据库操作都使用同一个变量。
var g_postgres_db *sql.DB = nil

// OpenPostgresDB 打开Postgres数据库
//  @return bool true：正常打开数据库，false：打开数据库失败
// !在调用完数据库后一定要使用ClosePostgresDB关闭连接。
func openPostgresDB() bool {
    // 避免重复打开数据库
    if g_postgres_db != nil {
        return true
    }

    var err error
    g_postgres_db, err = sql.Open("postgres", fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable", cfg.DBHost, cfg.DBUser, cfg.DBPassword, cfg.DBName))
    return !golog.CheckError(err)
}

// 关闭数据库连接
// !在调用完数据库后一定要关闭连接。
func closePostgresDB() {
    if g_postgres_db != nil {
        g_postgres_db.Close()
    }
    g_postgres_db = nil
}

// 从known_file表中查询
//  @param 关键字：文件名
//  @return known_file_struct文件信息结构体的数组
func queryKnownFileTable(f *ExtractedFile) bool {
    qstr := fmt.Sprintf(`SELECT * FROM known_file_table where file_name='%s'`, f.Name)
    rows, err := g_postgres_db.Query(qstr)
    if golog.CheckError(err) {
        defaultLog.Error(err.Error())
        return false
    }
    defer rows.Close()

    if rows.Next() {
        var id int  // 数据库的索引字段，抛弃。
        var idx int // 防止重名的文件序号，抛弃
        err = rows.Scan(&id, &f.Name, &idx, &f.TypeIndex, &f.Score, &f.Count, &f.Md5, &f.Description)
        if golog.CheckError(err) {
            defaultLog.Error(err.Error())
            return false
        } else {
            return true
        }
    }
    return false
}

// 从file_suffix表中查询
//  @param 文件结构体
//  @return 是否查询到对应的记录
func queryFileSuffixTable(f *ExtractedFile) bool {
    qstr := fmt.Sprintf(`SELECT description FROM file_suffix_table where suffix_name='%s'`, filepath.Ext(f.Name))
    rows, err := g_postgres_db.Query(qstr)
    if golog.CheckError(err) {
        defaultLog.Error(err.Error())
        return false
    }
    defer rows.Close()

    if rows.Next() {
        // 有对应的后缀名记录

        // 数据库的索引字段，抛弃。
        // var id int
        // 文件后缀名
        // var suffix_name string
        err = rows.Scan(&f.Description)
        if golog.CheckError(err) {
            defaultLog.Error(err.Error())
            return false
        }
    } else {
        // 直接搜后缀名，没发现对应的记录，现在再次尝试在其他位置搜索后缀名
        // 可能在后缀名的后面增加.1之类的数字。如：.so.6
        // 也有可能添加其他的后缀。如：.so.bak

        // 2.将文件名按照.进行分割，然后从后往前依次查找是否有符合的后缀名
        parts := strings.Split(f.Name, ".")
        tail := "" //后缀名的尾巴
        for i := len(parts) - 1; i > 0; i-- {
            statement := fmt.Sprintf(`SELECT type_index,score,description FROM file_suffix_table where suffix_name='%s'`, "."+parts[i]+".$${version}$$")
            results, err := g_postgres_db.Query(statement)
            if golog.CheckError(err) {
                defaultLog.Error(err.Error())
                return false
            }
            defer results.Close()

            if results.Next() {
                err = results.Scan(&f.TypeIndex, &f.Score, &f.Description)
                if golog.CheckError(err) {
                    defaultLog.Error(err.Error())
                    return false
                }
                // 将字符串 $${version}$$ 用实际的字符串进行修正
                f.Description = strings.Replace(f.Description, "$${version}$$", tail, -1)
                return true
            }
            tail = "." + parts[i] + tail
        }
    }

    return false
}

// 从内核CVE表中查询
//  @return 所有关于内核CVE的记录
func queryKernelVulnTable() (kvs []Vulnerablity) {
    rows, err := g_postgres_db.Query(`SELECT * FROM kernel_vulnerability_table`)
    if err != nil {
        defaultLog.Error(err.Error())
        return
    }
    defer rows.Close()

    for rows.Next() {
        // 数据库的索引字段，抛弃。
        var id int
        var kv Vulnerablity
        err = rows.Scan(&id, &kv.ID, &kv.AffectedVersion, &kv.Type, &kv.Description, &kv.Severity, &kv.FixSuggestion)
        if err != nil {
            fmt.Println(err)
        }
        kvs = append(kvs, kv)
    }
    return
}

// QueryBinaryFileList 从binary file table中搜索同样的filename
//  @param file 文件名
//  @return verSearchKey 搜索版本信息的关键字
func queryBinaryFileList(file string) (verSearchKey, reg string) {
    qstr := fmt.Sprintf(`SELECT * FROM binary_file_table where file_name='%s'`, file)
    rows, err := g_postgres_db.Query(qstr)
    if err != nil {
        defaultLog.Error(err.Error())
        return
    }
    defer rows.Close()

    for rows.Next() {
        // 数据库的索引字段，抛弃。
        var id int
        var tmp_name string
        golog.CheckError(rows.Scan(&id, &tmp_name, &verSearchKey, &reg))
    }
    return
}

// 利用文件名和版本信息去数据库中搜索是不是有这个文件。
// 如果有这个文件就返回这个文件的md5，来和本文件的md5进行比较。
// 用来判断是不是一个文件。
func queryBinaryFileDetailInfo(file string, ver Version) string {
    qstr := fmt.Sprintf(`SELECT * FROM binary_file_detail_table where file_name='%s'`, file)
    rows, err := g_postgres_db.Query(qstr)
    if err != nil {
        defaultLog.Error(err.Error())
        return ""
    }
    defer rows.Close()

    for rows.Next() {
        // 数据库的索引字段，抛弃。
        var id int
        var fname string
        var v string
        var md5 string
        golog.CheckError(rows.Scan(&id, &fname, &v, &md5))
        // return the md5 of file if the version is the same.
        // todo 判断版本是否相同需要优化
        if ver.ToString() == v {
            return md5
        }
    }
    return ""
}

func queryBinaryProgramVulnerability(program_name string) Vulnerablity {
    var vuln Vulnerablity
    qstr := fmt.Sprintf(`SELECT * FROM program_vulnerability_table where file_name='%s'`, program_name)
    rows, err := g_postgres_db.Query(qstr)
    if err != nil {
        defaultLog.Error(err.Error())
        return vuln
    }
    defer rows.Close()

    for rows.Next() {
        // 数据库的索引字段，抛弃。
        var id int
        //id ,vid ,file_name , affected_ver  vtype TEXT, vdescription TEXT, severity INT, fix_suggestion
        golog.CheckError(rows.Scan(&id, &vuln.ID, &vuln.TargetOfAttack, &vuln.AffectedVersion,
            &vuln.Type, &vuln.Description, &vuln.Severity, &vuln.FixSuggestion))
    }
    return vuln
}

// 获取某个类型的编号。
// example: 搜索elf，返回elf对应的类型编号。
// func QueryFileTypeIndex(fileType string) (type_id int, err error) {
//     qstr := fmt.Sprintf(`SELECT * FROM file_type_index_table where type='%s'`, fileType)
//     rows, err := g_postgres_db.Query(qstr)
//     if err != nil {
//         share.DefaultLogFormat.Error(err.Error())
//         return -1, err
//     }
//     defer rows.Close()

//     if rows.Next() {
//         golog.CheckError(rows.Scan(&type_id))
//     } else {
//         return -1, errors.New("no result")
//     }
//     return
// }
