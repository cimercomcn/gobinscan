package sql

import (
    "database/sql"
    "errors"
    "fmt"
    "path/filepath"
    "strings"

    "github.com/cimercomcn/gobinscan/pkg/common"
    _ "github.com/lib/pq"
    "github.com/neumannlyu/golog"
)

type PostgresSQL struct {
    DBPtr *sql.DB
}

// OpenPostgresDB 打开Postgres数据库
//  @return bool true：正常打开数据库，false：打开数据库失败
// !在调用完数据库后一定要使用ClosePostgresDB关闭连接。
func (pg *PostgresSQL) Open(h, u, p, d string) bool {
    // 避免重复打开数据库
    if pg.DBPtr != nil {
        return true
    }

    db, err := sql.Open("postgres",
        fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable",
            h, u, p, d))
    if golog.CatchError(err) {
        _cfgPtr.Logs.CommonLog.Fatal(
            fmt.Sprintf("open PostgresSQL failed err.Error(): %v\n",
                err.Error()))
        return false
    } else {
        _cfgPtr.Logs.CommonLog.Info("open PostgresSQL successfully.\n")
        pg.DBPtr = db
        return true
    }
}

// 关闭数据库连接
// !在调用完数据库后一定要关闭连接。
func (pg *PostgresSQL) Close() {
    if pg.DBPtr != nil {
        pg.DBPtr.Close()
    }
    pg.DBPtr = nil
}

// 从known_file表中查询
//  @param 关键字：文件名
//  @return known_file_struct文件信息结构体的数组
func (pg *PostgresSQL) IsKnownFileByName(exfile *common.ExtractedFile) bool {
    rows, err := pg.DBPtr.Query(
        "SELECT file_name,flag,rating,count,description FROM known_file_table" +
            " where file_name='" + exfile.Name + "'")
    if golog.CatchError(err) {
        _cfgPtr.Logs.CommonLog.Error(err.Error())
        return false
    }
    defer rows.Close()

    if rows.Next() {
        err = rows.Scan(
            &exfile.Name,
            &exfile.Flag,
            &exfile.Rating,
            &exfile.Count,
            &exfile.Description)
        if golog.CatchError(err) {
            _cfgPtr.Logs.CommonLog.Error(err.Error())
            return false
        } else {
            return true
        }
    }
    return false
}

// 从file_type表中查询
//  @param 文件结构体
//  @return 是否查询到对应的记录
func (pg *PostgresSQL) IsKnownFileByType(exfile *common.ExtractedFile) bool {
    rows, err := pg.DBPtr.Query(
        "SELECT flag, rating, description FROM file_type_table" +
            " where suffix_name='" + filepath.Ext(exfile.Name) + "'")
    if golog.CatchError(err) {
        _cfgPtr.Logs.CommonLog.Error(err.Error())
        return false
    }
    defer rows.Close()

    if rows.Next() {
        // 有对应的后缀名记录

        // 数据库的索引字段，抛弃。
        // var id int
        // 文件后缀名
        // var suffix_name string
        err = rows.Scan(
            &exfile.Flag,
            &exfile.Rating,
            &exfile.Description)
        if golog.CatchError(err) {
            _cfgPtr.Logs.CommonLog.Error(err.Error())
            return false
        } else {
            return true
        }
    } else {
        // 直接搜后缀名，没发现对应的记录，现在再次尝试在其他位置搜索后缀名
        // 可能在后缀名的后面增加.1之类的数字。如：.so.6
        // 也有可能添加其他的后缀。如：.so.bak

        // 2.将文件名按照.进行分割，然后从后往前依次查找是否有符合的后缀名
        parts := strings.Split(exfile.Name, ".")
        tail := "" //后缀名的尾巴
        for i := len(parts) - 1; i > 0; i-- {
            results, err := pg.DBPtr.Query(
                "SELECT flag, rating,description FROM file_type_table " +
                    "where suffix_name='." + parts[i] + ".$${version}$$'")
            if golog.CatchError(err) {
                _cfgPtr.Logs.CommonLog.Error(err.Error())
                return false
            }
            defer results.Close()

            if results.Next() {
                err = results.Scan(
                    &exfile.Flag,
                    &exfile.Rating,
                    &exfile.Description)
                if golog.CatchError(err) {
                    _cfgPtr.Logs.CommonLog.Error(err.Error())
                    return false
                }
                // 将字符串 $${version}$$ 用实际的字符串进行修正
                exfile.Description = strings.Replace(
                    exfile.Description, "$${version}$$", tail, -1)
                return true
            }
            tail = "." + parts[i] + tail
        }
    }

    return false
}

// 从内核CVE表中查询
//  @return 所有关于内核CVE的记录
func (pg *PostgresSQL) GetAllKernelVuln() (kvs []common.Vulnerablity) {
    rows, err := pg.DBPtr.Query(
        "SELECT vul_id,affected_kernel_ver,vul_type,vul_description," +
            "severity,fix_suggestion FROM kernel_vulnerability_table")
    if err != nil {
        _cfgPtr.Logs.CommonLog.Error(err.Error())
        return
    }
    defer rows.Close()

    for rows.Next() {
        var kv common.Vulnerablity
        if err := rows.Scan(
            &kv.ID,
            &kv.AffectedVersion,
            &kv.Type,
            &kv.Description,
            &kv.Severity,
            &kv.FixSuggestion); err != nil {
            _cfgPtr.Logs.CommonLog.Error(err.Error())
        }
        kvs = append(kvs, kv)
    }
    return
}

// 判断是否存在漏洞
func (pg *PostgresSQL) GetProgramVulnerabilities(
    exfile *common.ExtractedFile) (
    vlunerabilities []common.Vulnerablity, err error) {
    rows, err := pg.DBPtr.Query(
        "SELECT ver_search_key, regular FROM program_table " +
            "where file_name='" + exfile.Name + "'")
    if golog.CatchError(err) {
        return nil, err
    }
    defer rows.Close()

    for rows.Next() {
        if golog.CatchError(
            rows.Scan(
                &exfile.VersionSearchKey,
                &exfile.VersionSearchRegular)) {
            _cfgPtr.Logs.CommonLog.Error(err.Error())
            continue
        }
        // 2. 判断版本信息，然后和详细二进制表进行比对，
        // 提示是不是原版的文件（或者不在数据库中）
        // Get the version infomation of the binary file
        if err := exfile.GetBinaryVersion(); golog.CatchError(err) {
            _cfgPtr.Logs.CommonLog.Error(err.Error())
            continue
        }

        // 3. 如果有的话，就去文件漏洞库中查找；没有的话就跳过
        // 在程序漏洞表进行搜索
        vlunerabilities = pg.SearchProgramVulnerabilityTable(*exfile)
        return
    }

    return vlunerabilities, errors.New("not found version")
}

func (pg *PostgresSQL) SearchProgramVulnerabilityTable(
    exfile common.ExtractedFile) (vlunerabilities []common.Vulnerablity) {
    rows, err := pg.DBPtr.Query(
        "SELECT vid, file_name, affected_ver, vtype, vdescription, severity," +
            " fix_suggestion FROM program_vulnerability_table " +
            "where file_name='" + exfile.Name + "'")
    if golog.CatchError(err) {
        _cfgPtr.Logs.CommonLog.Error(err.Error())
        return nil
    }
    defer rows.Close()

    for rows.Next() {
        var vuln common.Vulnerablity
        // id ,vid ,file_name , affected_ver  vtype TEXT,
        // vdescription TEXT, severity INT, fix_suggestion
        if !golog.CatchError(
            rows.Scan(
                &vuln.ID,
                &vuln.TargetOfAttack,
                &vuln.AffectedVersion,
                &vuln.Type,
                &vuln.Description,
                &vuln.Severity,
                &vuln.FixSuggestion)) {
            if vuln.IsAffected(exfile.Version) {
                vlunerabilities = append(vlunerabilities, vuln)
            }
        }
    }
    return
}
