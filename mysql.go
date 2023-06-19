package gobinscan

import (
    "database/sql"
    "fmt"
    "log"

    _ "github.com/go-sql-driver/mysql"
)

var g_mysql *sql.DB

func openMysqlDB() bool {
    // 避免重复打开数据库
    if g_mysql != nil {
        return true
    }

    var err error
    g_mysql, err = sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s",
        cfg.DB.User, cfg.DB.Password, cfg.DB.Host, cfg.DB.Name))
    if err != nil {
        log.Fatal(err)
    }

    return true
}
