package config

type DBCFG struct {
    // 数据库厂家，目前仅支持“postgres”和“mysql”
    Platform string
    // 数据库服务器的IP地址
    Host string
    // 数据库服务器的用户名
    User string
    // 数据库服务器的用户名对应的密码
    Password string
    // 数据库名
    Name string
}
