# gobinscan

## 导入

···
go get github.com/neumannlyu/gobinscan
···

## 使用方法

```
// 初始化配置
// @param1: 预分析bin文件所在路径
// @param2: 设置日志输入等级
// @return 返回一个配置对象，可以通过这个对象指针来进行配置
pcfg := InitConfig("../zy.bin", golog.LOGLEVEL_ALL)

// 设置数据库的主机
pcfg.DBHost = "172.16.5.114"
// 设置数据库的用户名
pcfg.DBUser = "ly"
// 设置数据库的用户名对应的密码
pcfg.DBPassword = "123456"
// 设置数据库名
pcfg.DBName = "lydb"

// 进行运行环境检查
if CheckEnv() {
    // Run是分析的接口，只需要调用Run函数即可。
    // 返回一个Result struct，这个结构体中保存了分析结果。调用ToJson可以转成Result Json字符串
    fmt.Printf("Run().ToJson(): \n%s\n", Run().ToJson())
}
```