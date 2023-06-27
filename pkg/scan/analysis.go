package scan

// 分析模块的运行入口，调用这个函数开始分析
//
//	@param rootdir bin文件提取后保存的路径
// func analysis(rootdir string) {

//     // 优先分析
//     // 1. 未知的elf
//     if len(unknwonElfFiles) > 0 {
//         for _, elffile := range unknwonElfFiles {
//             printf := color.New(color.Underline, color.Bold, color.FgRed).PrintfFunc()
//             defaultLog.Warn("未知ELF文件:" + elffile.Name)
//             fmt.Println()
//             printf("  文件路径: %s  ", elffile.Dir)
//             fmt.Println()
//             printf("  系统评分: %d  ", elffile.Score)
//             fmt.Println()
//             fmt.Println()
//         }
//     } else {
//         color.New(color.BgWhite, color.FgHiGreen).
//             Printf("\n                                未发现未知ELF文件。                                        \n")
//         sortedfile := Sort(append(knownfiles, unknwonfiles...))
//         outlevel := 1
//         score := sortedfile[0].Score
//         for i := 0; i < len(sortedfile); i++ {
//             if score <= sortedfile[i].Score && outlevel > 0 {
//                 s := fmt.Sprintf("score=%d filename=%s %s", sortedfile[i].Score, sortedfile[i].Name, sortedfile[i].Description)
//                 defaultLog.Info("优先分析目标：" + s + "\n")
//             } else if outlevel > 0 {
//                 outlevel = outlevel - 1
//                 score = sortedfile[i].Score
//                 s := fmt.Sprintf("score=%d filename=%s %s", sortedfile[i].Score, sortedfile[i].Name, sortedfile[i].Description)
//                 defaultLog.Info("优先分析目标：" + s + "\n")
//             } else {
//                 break
//             }
//         }
//     }

//     printf := color.New(color.BgBlack, color.FgGreen, color.Bold).PrintfFunc()
//     fmt.Println()
//     printf("                                                                                                                      ")
//     fmt.Println()
//     printf("                                   Vulnerability analysis module completed                                            ")
//     fmt.Println()
//     printf("                                   The total analysis time is 52437 ms                                                ")
//     fmt.Println()
//     printf("                                                                                                                      ")
//     fmt.Println()
//     fmt.Println()
// }

// // 排序
// func Sort(fs []ExtractedFile) (sorted []ExtractedFile) {
//     for i := 0; i < len(fs); i++ {
//         tmp := fs[i]
//         for j := 0; j < len(fs); j++ {
//             if tmp.Score < fs[j].Score {
//                 t := fs[j]
//                 fs[j] = tmp
//                 tmp = t
//             }
//         }
//         sorted = append(sorted, tmp)
//     }
//     return
// }
