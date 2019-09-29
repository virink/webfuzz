package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hedzr/cmdr"
)

const (
	// APPNAME Name for app
	APPNAME = "WebFuzz"
	// VERSION Version for app
	VERSION = "0.0.2"

	HEAD int = 1
	GET  int = 2
	POST int = 3

	NORMAL int = 1
	LENGTH int = 2
	RANGE  int = 3
)

var (
	HMethod, HAction map[int]string
	resSc, resLen    int
	resBody          string

	Debug *log.Logger
	Info  *log.Logger
	Error *log.Logger

	// BaseURL target url
	BaseURL string
)

func init() {
	HMethod = make(map[int]string, 3)
	HAction = make(map[int]string, 3)
	HMethod[HEAD] = "HEAD"
	HMethod[GET] = "GET"
	HMethod[POST] = "POST"
	HAction[NORMAL] = "NORMAL"
	HAction[LENGTH] = "LENGTH"
	HAction[RANGE] = "RANGE"

	debugFile, err := os.OpenFile("webfuzz_debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		Error.Fatalln("打开日志文件失败：", err)
	}
	Debug = log.New(debugFile, "[D] ", log.Ldate|log.Ltime|log.Lshortfile)
	// Debug = log.New(io.MultiWriter(os.Stderr, debugFile), "[D] ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(os.Stderr, "[E] ", log.Ldate|log.Ltime)
	Info = log.New(os.Stdout, "[I] ", log.Ldate|log.Ltime)
}

func main() {

	root := cmdr.Root(APPNAME, VERSION).
		Header("[$] WebFuzz - Virink <virink@outlook.com>").
		Description("Fuzz web dir and file", "A penetration test tool for fuzz web dir and file")
	rootCmd := root.RootCommand()

	// 字典处理
	dictCmd := root.NewSubCommand().
		Titles("d", "dict").
		Description("", "Update Dicts").
		Group("Dict").
		Action(func(cmd *cmdr.Command, args []string) (err error) {
			dictFile := cmdr.GetString("app.dict.input")
			dbFile := cmdr.GetString("app.dict.output")
			jsonStr := cmdr.GetBool("app.dict.json")
			if _, e := os.Stat(dictFile); os.IsNotExist(e) {
				Error.Println("Dict file is not exist!")
				return
			}
			t := time.Now().UnixNano()
			UpdateDicts(dictFile, dbFile, jsonStr)
			t = time.Now().UnixNano() - t
			Info.Println(fmt.Sprintf("[+] UpdateDicts use %f s", float64(t)/1e9))
			return
		})
	dictCmd.NewFlag(cmdr.OptFlagTypeString).
		Titles("i", "input").
		Description("Read the input file (*.txt / *.dic / *.dict)", ``).
		DefaultValue("dir.dic", "FILE")
	dictCmd.NewFlag(cmdr.OptFlagTypeString).
		Titles("o", "output").
		Description("Write the output file (*.db)", ``).
		DefaultValue(DictDB, "FILE")
	dictCmd.NewFlag(cmdr.OptFlagTypeBool).
		Titles("j", "json").
		Description("Print Dict as Json", ``).
		DefaultValue(false, "JSON")

	// 爆破目录
	fuzzCmd := root.NewSubCommand().
		Titles("f", "fuzz", "fuzzing").
		Description("", "Fuzzing Dirs/Files").
		Group("Fuzzing").
		Action(func(cmd *cmdr.Command, args []string) (err error) {
			BaseURL = cmdr.GetString("app.fuzz.url")
			thread := cmdr.GetInt("app.fuzz.thread")
			interval := cmdr.GetInt("app.fuzz.interval")
			// TODO: more func for webType
			webType := cmdr.GetString("app.fuzz.type")
			dbFile := cmdr.GetString("app.fuzz.dict")
			method := cmdr.GetInt("app.fuzz.method")
			action := cmdr.GetInt("app.fuzz.action")
			// log.Println(BaseURL, thread, interval, method, action)
			reg := regexp.MustCompile(`^https?://([\w-]+\.)+[\w-]+(/[\w-./?%&=]*)?(\:\d+)?/?$`)
			ret := reg.FindAllString(BaseURL, -1)
			// fmt.Printf("%q\n", ret)
			if len(ret) > 0 && len(ret[0]) > 5 {
				if strings.HasSuffix(BaseURL, "/") {
					BaseURL = BaseURL[:len(BaseURL)-1]
				}
				Info.Println("|#| Target   : ", BaseURL)
				Info.Println("|#| Thread   : ", thread)
				Info.Println("|#| Interval : ", interval)
				Info.Println("|#| Dict     : ", dbFile)
				// Prepare for brute
				if PrepareForBrute(method, action) {
					Dispatcher(thread, interval, webType, dbFile)
				}
			} else {
				Info.Println("[-] Please input target url!")
			}
			return
		})
	fuzzCmd.NewFlag(cmdr.OptFlagTypeString).
		Titles("u", "url").
		Description("website which you want to fuzz.", "").
		Group("").
		DefaultValue("", "URL")
	fuzzCmd.NewFlag(cmdr.OptFlagTypeString).
		Titles("t", "type").
		Description("Server type: php, jsp, asp, aspx, db", "").
		Group("").
		DefaultValue("php", "TYPE")
	fuzzCmd.NewFlag(cmdr.OptFlagTypeString).
		Titles("d", "dict").
		Description("Dict db file", "").
		Group("").
		DefaultValue(DictDB, "FILE")
	fuzzCmd.NewFlag(cmdr.OptFlagTypeInt).
		Titles("n", "thread").
		Description("number of Thread.", "").
		Group("").
		DefaultValue(10, "THREAD").
		HeadLike(true, 1, 100)
	fuzzCmd.NewFlag(cmdr.OptFlagTypeInt).
		Titles("i", "interval").
		Description("number of interval time.", "").
		Group("").
		DefaultValue(0, "INTERVAL").
		HeadLike(true, 1, 100)
	fuzzCmd.NewFlag(cmdr.OptFlagTypeInt).
		Titles("m", "method").
		Description("Request method : HEAD 1, GET 2, POST 3", "").
		Group("").
		DefaultValue(1, "METHOD").
		HeadLike(true, 1, 3)
	fuzzCmd.NewFlag(cmdr.OptFlagTypeInt).
		Titles("a", "action").
		Description("Request action: NORMAL 1, LENGTH 2, RANGE 3", "").
		Group("").
		DefaultValue(1, "ACTION").
		HeadLike(true, 1, 3)

	if err := cmdr.Exec(rootCmd); err != nil {
		Error.Println(err)
	}
}
