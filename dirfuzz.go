package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	rua "github.com/EDDYCJY/fake-useragent"

	similarity "github.com/virink/htmlsimilarity"
)

const (
	// SimilarDistance 相似性汉明距离
	SimilarDistance = 3
	// BruteTimeout 爆破队列阻塞超时时间
	BruteTimeout = 5
)

// ReqUrls ReqUrls
type ReqUrls struct {
	t int // 1 file 2 dir
	p string
}

// Results 爆破结果结构
type Results struct {
	Forbidden []string `json:"403"`
	Ok        []string `json:"200"`
}

// Resp Resp
type Resp struct {
	Status int
	Length int
	Body   string
}

var (
	// HTTPClient HTTP 请求客户端
	HTTPClient http.Client
	// HTTPMethod HTTP 請求方法
	HTTPMethod int
	// HTTPAction HTTP 請求動作
	HTTPAction int
	// SimilarBody 相似性-404 頁面內容
	SimilarBody string
	// NotFoundLength 404 内容长度
	NotFoundLength int

	reqUrls    chan ReqUrls
	dictUrls   chan ReqUrls
	cancelChan chan bool

	// ResultUrls 爆破结果
	ResultUrls *Results
)

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	HTTPClient = http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
	}

	HTTPMethod = 2
	HTTPAction = 1

	ResultUrls = new(Results)

	reqUrls = make(chan ReqUrls, 102400)
	dictUrls = make(chan ReqUrls, 1024)

	cancelChan = make(chan bool)
}

// HTTPRequest HTTP 请求
func HTTPRequest(url string, method int, action int) (status int, length int, body string) {
	_method := ""
	body = ""
	length = 0
	var _body io.Reader
	_body = nil
	if method == HEAD {
		_method = "HEAD"
		if action == LENGTH {
			_body = strings.NewReader("233")
		}
	} else if method == GET {
		_method = "GET"
	} else if method == POST {
		_method = "POST"
	}
	req, err := http.NewRequest(_method, url, _body)
	if err == nil {
		randomUserAgent := rua.Computer()
		req.Header.Set("User-Agent", randomUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Connection", "close")
		if method == GET && action == RANGE {
			_r := r.Intn(9) + 1
			req.Header.Set("Range", fmt.Sprintf("bytes=-%d", _r))
		}
		resp, err := HTTPClient.Do(req)
		if err == nil {
			if resp.StatusCode == 302 {
				body = resp.Header.Get("Location")
				// TODO: Auto Redirect
				return resp.StatusCode, 0, body
			}

			// Header Content-Length
			if action == LENGTH {
				length, _ = strconv.Atoi(resp.Header.Get("Content-Length"))
				// Debug.Println("length", length, "not", NotFoundLength, "header", resp.Header.Get("Content-Length"), url)
				// Debug.Println(resp.Header)
				if length == NotFoundLength {
					return 404, length, ""
				}
				if length > 0 {
					return resp.StatusCode, length, ""
				}
			}

			// 判断状态 - RANGE 只是省流量
			if action == RANGE && resp.Header.Get("Content-Range") != "" {
				// _tmp := strings.Split(resp.Header.Get("Content-Range"), "/")
				// if len(_tmp) > 1 {
				// 	length, _ = strconv.Atoi(_tmp[1])
				// }
				return resp.StatusCode, 233, ""
			}

			// Read Body Data
			if method > HEAD && action >= NORMAL {
				defer resp.Body.Close()
				_body, err := ioutil.ReadAll(resp.Body)
				if err != nil {
					Error.Println("ioutil ReadAll failed :", err.Error())
					return 400, 0, ""
				}
				body = string(_body)
				if len(body) == NotFoundLength {
					return 404, len(body), body
				}
				isSimilar, _ := similarity.GetSimilar(SimilarBody, body)
				if len(SimilarBody) > 0 && isSimilar {
					return 404, 0, ""
				}
			}

			// Default
			return resp.StatusCode, len(body), body
		}
	}
	return 400, 0, ""
}

// PrepareForBrute 预处理
func PrepareForBrute(method int, action int) bool {
	// 测试爆破方法
	// TODO: Range Action
	/*
		Bursting Performances in Blind SQL Injection - Take 2 (Bandwidth)
		http://www.wisec.it/sectou.php?id=472f952d79293
	*/
	// test for head normal
	r := make(map[int]Resp, 5)
	// 正常页面
	// Debug.Println("Try to req HEAD & NORMAL 0 : ", BaseURL)
	// fmt.Printf("\r[*] %100s", "Try to req HEAD & NORMAL")
	redirectBaseURL := BaseURL
	rS, rL, rB := HTTPRequest(BaseURL, HEAD, NORMAL)
	if rS == 302 {
		redirectBaseURL := rB
		if !strings.HasPrefix(redirectBaseURL, "http://") || !strings.HasPrefix(redirectBaseURL, "https://") {
			if strings.HasPrefix(redirectBaseURL, "/") {
				redirectBaseURL = BaseURL + redirectBaseURL
			} else {
				redirectBaseURL = BaseURL + "/" + redirectBaseURL
			}
		}
		Info.Println("[+] BaseURL Redirect : ", redirectBaseURL)
		rS, rL, rB = HTTPRequest(redirectBaseURL, HEAD, NORMAL)
	}
	r[0] = Resp{rS, rL, rB}
	if rS == 200 {
		url := fmt.Sprintf("%s/%s", BaseURL, RandString(10))
		rS, rL, rB = HTTPRequest(url, HEAD, NORMAL)
		r[1] = Resp{rS, rL, rB}
		url = fmt.Sprintf("%s/%s/%s", BaseURL, RandString(10), RandString(10))
		rS, rL, rB = HTTPRequest(url, HEAD, NORMAL)
		r[2] = Resp{rS, rL, rB}
		url = fmt.Sprintf("%s/%s/%s.html", BaseURL, RandString(10), RandString(5))
		rS, rL, rB = HTTPRequest(url, HEAD, NORMAL)
		r[3] = Resp{rS, rL, rB}
		if (r[1].Status == r[2].Status) && (r[2].Status == r[3].Status) && (r[3].Status == 404) {
			HTTPMethod = HEAD
			HTTPAction = NORMAL
			Info.Println("[+] Use NotFound Status")
		} else {
			rS, rL, rB = HTTPRequest(redirectBaseURL, GET, NORMAL)
			r[0] = Resp{rS, rL, rB}
			url = fmt.Sprintf("%s/%s", BaseURL, RandString(10))
			rS, rL, rB = HTTPRequest(url, GET, NORMAL)
			r[1] = Resp{rS, rL, rB}
			url = fmt.Sprintf("%s/%s/%s", BaseURL, RandString(10), RandString(10))
			rS, rL, rB = HTTPRequest(url, GET, NORMAL)
			r[2] = Resp{rS, rL, rB}
			url = fmt.Sprintf("%s/%s/%s.html", BaseURL, RandString(10), RandString(5))
			rS, rL, rB = HTTPRequest(url, GET, NORMAL)
			r[3] = Resp{rS, rL, rB}
			if (r[2].Status == r[3].Status) && (r[3].Status == r[1].Status) && (r[1].Status == 404) {
				// Normal NotFound Status
				HTTPMethod = GET
				HTTPAction = NORMAL
				Info.Println("[+] Use NotFound Status")
			} else {
				if (r[2].Status == r[3].Status) && (r[3].Status == r[1].Status) && (r[1].Status == 200) && (r[1].Length == r[2].Length) && (r[2].Length == r[3].Length) {
					// OK Status + 固定长度 NotFound Page
					HTTPMethod = GET
					HTTPAction = LENGTH
					NotFoundLength = r[1].Length
					Info.Println("[+] Use NotFound Length")
				} else {
					// 相似性判斷
					isSimilar := [3]bool{false, false, false}
					if math.Abs(float64(r[1].Length-r[2].Length)) < 100 {
						isSimilar[0], _ = similarity.GetSimilar(r[1].Body, r[2].Body)
					}
					if math.Abs(float64(r[3].Length-r[2].Length)) < 100 {
						isSimilar[1], _ = similarity.GetSimilar(r[3].Body, r[2].Body)
					}
					if math.Abs(float64(r[3].Length-r[1].Length)) < 100 {
						isSimilar[2], _ = similarity.GetSimilar(r[3].Body, r[1].Body)
					}
					for _, v := range isSimilar {
						if !v {
							return false
						}
					}
					Info.Println("[+] Use SimHash Similar")
					SimilarBody = r[1].Body
				}
			}
		}
	}
	Info.Println("Brute : Method = ", HMethod[HTTPMethod], "Action : ", HAction[HTTPAction])
	return true
}

// StartToBrute 開始爆破 - 動態線程處理
func StartToBrute(wg *sync.WaitGroup, webType string, threadCount int, interval int, timeout time.Duration) {
	Debug.Println("StartToBrute...")
	defer wg.Done()
	//并发访问网址
	for i := 0; i < threadCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-time.After(timeout):
					if cancelChan != nil {
						cancelChan <- true
					}
					return
				case <-cancelChan:
					return
				case uri := <-reqUrls:
					_uri := StringStrip(uri.p, "/")
					if uri.t == 2 && !strings.HasSuffix(_uri, "/") {
						_uri += "/"
					}
					url := strings.Join([]string{BaseURL, _uri}, "/")
					rS, _, _ := HTTPRequest(url, HTTPMethod, HTTPAction)
					fmt.Printf("\r\x1b[1;36m[*] %d - %-100s\x1b[0m\r", rS, url)
					if rS == 200 {
						ResultUrls.Ok = append(ResultUrls.Ok, url)
						if uri.t == 2 {
							_p := ReqUrls{2, _uri}
							dictUrls <- _p
						}
						fmt.Printf("\r\x1b[1;32m[*] %d - %-100s\x1b[0m\n", rS, url)
					} else if rS == 403 {
						if uri.t == 2 && webType == "jsp" {
							_p := ReqUrls{2, _uri}
							dictUrls <- _p
						}
						ResultUrls.Forbidden = append(ResultUrls.Forbidden, url)
						fmt.Printf("\r\x1b[1;31m[*] %d - %-100s\x1b[0m\n", rS, url)
					}
					// 间隔时间
					if interval > 0 {
						time.Sleep(time.Duration(interval) * time.Second)
					}
					// time.Sleep(time.Duration(1) * time.Second)
				}
			}
		}()
	}
}

// GetDictUrls 从自动获取并处理地址
func GetDictUrls(wg *sync.WaitGroup) {
	Debug.Println("GetDictUrls ...")
	defer wg.Done()
	for {
		select {
		case <-cancelChan:
			return
		case uri := <-dictUrls:
			_uri := StringStrip(uri.p, "/")
			paths := strings.Split(_uri, "/")
			// Debug.Println("GetDictUrls Uri.p : ", _uri)
			// Debug.Println("GetDictUrls paths : ", paths)
			t := Nodes
			// TODO ...
			for i, p := range paths {
				// Debug.Println("GetDictUrls range paths p : ", p)
				if _, ok := t.Nodes[p]; ok {
					t = t.getNode(p)
				}
				// 最后一个路径
				if i == len(paths)-1 && t.Path == p {
					for _, u := range t.getFiles() {
						_q := ReqUrls{1, fmt.Sprintf("%s/%s", _uri, u)}
						reqUrls <- _q
					}
					for _, u := range t.getNodeKeys() {
						_q := ReqUrls{2, fmt.Sprintf("%s/%s/", _uri, u)}
						reqUrls <- _q
					}
				}
			}
		}
	}
}

func saveResult(name string) {
	data, err := json.MarshalIndent(&ResultUrls, "", "\t")
	if err != nil {
		Error.Println("Marshal ResultUrls : ", err)
	}
	if ioutil.WriteFile(name, data, 0644) == nil {
		// log.Println(string(data))
		Info.Println("[+] Save to results.log")
	}
}

// Dispatcher Fuzz 调度器
func Dispatcher(threadCount, interval int, webType, dbFile string) {
	Debug.Println("Dispatcher...")

	wg := &sync.WaitGroup{}

	dictNode := Nodes
	dictNode.load(dbFile)

	// 插入初始地址
	Debug.Println("Dispatcher Insert reqUrls...")
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, d := range dictNode.getNodeKeys() {
			_q := ReqUrls{2, StringStrip(d, "/")}
			reqUrls <- _q
		}
		for _, d := range dictNode.getFiles() {
			_q := ReqUrls{1, StringStrip(d, "/")}
			reqUrls <- _q
		}
		Info.Println("[+] Load init dict : ", len(reqUrls))
	}()
	Debug.Println("Dispatcher GetDictUrls...")

	wg.Add(1)
	go GetDictUrls(wg)
	Debug.Println("Dispatcher StartToBrute...")

	wg.Add(1)
	go StartToBrute(wg, webType, threadCount, interval, 5*time.Second)

	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case v := <-cancelChan:
			if v {
				close(cancelChan)
			}
		}
	}()

	wg.Wait()
	Debug.Println("Dispatcher Finish...")

	// ResultUrls
	sort.Strings(ResultUrls.Ok)
	sort.Strings(ResultUrls.Forbidden)
	Info.Printf("[+] Result : { 200 : %d, 403 : %d }          \n", len(ResultUrls.Ok), len(ResultUrls.Forbidden))
	saveResult("result.log")
}
