package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"golang.org/x/net/html"
	"golang.org/x/net/http2"
)

func main() {
	utils.RecordAsClient()

	verbose := flag.Bool("v", false, "verbose")
	_ = flag.Int("c", 10, "congestion window packet amount")
	_ = flag.Int("f", 32, "flow control kB")
	delayRequest := flag.Int("d", 0, "delay request")

	flag.Parse()
	urls := flag.Args()
	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogTimeFormat("")

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	hclient := &http.Client{Transport: tr}

	var wg sync.WaitGroup
	wg.Add(len(urls))
	for index, addr := range urls {
		if index == 1 && *delayRequest != 0 {
			waiting := *delayRequest + rand.New(rand.NewSource(time.Now().UnixNano())).Intn(20)
			timeToWait := time.Millisecond * time.Duration(waiting)
			utils.Infof("Waoting for %d ms until sending second Request", waiting)
			time.Sleep(timeToWait)
		}
		utils.Infof("GET %s", addr)
		go func(addr string, index int) {
			start := time.Now()

			rsp, err := hclient.Get(addr)
			if err != nil {
				panic(err)
			}
			utils.Infof("Got response for %s: %#v", addr, rsp)

			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			if err != nil {
				panic(err)
			}
			//utils.Infof("Request Body Complete!")
			//utils.Infof("HTML:\n\n %s", body.Bytes())
			elapsed := time.Since(start)
			utils.Infof("=====MAIN HTML LOADING COMPLETE====")
			utils.Infof("Loading %s took %s", addr, elapsed)
			utils.RecordF2("LoadingMainTime"+strconv.Itoa(index), elapsed.Nanoseconds(), 0)
			resourceLinks := getHtmlResourceLinks(body, addr)
			var innerWg sync.WaitGroup
			innerWg.Add(len(resourceLinks))
			concurrentGoroutines := make(chan struct{}, 100) //max 100 streams TODO: sort request for scheduling?
			//var mutex sync.Mutex
			for link, _ := range resourceLinks {
				go func(link string) {
					concurrentGoroutines <- struct{}{}
					utils.Infof("=====REQUESTING %s ====", link)
					start_link := time.Now()
					rsp, err := hclient.Get(link)
					if err != nil {
						panic(err)
					}
					body := &bytes.Buffer{}
					_, err = io.Copy(body, rsp.Body)
					if err != nil {
						panic(err)
					}
					elapsed_link := time.Since(start_link)
					utils.Infof("=====LOADING COMPLETE %s====took:%s", link, elapsed_link)
					//utils.Infof("Requesting %s took %s", link, elapsed_link)
					<-concurrentGoroutines
					innerWg.Done()
					//checkFinishedEndings(resourceLinks, link, start, mutex)
				}(link)
			}
			innerWg.Wait()
			elapsed = time.Since(start)
			utils.Infof("Processing the full page took %s", elapsed)
			utils.RecordF2("ProcessingAllTime"+strconv.Itoa(index), elapsed.Nanoseconds(), 0)
			wg.Done()
		}(addr, index)
	}
	wg.Wait()
}

func getAttributeValue(attribute string, t html.Token) (ok bool, href string) {
	for _, a := range t.Attr {
		if a.Key == attribute {
			href = a.Val
			ok = true
		}
	}
	return
}
func getHtmlResourceLinks(body *bytes.Buffer, addr string) map[string]bool {
	addrParts := strings.Split(addr, "/")
	baseAddr := addrParts[0] + "/" + addrParts[1] + "/" + addrParts[2] + "/"

	z := html.NewTokenizer(body)
	resourceLinks := make(map[string]bool)
	for {
		tt := z.Next()
		switch {
		case tt == html.ErrorToken:
			// End of the document, we're done
			return resourceLinks
		case tt == html.StartTagToken:
			t := z.Token()
			isLink := t.Data == "link"
			isScript := t.Data == "script"
			isImg := t.Data == "img"
			if !isLink && !isScript && !isImg {
				continue
			}
			var attribute string
			if isLink {
				attribute = "href"
			} else {
				attribute = "src"
			}
			ok, url := getAttributeValue(attribute, t)
			if !ok {
				continue
			}
			resourceLinks[baseAddr+url] = false
		case tt == html.SelfClosingTagToken:
			t := z.Token()
			isImg := t.Data == "img"
			if !isImg {
				continue
			}
			ok, url := getAttributeValue("src", t)
			if !ok {
				continue
			}
			resourceLinks[baseAddr+url] = false
		}
	}
}

func checkFinishedEndings(resourceLinks map[string]bool, link string, start time.Time, mutex sync.Mutex) {
	mutex.Lock()
	defer mutex.Unlock()
	resourceLinks[link] = true
	link = strings.ToLower(link)
	if strings.HasSuffix(link, "html") {
		checkAllDone(resourceLinks, "html", "", start)
	}
	if strings.HasSuffix(link, "css") {
		checkAllDone(resourceLinks, "css", "", start)
	}
	if strings.HasSuffix(link, "js") {
		checkAllDone(resourceLinks, "js", "", start)
	}
	if strings.HasSuffix(link, "png") || strings.HasSuffix(link, "jpg") {
		checkAllDone(resourceLinks, "png", "jpg", start)
	}
}

func checkAllDone(resourceLinks map[string]bool, suffix string, suffix2 string, start time.Time) {
	allDone := true
	for key, finished := range resourceLinks {
		key = strings.ToLower(key)
		if suffix2 != "" && strings.HasSuffix(key, suffix2) && !finished {
			allDone = false
		}
		if strings.HasSuffix(key, suffix) && !finished {
			allDone = false
		}
	}
	if allDone {
		utils.RecordF2(suffix+suffix2+"loaded", time.Since(start).Nanoseconds(), 0)
	}
}
