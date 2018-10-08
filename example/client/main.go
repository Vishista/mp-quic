package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Vishista/mp-quic/h2quic"
	"github.com/Vishista/mp-quic/internal/utils"
	"github.com/Vishista/mp-quic/protocol"
	"golang.org/x/net/html"
	"crypto/tls"
)

func getLocalEthernetAddresses(ips *[]string, ni string) {
	networkInterfaces := strings.Split(ni, ",")
	ifaces, err := net.Interfaces()
	var newIps []string
	for _, _ = range networkInterfaces {
		newIps= append(newIps ,"workaround")
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			fmt.Println(err)
			return
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			}
			for index, networkInterface := range networkInterfaces {
				if match, _ := regexp.MatchString(networkInterface, i.Name); match {
					if ip.To4() != nil {
						newIps[index] = ip.String()
					}
				}
			}
		}
	}
	*ips = newIps
}

func main() {
	utils.RecordAsClient()

	verbose := flag.Bool("v", false, "verbose")
	delayRequest := flag.Int("d", 0, "delay request")
	fake_mp := flag.Bool("fmp", false, "fake multipath")
	ni := flag.String("n", "wlan", "network interfaces separated by ,")
	mip := flag.String("mip", "", "additional remote ips/ports separated by ,")
	c := flag.Int("c", 10, "congestion window packet amount")
	f := flag.Int("f", 32, "flow control kB")
	//important
	//the first network interface (-n flag) is used to connect to the url given in urls := flag.Args()
	//further network interfaces are mapped to additional ips (-mip flag)
	//thus len(mip) must be len(ni)-1

	flag.Parse()
	urls := flag.Args()
	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogTimeFormat("")
	protocol.SetInitialCongestionWindow(*c)
	protocol.SetInitialReceiveStreamFlowControlWindow(*f)

	var localIps []string
	getLocalEthernetAddresses(&localIps, *ni)
	if *fake_mp {
		localIps = append(localIps, localIps[0])
	}
	fmt.Println("Detected Network Interfaces:", localIps)
	var moreRemoteIps []string
	if(*mip != ""){
		moreRemoteIps = strings.Split(*mip, ",")
	}
	hclient := &http.Client{
		Transport: h2quic.NewQuicRoundTripper(localIps,  moreRemoteIps, &tls.Config{InsecureSkipVerify: true}),
	}
	var wg sync.WaitGroup
	wg.Add(len(urls))
	for index, addr := range urls {
		if index == 1 && *delayRequest != 0 {
			waiting := *delayRequest + rand.New(rand.NewSource(time.Now().UnixNano())).Intn(20)
			timeToWait := time.Millisecond * time.Duration(waiting)
			utils.Infof("Waiting for %d ms until sending second Request", waiting)
			time.Sleep(timeToWait)
		}
		utils.Infof("GET %s", addr)
		go func(addr string, index int) {
			start := time.Now()
                     utils.Infof("haan", addr)
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
			utils.Infof("Request Body Complete!")
			utils.Infof("HTML:\n\n %s", body.Bytes())
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
