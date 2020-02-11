package main

// TODO: encrypt cookiejar with u/p
//       invalidating a Cookie (logout) is not an option, as hitting the rate limit on RegFish.de is too easy

import (
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	cookiejar "github.com/orirawlings/persistent-cookiejar"
)

type (
	DomainName string
	RR         struct {
		id    uint
		Rname string
		Rttl  uint
		Rtype string
		Rdata string
	}
	Whois struct {
		id           uint
		Wtype        string
		Fname        string
		Lname        string
		Organisation string
		Address      string
		Postalcode   string
		City         string
		Countrycode  string
		Phone_int    string
		Phone_ort    string
		Phone_num    string
		Fax_int      string
		Fax_ort      string
		Fax_num      string
		Email        string
		Sip          string
	}
	Domain struct {
		RRs map[uint]RR
		//Whois Whois
		uri      string
		Name     DomainName
		Contract map[string]string
	}
	Domains map[DomainName]Domain
)

const baseURL = "https://www.regfish.de"

// included from credentials.go:
// const username = ""
// const password = ""

type RF struct {
	jar       cookiejar.Jar
	client    *http.Client
	logged_in bool
	retries   uint
	doc       *goquery.Document
	username  string
	password  string

	Domains Domains
}

func (rf *RF) check_login() bool {
	initial_try := false
	if rf.doc == nil {
		response, _ := rf.client.Get(baseURL + "/my/login")
		rf.doc, _ = goquery.NewDocumentFromReader(response.Body)
		initial_try = true

	}
	if rf.doc != nil && rf.doc.Find("div.reb:nth-child(1)").Text() == "Ausloggen" {
		if initial_try {
			log.Println("Still logged in from previous session")
		}
		return true
	} else {
		log.Println("Not logged in")
		return false
	}
}

func (rf *RF) Login(username string, password string) (bool, error) {
	md5username := fmt.Sprintf("%x", md5.Sum([]byte(username)))
	jar, _ := cookiejar.New(&cookiejar.Options{PersistSessionCookies: true, Filename: cookiejar.DefaultCookieFile() + "_" + md5username})
	rf.jar = *jar
	rf.client = &http.Client{
		Timeout: 30 * time.Second,
		Jar:     &rf.jar,
	}
	rf.username = username
	rf.password = password

	success, err := rf.do_login()
	if success {
		log.Println("Logged in")
	}

	domains := make(Domains)
	rf.Domains = domains

	return success, err
}

func (rf *RF) do_login() (bool, error) {
	var err error
	var response *http.Response

	if rf.check_login() {
		return true, nil
	}

	response, err = rf.client.PostForm(baseURL+"/my/login", url.Values{"u": {rf.username}, "p": {rf.password}})
	if err != nil {
		rf.retries += 1
		log.Fatal(err)
		return false, err
	}

	rf.doc, err = goquery.NewDocumentFromReader(response.Body)

	if err != nil {
		rf.retries += 1
		log.Fatal(err)
		return false, err
	}

	is_login := rf.check_login()

	if is_login {
		rf.retries = 0
		return true, nil
	} else {
		rf.retries += 1
		return false, err
	}
}

func (rf *RF) SaveSession() {
	err := rf.jar.Save()
	if err != nil {
		log.Fatal(err)
	}
}

func (rf *RF) get_domainlist() error {
	domains := make(Domains)
	var err error
	var response *http.Response

	page := 1

	for {
		response, err = rf.client.Get(fmt.Sprintf(baseURL+"/my/domains/list?sb=ST_TS_EXPIRES&sd=asc&site=%v", page))
		rf.doc, err = goquery.NewDocumentFromReader(response.Body)
		if err != nil {
			log.Fatal(err)
		}
		if !rf.check_login() {
			return fmt.Errorf("Not logged in")
		}

		nextPage := false

		rf.doc.Find("tr.dlistitem").Each(func(i int, s *goquery.Selection) {
			domain := DomainName(strings.TrimSpace(s.Find("td.col_domain > a").Text()))
			href, _ := s.Find("td.col_domain > a").Attr("href")

			// log.Println(domain, "\t", href)
			domains[domain] = Domain{uri: href}
		})

		rf.doc.Find("div.re > div > a").EachWithBreak(func(i int, s *goquery.Selection) bool {
			if s.Text() == "»" {
				nextPage = true
				return false
			}
			return true

		})
		if nextPage {
			page += 1
		} else {
			break
		}
	}
	for k, v := range domains {
		rf.Domains[k] = v
	}
	return nil
}

func domainname2uripart(d DomainName) string {
	s := string(d)
	a := strings.Split(s, ".")
	for i := len(a)/2 - 1; i >= 0; i-- {
		opp := len(a) - 1 - i
		a[i], a[opp] = a[opp], a[i]

	}
	return "*/" + strings.Join(a, "/") + "/"
}

func (rf *RF) get_domain(domain_name DomainName) (Domain, error) {
	var err error
	var response *http.Response

	var uripart string
	var domain Domain

	var ok bool
	if domain, ok = rf.Domains[domain_name]; ok {
	} else {
		//return Domain{}, fmt.Errorf("Domain %v not found in Domains list", domain_name)
		log.Printf("Domain %v not found in current Domains list", domain_name)
	}

	uripart = domainname2uripart(domain_name)
	origuri := fmt.Sprintf(baseURL+"/my/domains/%srr/allinone", uripart)
	response, err = rf.client.Get(origuri)
	rf.doc, err = goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	if !rf.check_login() {
		return Domain{}, fmt.Errorf("Not logged in")
	}

	if response.Request.URL.String() != origuri {
		err := fmt.Errorf("Got redirected. Non existing domain?")
		log.Println(err)
		return Domain{}, err
	}

	domain = Domain{Name: domain_name, uri: uripart}

	domain.RRs = make(map[uint]RR)

	rf.doc.Find("#dnszone > * > tr").Each(func(i int, s *goquery.Selection) {
		var id uint = 0
		idattr, _ := s.Attr("id")
		idslice := strings.Split(idattr, "_")
		if len(idslice) == 2 && idslice[0] == "a" {
			idi, _ := strconv.ParseUint(idslice[1], 10, 32)
			id = uint(idi)

			rrname := strings.TrimSpace(s.Find(fmt.Sprintf("#rr_%v_name", id)).Text())
			rrttl, _ := strconv.ParseUint(strings.TrimSpace(s.Find(fmt.Sprintf("#rr_%v_ttl", id)).Text()), 10, 32)
			if rrttl == 0 {
				// 86400 is the standard ttl on Regfish.de
				rrttl = 86400
			}
			rrtype := strings.TrimSpace(s.Find(fmt.Sprintf("#rr_%v_type", id)).Text())
			rrdata := strings.TrimSpace(s.Find(fmt.Sprintf("#rr_%v_data", id)).Text())

			if rrtype == "" {
				rrtype = "SOA"
				rrttl = 0
				rrdata = strings.ReplaceAll(strings.TrimSpace(s.Find("td:nth-child(5)").Text()), "\n", " ")
			}

			domain.RRs[id] = RR{id: id, Rname: rrname, Rttl: uint(rrttl), Rtype: rrtype, Rdata: rrdata}
		}
	})

	rf.Domains[domain_name] = Domain{Name: domain_name, RRs: domain.RRs, uri: uripart}
	return domain, nil
}

func chop(s string, b byte) string {
	if len(s) > 0 && s[len(s)-1] == b {
		s = s[0 : len(s)-1]

	}
	return s
}

func (rf *RF) get_domaincontract(domain_name DomainName) (map[string]string, error) {
	var err error
	var response *http.Response

	var uripart string

	uripart = domainname2uripart(domain_name)
	origuri := fmt.Sprintf(baseURL+"/my/domains/%scontract/", uripart)
	response, err = rf.client.Get(origuri)
	rf.doc, err = goquery.NewDocumentFromReader(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	if !rf.check_login() {
		return map[string]string{}, fmt.Errorf("Not logged in")
	}

	if response.Request.URL.String() != origuri {
		err := fmt.Errorf("Got redirected. Non existing domain?")
		log.Println(err)
		return map[string]string{}, err
	}

	contract := make(map[string]string)

	rf.doc.Find("table.datastyle > tbody > tr").Each(func(i int, s *goquery.Selection) {
		k := chop(strings.TrimSpace(s.Find("td:nth-child(1)").Text()), ':')
		v := strings.TrimSpace(s.Find("td:nth-child(2)").Text())

		if k != "" {
			contract[k] = v
		}
	})

	if val, ok := rf.Domains[domain_name]; ok {
		val.Contract = contract
		rf.Domains[domain_name] = val
	}
	return contract, nil
}

func (rf *RF) GetAll() error {
	err := rf.get_domainlist()
	for k, _ := range rf.Domains {
		_, err = rf.get_domain(k)
		_, err = rf.get_domaincontract(k)
	}
	return err
}

func PrintDomainList(l *Domains) {
	for k, _ := range *l {
		fmt.Printf("%v\n", k)
	}
}

var Usage = func() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] [domain...]\n", path.Base(os.Args[0]))
	flag.PrintDefaults()
	os.Exit(2)

}

func main() {
	log.SetOutput(ioutil.Discard)

	// flag.CommandLine.SetOutput(os.Stdout)
	flag.Usage = Usage

	opt_l := flag.Bool("l", false, "list domains")
	opt_a := flag.Bool("a", false, "all domain data as JSON")
	opt_d := flag.Bool("d", false, "dump domain data as JSON")
	opt_v := flag.Bool("v", false, "verbose mode, log on STDERR")

	flag.Parse()

	if *opt_l == false && *opt_a == false && *opt_d == false && flag.NArg() == 0 {
		flag.Usage()
	}
	if *opt_v {
		log.SetOutput(os.Stderr)
	}
	if *opt_d && flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Need domain name(s) as arguments for -d flag\n\n")
		flag.Usage()
	}

	rf := &RF{}
	rf.Login(username, password)
	defer rf.SaveSession()

	done := false
	if *opt_l {
		rf.get_domainlist()
		PrintDomainList(&rf.Domains)
		done = true
	}
	if !done && *opt_a {
		rf.GetAll()
		s, _ := json.MarshalIndent(rf.Domains, "", "  ")
		fmt.Println(string(s))
		done = true
	}
	if !done && *opt_d {
		for _, v := range flag.Args() {
			rf.get_domain(DomainName(v))
			rf.get_domaincontract(DomainName(v))
		}
		s, _ := json.MarshalIndent(rf.Domains, "", "  ")
		fmt.Println(string(s))
	}
}
