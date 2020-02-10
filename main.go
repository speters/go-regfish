package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
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
		uri  string
		Name DomainName
	}
	Domains map[DomainName]Domain
)

const baseURL = "https://www.regfish.de"

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
	jar, _ := cookiejar.New(&cookiejar.Options{PersistSessionCookies: true})
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
	rf.Domains = domains
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
		return Domain{}, fmt.Errorf("Got redirected. Non existing domain?")
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
			log.Println(id)

			rrname := strings.TrimSpace(s.Find(fmt.Sprintf("#rr_%v_name", id)).Text())
			rrttl, _ := strconv.ParseUint(strings.TrimSpace(s.Find(fmt.Sprintf("#rr_%v_ttl", id)).Text()), 10, 32)
			if rrttl == 0 {
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

	return domain, nil
}

func main() {
	rf := &RF{}
	rf.Login(username, password)
	defer rf.SaveSession()

	rf.get_domainlist()
	for k, v := range rf.Domains {
		fmt.Printf("key[%s] value[%s]\n", k, v.uri)

	}
	rf.SaveSession()

	fmt.Println(domainname2uripart("rootcamp.net"))
	d, _ := rf.get_domain("rootcamp.net")
	s, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(s))

	os.Exit(3)

	//	log.Println("Number of bytes copied to STDOUT:", n)
}
