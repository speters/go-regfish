# go-regfish - a simple domain and contract lister for Regfish Domain Hoster

This simple tools lists the domains hosted by Regfish.de.

Its main purpose is to keep track of the date of the contracts.

```
Usage: go-regfish [options] [domain...]
  -L    list domains with contract end
  -a    all domain data as JSON
  -c string
        path to config file (default "~/.smtpclient.ini")
  -d    dump domain data as JSON
  -l    list domains
  -v    verbose mode, log on STDERR
```

### ini file format
```
[go-regfish]
username=foo
password=bar
```

