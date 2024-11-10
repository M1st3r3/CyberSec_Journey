
Subdomain enumeration
```sh
ffuf -u http://[DOMAIN_NAME]/ -H 'HOST: FUZZ.[DOMAIN_NAME]' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac
```


