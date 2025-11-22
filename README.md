# Hazzy Security Audit Pro (FREE)

Advanced security audit GitHub Action (FREE full features).  
Performs DNS, WHOIS (raw), HTTPS check, security headers, SSL info, basic safe port checks and WAF hints.

**Use responsibly — only scan domains you own or have permission for.**

## Usage
```yaml
- name: Security Audit
  uses: yourname/hazzy.security_auditpro@v1
  with:
    url: "example.com"
    ports: "22,80,443"
