# Boss of the SOC v1 - Writeup

## Working with splunk, quick guide

<https://cyberdefenders.org/static/img/BOTSv1/BOTS-Guide.pdf>
<https://docs.splunk.com/Documentation/Splunk/8.0.5/SearchTutorial/Aboutthesearchapp>

- edit event sampling for convenience

## Notes throughout the challenges

- src_ip=40.80.148.42 
- dest=imreallynotbatman.com
- CMS: Joomla
- Vuln scanner used: WVS (Acunetix)

## Challenges

1. This is a simple question to get you familiar with submitting answers. What is the name of the company that makes the software that you are using for this competition? Just a six-letter word with no punctuation. **Splunk**

2. What is the likely IP address of someone from the Po1s0n1vy group scanning imreallynotbatman.com for web application vulnerabilities?

   - **40.80.148.42**

   - entered imreallynotbatman.com in the search bar
   - checked patterns tab and found a large amount of events related to the ip 40.80.148.42 on port 49468

3. What company created the web vulnerability scanner used by Po1s0n1vy? Type the company name. (For example, "Microsoft" or "Oracle")

    - When having selected the whole timeline of events regarding src_ip and dest looked through intresting fields on the lefthand side
    - http.redirect had 2 particular events:
      - "http.redirect"="<http://imreallynotbatman.com/joomla/index.php/component/search/?searchword=&ordering=popular&searchphrase=any&areas[0]=SomeCustomInjectedHeaderinjected_by_wvs">
      - searched for wvs on google --> **Acunetix**

4. What content management system is imreallynotbatman.com likely using? (Please do not include punctuation such as . , ! ? in your answer. We are looking for alpha characters only.)
   - **Joomla**
   - was present in the URL of various HTTP requests from events

5. What is the name of the file that defaced the imreallynotbatman.com website? Please submit only the name of the file with the extension (For example, "notepad.exe" or "favicon.ico").

    - Q: What is defacement of a file?
      - <https://www.imperva.com/learn/application-security/website-defacement-attack/>
      - change content on webpage with own (malicious) content
      - through access, SQLi, XSS, DNS Hijacking, Malware
    - 