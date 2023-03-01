# D-Link DIR-615 vulns (PoC)

The Internet went down and I was so bored... I decided to scan my router and found something interesting...

All exploits tested on **DIR-615 E4 Ver.: 5.10** with **Kali Linux** usage.


#### D-Link DIR-615 TFTP DoS (Buffer Overflow) PoC

This is very weak exploit, but this is exists and this is buffer overflow. If you try hard you will get TFTP Buffer Overflow RCE :)

Example usage:
```shell
python3 dir615_tftp_dos_poc.py
```

Tested on **Kali Linux**.


#### D-Link DIR-615 TFTP Credentials Disclosure (PoC)

This exploit is more interesting, this allows to get **passwd**, **shadow** files. And this doesn't need authorization, root privileges. If you know, where router admin password is, you can open issue or rewrite this script to get it files.

Example usage:
```shell
mkdir creds
python3 dir615_tftp_creds_disclosure.py -P creds
```
