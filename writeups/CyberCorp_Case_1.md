# CyberCorp Case 1

## questions

1. What is the build number (in the format ddddd, where each d is a single decimal number, for example - 12345) of the installed Windows version?
    - 17134
    - Solve: WRR --> .\Registry Hives\software --> Windows installation tab

2. What is the parent process PID of the process, that accepts incoming network connections on the port 1900/UDP?

volatility --> imageinfo --> profile

with volatility3:

- ./vol.py -f ../CyberPolygon_Forensic_Artifacts/memdump.mem windows.pslist.PsList > pslist.txt
- ./vol.py -f ../CyberPolygon_Forensic_Artifacts/memdump.mem windows.pslist.PsTree > pstree.txt
- ./vol.py -f ../CyberPolygon_Forensic_Artifacts/memdump.mem windows.netscan.NetScan > netscan.txt

Solve:

- `cat netscan.txt|grep 1900`

```bash
0xcd83ffc2b2f0  UDPv6   fe80::114:c5ef:2a5c:be56        1900    *       0               4688    svchost.exe     2020-06-20 18:36:22.000000 
0xcd83ffc3a2f0  UDPv6   ::1     1900    *       0               4688    svchost.exe     2020-06-20 18:36:22.000000 
0xcd8400b6d8a0  UDPv4   192.168.184.130 1900    *       0               4688    svchost.exe     2020-06-20 18:36:22.000000 
0xcd8400b76010  UDPv4   127.0.0.1       1900    *       0               4688    svchost.exe     2020-06-20 18:36:22.000000 
```

- cat ./pstree.txt | grep 4688

```bash
** 4688 648     svchost.exe     0xcd83ffc5c580  6       -       0       False   2020-06-20 18:36:22.000000      N/A
```

3. What is the IP address of the attacker command and control center, the connection with which was still active at the time of forensic artifacts acquisition?

- looking at it, we need a ESTABLISHED connection
- `cat netscan.txt | grep ESTABLISHED`

```bash
0xcd83febe4a80  TCPv4   192.168.184.130 50242   151.101.1.16    443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:52.000000 
0xcd83fec454c0  TCPv4   192.168.184.130 50199   54.85.86.160    443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:40.000000 
0xcd83fec7f700  TCPv4   192.168.184.130 50368   192.168.184.100 445     ESTABLISHED     4       System  2020-06-20 19:35:38.000000 
0xcd8400a37010  TCPv4   192.168.184.130 49730   51.105.249.239  443     ESTABLISHED     2844    svchost.exe     2020-06-20 18:38:41.000000 
0xcd8400c5ccc0  TCPv4   192.168.184.130 50181   151.101.65.67   443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:31.000000 
0xcd8400e62cc0  TCPv4   192.168.184.130 50223   151.101.2.2     443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:47.000000 
0xcd8400f6b620  TCPv4   192.168.184.130 50213   151.101.2.202   443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:45.000000 
0xcd8400f92cc0  TCPv4   192.168.184.130 50179   151.101.65.67   443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:31.000000 
0xcd8401006bb0  TCPv4   192.168.184.130 50346   151.101.2.133   443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:31:53.000000 
0xcd84010dacc0  TCPv4   192.168.184.130 50210   151.101.84.157  443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:44.000000 
0xcd84015ab260  TCPv4   192.168.184.130 50208   151.101.1.16    443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:43.000000 
0xcd840169d2f0  TCPv4   192.168.184.130 50133   196.6.112.70    443     ESTABLISHED     4224    rundll32.exe    2020-06-20 19:29:06.000000 
0xcd840191a010  TCPv4   192.168.184.130 50286   151.101.2.49    443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:31:03.000000 
0xcd8401b03970  TCPv4   192.168.184.130 50328   151.101.2.133   443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:31:21.000000 
0xcd8401c50cc0  TCPv4   192.168.184.130 50226   104.244.42.133  443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:51.000000 
0xcd8401e06cc0  TCPv4   192.168.184.130 50227   104.244.42.131  443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:51.000000 
0xcd8401ef4980  TCPv4   192.168.184.130 50456   184.50.175.209  443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:48:06.000000 
0xf80020581cc0  TCPv4   192.168.184.130 50223   151.101.2.2     443     ESTABLISHED     3640    chrome.exe      2020-06-20 19:30:47.000000 
                                                                                                                                              
```

```bash
0xcd840169d2f0  TCPv4   192.168.184.130 50133   196.6.112.70    443     ESTABLISHED     4224    rundll32.exe    2020-06-20 19:29:06.000000
```

4. What is the PID of the process where malicious code was located at the moment of forensic artifacts acquisition?

I dont have a single clue how I got to this, but:
- in pslist: winlogon.exe is executing and spawns: cmd.exe, etc.
- `3232    6064    winlogon.exe    0xcd840106d580  7       -       3       False   2020-06-20 19:28:44.000000      N/A     Disabled`
- 3232

```bash
cat pslist.txt | grep 3232
3232    6064    winlogon.exe    0xcd840106d580  7       -       3       False   2020-06-20 19:28:44.000000      N/A     Disabled
4852    3232    fontdrvhost.ex  0xcd8401109580  5       -       3       False   2020-06-20 19:28:44.000000      N/A     Disabled
8100    3232    dwm.exe 0xcd83fecff080  11      -       3       False   2020-06-20 19:28:44.000000      N/A     Disabled
1748    3232    userinit.exe    0xcd83ffef2580  0       -       3       False   2020-06-20 19:28:55.000000      2020-06-20 19:29:20.000000      Disabled
5224    3232    cmd.exe 0xcd84012a84c0  0       -       3       False   2020-06-20 19:29:54.000000      2020-06-20 19:31:55.000000      Disabled
288     3232    cmd.exe 0xcd8400e37080  0       -       3       False   2020-06-20 19:33:00.000000      2020-06-20 19:33:29.000000      Disabled
3928    3232    cmd.exe 0xcd83febcf580  0       -       3       False   2020-06-20 19:34:27.000000      2020-06-20 19:35:51.000000      Disabled
```

notes
- vol2 malfind --> MZ means executable --> possible malware
- Event log explorer, google right event log
  - eventID 4688 = start process

- chainsaw tool --> log analyzer
- Persistence --> WMI (Windows Management Instrumentation)