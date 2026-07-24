# SIGMA Kuralları

## SIEM Tespit Formatı

Bu depo, farklı saldırı tekniklerini tespit etmeye yönelik Sigma kurallarını ve açıklamalarını içerir. Her kural aşağıdaki standart formatta doküman edilmiştir:

- **Tehdit Türü & MITRE ATT&CK Mapping**
- **Log Kaynağı**
- **Tespit Mekanizması**
- **False Positive İhtimalleri**
- **Kritiklik Seviyesi**

---

## Potential Keylogging Software Execution

Windows sistemlerde kullanıcı klavye girdilerini takip eden ve kaydetmeye çalışan bilinen Keylogger yazılımlarının veya bunlarla ilişkili komut satırı parametrelerinin çalıştırılmasını tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Credential Access**
- **T1056.001 - Input Capture: Keylogging**

### Tespit Mekanizması
- Bilinen zararlı yürütülebilir dosya adları:
  - `keylogger.exe`
  - `pyhook.exe`
  - `kl.exe`
- Klavye dinleme işlemleri için kullanılan Windows API çağrıları veya parametreleri:
  - `SetWindowsHookEx`
  - `GetAsyncKeyState`
  - `--log-keys`
  - `logkeys`

### False Positive İhtimalleri
- Yetkili uzak masaüstü/yönetim araçları (RAT)
- Erişilebilirlik (ekran okuyucu/klavye) yazılımları

### Kritiklik Seviyesi
**High**

---

## Application Layer Protocol: DNS Tunneling or C2 Activity

DNS protokolü kötüye kullanılarak yapılan tünelleme (DNS Tunneling), veri sızdırma (data exfiltration) veya komuta kontrol (C2) sunucusu haberleşme aktivitelerini tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Command and Control**
- **T1071.004 - Application Layer Protocol: DNS**

### Log Kaynağı
- `zeek (DNS)`

### Tespit Mekanizması
Aşağıdaki iki durum aynı anda gerçekleştiğinde tetiklenir:

- Subdomain alanının **60 karakterden uzun** olması.
- Sorgu tipinin aşağıdaki kayıt türlerinden biri olması:
  - `TXT`
  - `NULL`
  - `CNAME`

### False Positive İhtimalleri
- Sophos
- Cisco Umbrella
- Meşru DMARC/DKIM/SPF kayıt kontrolleri

### Kritiklik Seviyesi
**Medium**

---

## Application Layer Protocol: Web Protocols C2 and Malicious Egress Activity

Web protokolleri (HTTP/HTTPS) kullanılarak C2 sunucularıyla kurulan dışa dönük (egress) şüpheli bağlantıları ve sızma testi araçlarının izlerini tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Command and Control**
- **T1071.001 - Application Layer Protocol: Web Protocols**

### Log Kaynağı
- `webproxy`
  - Zscaler
  - Palo Alto
  - Squid
  - Zeek HTTP

### Tespit Mekanizması

Aşağıdaki durumlardan biri gerçekleştiğinde tetiklenir:

#### Şüpheli User-Agent
- CobaltStrike
- Metasploit
- Empire
- curl
- Python-urllib
- Go-http-client
- powershell

#### Doğrudan IP + Şüpheli URI
Alan adı yerine doğrudan IP adresine yapılan ve aşağıdaki URI'leri hedefleyen istekler:

- `/admin/get.php`
- `/news.php`
- `/connect`
- `/login/process.php`

### False Positive İhtimalleri
- DevOps otomasyon betikleri
- İç web servisleri

### Kritiklik Seviyesi
**High**

---

## Adversary-in-the-Middle: Rogue DHCP Server Activity

Ağ üzerinde yetkisiz (rogue) DHCP sunucularını veya DHCP Spoofing aktivitelerini tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Credential Access**
- **Defense Evasion**
- **T1557.003 - Adversary-in-the-Middle: DHCP Spoofing**

### Log Kaynağı
- Windows DHCP Server Event Logs

### Tespit Mekanizması

Aşağıdaki Event ID'lerden herhangi biri oluştuğunda tetiklenir:

#### Şüpheli DHCP Olayları
- Event ID **1056**
- Event ID **1020**
- Event ID **1046**

#### Yetkilendirme Durumları
- Event ID **1036**
- Event ID **1059**

### False Positive İhtimalleri
- Yanlış yapılandırılmış DHCP sunucuları
- Test laboratuvarları
- Ağ bakım çalışmaları

### Kritiklik Seviyesi
**High**

---

## Subvert Trust Controls: Mark-of-the-Web (MOTW) Bypass

İnternetten indirilen dosyalardaki Mark-of-the-Web korumasını kaldırmaya yönelik aktiviteleri tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Defense Evasion**
- **T1553.005 - Mark-of-the-Web Bypass**

### Log Kaynağı
- Windows Process Creation Logs

### Tespit Mekanizması

#### Doğrudan MOTW Silme
- `:Zone.Identifier`
- `Unblock-File`
- `Remove-Item -Path * :Zone.Identifier`

#### Disk İmajı Bağlama
- `Mount-DiskImage`
- `Mount-VHD`

### False Positive İhtimalleri
- Yazılım geliştiricileri
- ISO kullanan sistem yönetim betikleri

### Kritiklik Seviyesi
**High**

---

## Network Boundary Bridging: NAT Traversal and Tunneling Activity

Tünelleme araçlarının veya UPnP port yönlendirme komutlarının çalıştırılmasını tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Command and Control**
- **Defense Evasion**
- **T1599.001 - External Network Bridge**

### Log Kaynağı
- Windows Process Creation Logs

### Tespit Mekanizması

#### Tünelleme Araçları
- chisel
- frpc
- frps
- ngrok
- gost
- stun
- zerotier
- tailscale

#### UPnP Komutları
- `AddPortMapping`
- `upnpc`
- `miniupnpc`

### False Positive İhtimalleri
- Tailscale
- ZeroTier
- Teams
- Zoom

### Kritiklik Seviyesi
**High**

---

## Process Injection: Dynamic-Link Library Injection

DLL Injection ve Remote Thread Injection aktivitelerini tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Defense Evasion**
- **Privilege Escalation**
- **T1055.001 - DLL Injection**

### Log Kaynağı
- Sysmon Event ID **7**
- Sysmon Event ID **8**

### Tespit Mekanizması

#### Remote Thread Injection
Hedef süreçler:

- `lsass.exe`
- `svchost.exe`
- `explorer.exe`
- `winlogon.exe`

#### Şüpheli DLL Yüklenmesi

Şüpheli dizinler:

- `AppData\Local\Temp`
- `Users\Public`
- `Windows\Temp`
- `ProgramData`

### False Positive İhtimalleri
- EDR
- AV
- Debugger
- Hooking yapan kurumsal yazılımlar

### Kritiklik Seviyesi
**High**

---

## Potential Rootkit Installation or Driver Loading

Rootkit kurulumu veya BYOVD saldırılarıyla ilişkili sürücü yükleme aktivitelerini tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Defense Evasion**
- **T1014 - Rootkit**

### Log Kaynağı
- Windows Process Creation Logs

### Tespit Mekanizması

#### Şüpheli Araçlar
- `kdmapper.exe`
- `gmer.exe`
- `mhyprot.sys`
- `KDU.exe`
- `drvload.exe`

#### Şüpheli Komutlar
- `sc create type= kernel`
- `fltmc unload`
- `bcdedit /set testsigning on`
- `bcdedit /set nointegritychecks on`

### False Positive İhtimalleri
- Meşru sürücü güncellemeleri
- Donanım geliştirme ortamları

### Kritiklik Seviyesi
**High**

---

## Systemd Unit File Creation or Modification

Linux sistemlerde persistence amacıyla systemd servis veya timer dosyalarının oluşturulmasını ya da değiştirilmesini tespit eder.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Persistence**
- **T1543.002 - Systemd Service**

### Log Kaynağı
- Linux File Events

### Tespit Mekanizması

Aşağıdaki dizinlerde oluşturulan veya değiştirilen:

- `/etc/systemd/system/`
- `/usr/lib/systemd/system/`
- `~/.config/systemd/user/`

Dosya uzantıları:

- `.service`
- `.timer`

### False Positive İhtimalleri
- apt
- yum
- dnf
- Meşru yazılım kurulumları

### Kritiklik Seviyesi
**High**

---

## Web Server Spawning Interactive Shell

Linux web sunucularının shell başlatmasını tespit eder. Genellikle Web Shell veya RCE saldırılarının göstergesidir.

### Tehdit Türü & MITRE ATT&CK Mapping
- **Persistence**
- **Execution**
- **T1505.003 - Web Shell**
- **T1059.004 - Unix Shell**

### Log Kaynağı
- Linux Process Creation Logs

### Tespit Mekanizması

İki koşul birlikte gerçekleşmelidir.

#### Parent Process

- httpd
- apache2
- nginx
- php-fpm
- lighttpd
- caddy
- uwsgi

#### Child Process

- sh
- bash
- dash
- zsh
- python
- perl
- php
- nc
- netcat
- ncat

### False Positive İhtimalleri
- Meşru `exec()` veya `system()` çağrıları yapan web uygulamaları

### Kritiklik Seviyesi
**High**