# Network Exploitation, Reconnaissance, Vulnerability Engine & Exploit (N.E.R.V.E & Exploit)
![Nerv&Sploit](https://raw.githubusercontent.com/kavat/nerve/master/screenshots/dashboard.png)

# Table of Contents
* [Continuous Security](#Continuous-Security)
* [About NERV&SPLOIT](#)
  * [What is NERV&SPLOIT](#about-Nerv&Sploit)
  * [How it works](#how-it-works)
  * [Features](#features)
* [Prerequisites](#prerequisites)
* [Installation](#installation)
  * [Configuration file config.py](#Configuration-file-config.py)
  * [Deployment Recommendations](#Deployment-Recommendation)
  * [Installation - Docker](#docker)
  * [Installation - Bare Metal](#server)
  * [Installation - Multi Node](#Multi-Node-Installation)
  * [Upgrade](#upgrade)
* [Security](#security)
* [Usage](#usage)
* [License](#license)
* [Screenshots](#screenshots)


# Continuous Security
As [Paytm](https://github.com/paytm/nerve) said when initial branch of NERVE has been released, security scanning should be done continuously. Not daily, weekly, monthly, or quarterly.

The benefit of running security scanning continuously can be any of the following:
* You have a dynamic environment where infrastructure gets created every minute / hour / etc.
* You want to be the first to catch issues before anyone else
* You want the ability to respond quicker.

NERVE was created to address this problem. Commercial tools are great, but they are also heavy, not easily extensible, and cost money.
Next, union with Metasploit by Rapid7 (https://github.com/rapid7/metasploit-framework) has generated new build, called NERV&SPLOIT.

![Nerv&Sploit](https://github.com/kavat/nerve/blob/master/static/screenshots/12.png?raw=true)

# About NERV&SPLOIT
NERV&SPLOIT is a vulnerability scanner tailored to find low-hanging fruit level vulnerabilities, in specific application configurations, network services, and unpatched services.

Example of some of NERV&SPLOIT's detection capabilities:
* Interesting Panels (Solr, Django, PHPMyAdmin, etc.)
* Subdomain takeovers
* Open Repositories
* Information Disclosures
* Abandoned / Default Web Pages
* Misconfigurations in services (Nginx, Apache, IIS, etc.)
* SSH Servers
* Open Databases
* Open Caches
* Directory Indexing
* Best Practices
* NMAP execution without or with SSH VPN tunnel (this permits internal scan in order to detect services binded on localhost, it's important to indentify services if an attacker would want stealth persistency), named external or internal network scan
* CVE list based on packages installed list on the system (using cve-search framework forked [on my repo](https://github.com/kavat/cve-search))  
* Profile scan using DevSec framework to verify OS hardening (using my [compliance-profile](https://github.com/kavat/compliance-profile) project)
* Interface with Metasploit console (msfconsole)

# How it works
NERV&SPLOIT permits to conduce vulnerability assessment based on NMAP run, launching scanning TCP/UDP oriented and reaching informations services related. CVE search integration, OS hardering checks and msfconsole have been added to initial features building a continuos security framework

Network scan is based on NMAP library and checks and tests open doors and analysis services related: normal scan (external) does it from outside, internal scan does it from inside and it's very important when we want to check internal perimeter in order to detect all points where an attacker could do stealth persistency.

To come inside host, Flask interface creates a SSH VPN tunnel between itself and destination host (automatically or manually as indicated by UI interface).

CVE search has been implemented and joined with NERV&SPLOIT starting from the packages installed list. CVE-Search has been forked [on my repo](https://github.com/kavat/cve-search) and this version allows to perform API call with program name and version as only parameters. This provides a full list of CVE related to the packages installed on the system.

Using inspec framework and profiles official released by DevSec as:
* [Linux Baseline](https://github.com/dev-sec/linux-baseline)
* [CIS Linux](https://github.com/dev-sec/cis-dil-benchmark)
* [Windows Baseline](https://github.com/dev-sec/windows-baseline)

new project [compliance-profile](https://github.com/kavat/compliance-profile) on my repository was born. This feature allows to perform a scan to verify OS hardening suggested by DevSec profiles.

Metasploit can do all sorts of things and in this integration a web console linked to msfconsole has been realized.

Reports for every type of scan is provided.

## Manually SSH VPN tunnel creation
Manual creation has as requirement that preliminary operations on destination host has to be done by user.

User has to login to destination host and run the following command

```
sed "s/^[#]\{0,1\}PermitTunnel\(.*\)/PermitTunnel point-to-point/g" /etc/ssh/sshd_config -i
systemctl restart sshd
ip tuntap add tun0 mode tun
ip addr add X.X:X.X/30 dev tun0 # X.X.X.X is the value set in config.DEFAULT_SCAN['ip_peer_static'] in config.py
ip link set dev tun0 up
sysctl net.ipv4.ip_forward=1
sysctl net.ipv4.conf.all.route_localnet=1
iptables -t nat -I PREROUTING -i tun0 -j DNAT --to 127.0.0.1
```

After, interface will launches SSH VPN tunnel by itself (on destination host specified with SSH username and password) and it will starts assessment operations

# Limitations

Internal scan, CVE search and Compliance profile in this moment don't support Windows (in roadmap windows compatibility)

Internal scan, CVE search and Compliance profile in this moment support one host for time scan (in roadmap CIDR extension)

# Features
NERV&SPLOIT offers the following features:
* Dashboard (With a Login interface)
* Check external services status (CVE and Compliance Profile services)
* REST API (Scheduling assessments, Obtaining results, etc)
* Notifications
  * Slack
  * Email
  * Webhook
* Reports HTML for every type of scan
* Customizable scans
  * Configurable intrusiveness levels
  * Scan depth
  * Exclusions
  * DNS / IP Based
  * Thread Control
  * Custom Ports
* Network Topology Graphs
* CVE related to packages installed list
* Compliance profile execution with OS hardening best practice
* Integration with Metasploit with dedicated section in order to run msfconsole

# Prerequisites
NERV&SPLOIT will install all the prerequisites for you automatically if you choose the Server installation (CentOS 8.x and Ubuntu 22.04 LTS were tested) (by using `install/setup.sh` script). It also comes with a Dockerfile for your convenience.

Keep in mind, NERV&SPLOIT requires root access for the initial setup on bare metal (package installation, etc).

Services and Packages required for NERV&SPLOIT to run:
* Web Server (Flask)
* Redis server (binds locally)
* Nmap package (binary and Python nmap library)
* Metasploit package
* Inbound access on HTTP/S port (you can define this in config.py)

The installation script takes care of everything for you, but if you want to install it by yourself, keep in mind these are required.

For this version is strongly recommended Docker container installation.

# Installation

## Configuration file config.py
In config.py file user has to indicate new services configuration parameters, in details:

```
CVE_SCAN_SERVICE_HOST = "172.17.0.2"
CVE_SCAN_SERVICE_PORT = 5000
PROFILE_SERVICE_HOST = "172.17.0.3"
PROFILE_SERVICE_PORT = 5000
```

The first two lines indicate configuration for cve-search service, second two lines indicate configuration for compliance-profile service: both services has to be reachable from NERV&SPLOIT running host

## Deployment Recommendation
The best way to deploy it, is to run it against your infrastructure from multiple regions (e.g. multiple instances of NERV&SPLOIT, in multiple countries), and toggle continuous mode so that you can catch short-lived vulnerabilities in dynamic environments/cloud.

We typically recommend not to whitelist the IP addresses where NERV&SPLOIT will be initiating the scans from, to truly test your infrastructure from an attacker standpoint.

To make NERV&SPLOIT fairly lightweight, there's no use of a database other than Redis.

If you want to store your vulnerabilities long term, we recommend using the Web hook feature. At the end of each scan cycle, NERV&SPLOIT will dispatch a JSON payload to an endpoint of your choice, and you can then store it in a database for further analysis.

Here are the high level steps we recommend to get the most optimal results:
1. Deploy NERV&SPLOIT on 1 or more servers.
2. Create a script that fetches your Cloud services (such as AWS Route53 to get the DNS, AWS EC2 to get the instance IPs, AWS RDS to get the database IPs, etc.) and maybe a static list of IP addresses if you have assets in a Datacenter.
3. Call NERV&SPLOIT API (`POST /api/scan/submit`) and schedule a scan using the assets you gathered in step #2.
4. Fetch the results programmatically and act on them (SOAR, JIRA, SIEM, etc.)
5. Add your own logic (exclude certain alerts, add to database, etc.)

## Docker
### Clone the repository
`git clone git@github.com:kavat/nerve.git && cd nerve`

### Build the Docker image
`docker build -t nerve .`

### Create a container from the image
`docker run -e username="YOUR_USER" -e password="YOUR_PASSWORD" -d --privileged -p 8080:8080 nerve`

In your browser, navigate to http://ip.add.re.ss:8080 and login with the credentials you specified to in the previous command.

# Server
### Navigate to /opt
`cd /opt/`

### Clone the repository
`git clone git@github.com:kavat/nerve.git && cd nerve`

### Run Installer (requires root)
`bash install/setup.sh`

### Check NERV&SPLOIT is running
`systemctl status nerve`

In your browser, navigate to http://ip.add.re.ss:8080 and use the credentials printed in your terminal.

# Multi Node Installation
If you want to install NERV&SPLOIT in a multi-node deployment, you can follow the normal bare metal installation process, afterwards:
1. Modify the config.py file on each node
2. Change the server address of Redis `RDS_HOST` to point to a central Redis server that all NERV&SPLOIT instances will report to.
3. Run `service nerve restart` or `systemctl restart nerve` to reload the configuration
4. Run `apt-get remove redis` / `yum remove redis` (Depending on the Linux Distribution) since you will no longer need each instance to report to itself.
Don't forget to allow port 3769 inbound on the Redis instance, so that the NERV&SPLOIT instances can communicate with it.

# Upgrade
If you want to upgrade your platform, the fastest way is to simply git clone and overwrite all the files while keeping key files such as configurations.

* Make a copy of `config.py` if you wish to save your configurations
* Remove `/opt/nerve` and git clone it again.
* Move `config.py` file back into `/opt/nerve`
* Restart the service using `systemctl restart nerve`.

You could set up a cron task to auto-upgrade NERV&SPLOIT. There's an API endpoint to check whether you have the latest version or not that you could use for this purpose: `GET /api/update/platform`

# Security
There are a few security mechanisms implemented into NERV&SPLOIT you need to be aware of.

* Content Security Policy - A response header which controls where resource scan be loaded from.
* Other Security Policies - These Response headers are enabled: Content-Type Options, X-XSS-Protection, X-Frame-Options, Referer-Policy
* Brute Force Protection - A user will get locked if more than 5 incorrect login attempts are made.
* Cookie Protection - Cookie security flags are used, such as SameSite, HttpOnly, etc.

If you identify a security vulnerability, please submit a bug to us on GitHub.

We recommend to take the following steps before and after installation
1. Set a strong password (a password will be set for you if you use the bare metal installation)
2. Protect the inbound access to the panel (Add your management IP addresses to the allow list of the local firewall)
3. Add HTTPS (you can either patch Flask directly, or use a reverse proxy like nginx)
4. Keep the instance patched

# License
From orginal NERVE project, NERV&SPLOIT is distributed under the MIT License. See LICENSE for more information.

# Screenshots
## Login Screen
![Nerve](https://github.com/kavat/nerve/blob/master/static/screenshots/1.png?raw=true)
## Dashboard Screen
![Nerve](https://raw.githubusercontent.com/kavat/nerve/master/screenshots/dashboard.png)
## Assessment Configuration
![Nerve](https://github.com/kavat/nerve/blob/master/static/screenshots/3.png?raw=true)
## Reporting
![Nerve](https://raw.githubusercontent.com/kavat/nerve/master/screenshots/reporting.png)
## Network Map
![Nerve](https://github.com/kavat/nerve/blob/master/static/screenshots/6.png?raw=true)
## Vulnerabilities Network page
![Nerve](https://raw.githubusercontent.com/kavat/nerve/master/screenshots/vulnerabilities_network.png)
## Vulnerabilities CVE page
![Nerve](https://raw.githubusercontent.com/kavat/nerve/master/screenshots/vulnerabilities_cve.png)
## Vulnerabilities Inspec page
![Nerve](https://raw.githubusercontent.com/kavat/nerve/master/screenshots/vulnerabilities_inspec.png)
## Log Console
![Nerve](https://github.com/kavat/nerve/blob/master/static/screenshots/8.png?raw=true)
## Metasploit Console
![Nerve](https://github.com/kavat/nerve/blob/master/static/screenshots/13.png?raw=true)
