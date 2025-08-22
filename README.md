\# 🔎 NX-Scout XTree



NX-Scout XTree is a \*\*lightweight Nmap automation tool\*\* written in Python.  

It helps security professionals and learners quickly perform host discovery, port scanning, and vulnerability checks with a clean \*\*tree-style tabular report\*\*.



---



\## ✨ Features

\- 🎯 \*\*Multiple Scan Profiles\*\*  

&nbsp; - \*\*Discover\*\* → Host discovery (ping sweep, checks which hosts are up)  

&nbsp; - \*\*Quick\*\* → Fast scan of common ports with service version detection  

&nbsp; - \*\*Deep\*\* → Full port scan with detailed service versions  

&nbsp; - \*\*Vuln\*\* → Full scan + common NSE vulnerability scripts (⚠️ may be intrusive)  



\- 📊 \*\*Clean Reports\*\*  

&nbsp; - Minimal \*\*tree-style console view\*\*  

&nbsp; - Optional \*\*HTML/JSON/XML export\*\*  



\- 🖥️ \*\*Details per host\*\*  

&nbsp; - IP Address  

&nbsp; - MAC Address \& Vendor  

&nbsp; - Host state (up/down)  

&nbsp; - Open Ports + Services + Versions  

&nbsp; - Vulnerability findings (if applicable)  



\- 🚀 \*\*Flexible Target Input\*\*  

&nbsp; - Single IP → `192.168.17.10`  

&nbsp; - Range → `192.168.17.1-50`  

&nbsp; - Subnet (CIDR) → `192.168.17.0/24`  



---



\## 📦 Installation



\### Requirements

\- Python \*\*3.8+\*\*

\- \[Nmap](https://nmap.org/download.html) installed \& added to PATH

\- Python packages:

&nbsp; ```bash

&nbsp; pip install -r requirements.txt



