import xml.etree.ElementTree as ET

def parse_hosts(xml_file):
    """
    Returns {"hosts":[{"ip":..,"hostname":..,"mac":..,"state":..,"ports":[{...}],"host_scripts":[...]}]}
    """
    try:
        root = ET.parse(xml_file).getroot()
    except Exception as e:
        return {"hosts": [], "error": str(e)}

    hosts = []
    for host in root.findall("host"):
        state_el = host.find("status")
        state = state_el.get("state") if state_el is not None else "unknown"

        ip_el = host.find("address[@addrtype='ipv4']")
        mac_el = host.find("address[@addrtype='mac']")
        ip = ip_el.get("addr") if ip_el is not None else "N/A"
        mac = mac_el.get("addr") if mac_el is not None else ""
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ""

        ports = []
        for p in host.findall("ports/port"):
            pid = p.get("portid","")
            proto = p.get("protocol","")
            state_p = (p.find("state").get("state") if p.find("state") is not None else "")
            svc = p.find("service")
            service = svc.get("name") if svc is not None else ""
            version = svc.get("version") if svc is not None and "version" in svc.attrib else ""
            product = svc.get("product") if svc is not None and "product" in svc.attrib else ""
            extrainfo = svc.get("extrainfo") if svc is not None and "extrainfo" in svc.attrib else ""
            # build a readable version string
            ver_parts = []
            if product: ver_parts.append(product)
            if version: ver_parts.append(version)
            if extrainfo: ver_parts.append(extrainfo)
            ver = " ".join(ver_parts).strip()

            # collect scripts attached to port (vuln outputs)
            scripts = []
            for sc in p.findall('script'):
                sid = sc.get('id','script')
                sout = sc.get('output','').strip()
                scripts.append({'id': sid, 'output': sout})

            ports.append({
                "port": pid, "proto": proto, "state": state_p,
                "service": service, "version": ver, "scripts": scripts
            })

        # host-level scripts
        host_scripts = []
        for sc in host.findall('hostscript/script'):
            host_scripts.append({'id': sc.get('id','script'), 'output': sc.get('output','').strip()})

        hosts.append({
            "ip": ip, "hostname": hostname, "mac": mac, "state": state,
            "ports": ports, "host_scripts": host_scripts
        })

    return {"hosts": hosts}
