def _mk_table(headers, rows):
    # simple left-aligned ASCII grid
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(str(c)))
    def rowline(cells):
        return " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(cells))
    sep = "-+-".join("-"*w for w in widths)
    out = [rowline(headers), sep]
    for r in rows:
        out.append(rowline(r))
    return "\n".join(out)

def render_console_minimal(data, profile='quick'):
    lines = []
    for h in data.get("hosts", []):
        lines.append(f"Host: {h.get('ip','N/A')}")
        if h.get("hostname"): lines.append(f"  Hostname: {h['hostname']}")
        if h.get("mac"): lines.append(f"  MAC: {h['mac']}")
        lines.append(f"  State: {h.get('state','unknown')}")
        ports = h.get("ports", [])
        if profile == 'discover':
            lines.append("")  # nothing else for discover
        else:
            lines.append("")
            lines.append("Ports:")
            if ports:
                headers = ["Port", "Proto", "State", "Service", "Version"]
                rows = [[p["port"], p["proto"], p["state"], p["service"], p["version"]] for p in ports]
                lines.append(_mk_table(headers, rows))
            else:
                lines.append("  (no open ports)")
        # If vuln profile, include scripts/vulns
        if profile == 'vuln':
            vuln_lines = []
            # collect per-port scripts
            for p in ports:
                scripts = p.get('scripts', [])
                if scripts:
                    vuln_lines.append(f"\nVulnerabilities for {p['port']}/{p['proto']}:")
                    for s in scripts:
                        out = s.get('output','').strip()
                        if out:
                            # keep first line summary
                            first = out.splitlines()[0]
                            vuln_lines.append(f"  - [{s.get('id')}] {first}")
                        else:
                            vuln_lines.append(f"  - [{s.get('id')}]")
            # host-level scripts
            if h.get('host_scripts'):
                vuln_lines.append("\nHost script findings:")
                for s in h.get('host_scripts', []):
                    first = s.get('output','').splitlines()[0] if s.get('output') else ''
                    vuln_lines.append(f"  - [{s.get('id')}] {first}")
            if vuln_lines:
                lines.append("")
                lines.append("Vulnerabilities:")
                lines.extend(vuln_lines)
        lines.append("")
    return "\n".join(lines) if lines else "(no hosts parsed)"

def render_html_minimal(data, profile, target, date_str):
    # Pure-Python HTML, no Jinja needed
    def esc(s):
        return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    head = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>NX-Scout Report</title>
<style>
body {{ font-family: Arial; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; }}
tr:nth-child(even) {{ background-color: #f9f9f9; }}
h1, h2 {{ color: #333; }}
</style>
</head>
<body>
<h1>NX-Scout Scan Report</h1>
<p><strong>Profile:</strong> {esc(profile)} | <strong>Target:</strong> {esc(target)} | <strong>Date:</strong> {esc(date_str)}</p>
"""
    sections = []
    for host in data.get("hosts", []):
        ip = esc(host.get("ip",""))
        hostname = esc(host.get("hostname",""))
        mac = esc(host.get("mac",""))
        state = esc(host.get("state",""))

        section = [f"<h2>Host: {ip}</h2>", "<p>"]
        if hostname:
            section.append(f"<strong>Hostname:</strong> {hostname}<br>")
        if mac:
            section.append(f"<strong>MAC:</strong> {mac}<br>")
        section.append(f"<strong>State:</strong> {state}")
        section.append("</p>")

        ports = host.get("ports", [])
        if profile != 'discover' and ports:
            section.append("<table><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th></tr>")
            for p in ports:
                section.append("<tr>" +
                    f"<td>{esc(p.get('port',''))}</td>" +
                    f"<td>{esc(p.get('proto',''))}</td>" +
                    f"<td>{esc(p.get('state',''))}</td>" +
                    f"<td>{esc(p.get('service',''))}</td>" +
                    f"<td>{esc(p.get('version',''))}</td>" +
                    "</tr>")
            section.append("</table>")
        elif profile != 'discover':
            section.append("<p><em>No open ports found</em></p>")

        # vuln section for vuln profile
        if profile == 'vuln':
            vuln_html = []
            for p in ports:
                scripts = p.get('scripts', [])
                if scripts:
                    vuln_html.append(f"<h3>Vulnerabilities for {esc(p.get('port'))}/{esc(p.get('proto'))}</h3>")
                    vuln_html.append("<ul>")
                    for s in scripts:
                        out = (s.get('output') or '').splitlines()[0] if s.get('output') else ''
                        vuln_html.append(f"<li><strong>{esc(s.get('id'))}</strong>: {esc(out)}</li>")
                    vuln_html.append("</ul>")
            if host.get('host_scripts'):
                vuln_html.append("<h3>Host script findings</h3><ul>")
                for s in host.get('host_scripts', []):
                    out = (s.get('output') or '').splitlines()[0] if s.get('output') else ''
                    vuln_html.append(f"<li><strong>{esc(s.get('id'))}</strong>: {esc(out)}</li>")
                vuln_html.append("</ul>")
            if vuln_html:
                section.append("<h2>Vulnerabilities</h2>")
                section.extend(vuln_html)

        sections.append("\n".join(section))

    tail = "</body></html>"
    return head + "\n\n".join(sections) + tail
