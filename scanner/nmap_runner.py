import subprocess
import os

# Profiles tuned for Win/Kali/macOS
PROFILES = {
    "discover": "-sn",
    "quick": "-T4 -F -sV",
    "deep": "-sS -T4 -p- -sV",
    "vuln": "-sS -T4 -p- -sV --script vuln --script-timeout 30s"
}

PROFILE_PURPOSES = {
    "discover": "Host discovery (ping sweep, check which hosts are up)",
    "quick": "Quick scan of common ports with version detection",
    "deep": "Full port scan with detailed service versions",
    "vuln": "Full scan + common NSE vuln checks (may be intrusive)"
}

def run_nmap(target: str, profile: str, output_dir: str, timestamp: str):
    os.makedirs(output_dir, exist_ok=True)
    xml_path = os.path.join(output_dir, f"{profile}_{timestamp}.xml")
    args = f"{PROFILES[profile]} {target} -oX {xml_path}"
    cmd = f"nmap {args}"
    completed = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    combined = (completed.stdout or "") + (completed.stderr or "")
    return combined, xml_path, cmd