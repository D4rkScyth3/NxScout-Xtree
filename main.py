import os
import time

from scanner import run_nmap, PROFILES, PROFILE_PURPOSES, parse_hosts, render_console_minimal, render_html_minimal

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