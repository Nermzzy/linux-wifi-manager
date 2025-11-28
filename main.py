#!/usr/bin/env python3


import subprocess, json, time, os, sys, getpass, logging, argparse, signal
from datetime import datetime

# ----- Files in current working directory (portable) -----
CONFIG_FILE = "week3_cyber_tools/networking/wifi_manager/wifi_manager_config.json"
STATE_FILE = "week3_cyber_tools/networking/wifi_manager/wifi_manager_state.json"
LOG_FILE = "week3_cyber_tools/networking/wifi_manager/wifi_manager_pro.log"
KEYRING_SERVICE = "wi-fi"

# ----- Defaults -----
DEFAULT_CONFIG = {
    "auto_switch_in_daemon": False,   # if daemon should auto-switch when best candidate found
    "preferred": [],                  # user-preferred SSIDs (ordered)
    "blacklist": [],                  # SSIDs never auto-connect
    "check_interval": 20,             # daemon sleep between checks (seconds)
    "max_retries": 3,                 # attempts when actively connecting
    "backoff_base": 3,                # seconds * attempt multiplier wait
    "min_signal_diff_to_switch": 10,  # percent stronger required to auto-switch (avoid flapping)
    "notify": True,                   # use notify-send if available
    "auto_save_passwords": False      # if True, daemon will save keyring passwords if used interactively
}

# ----- Logging -----
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

# ----- Optional keyring support -----/
try:
    import keyring
    KEYRING_AVAILABLE = True
except Exception:
    KEYRING_AVAILABLE = False

# ----- Helper functions -----
def run_cmd_list(cmd_list, timeout=20):
    """Run cmd list and return (rc, stdout_text)."""
    try:
        proc = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout.strip()
    except Exception as e:
        return 1, str(e)

def run_cmd(cmd_str, timeout=20):
    """Run shell command string and return stdout or None."""
    try:
        out = subprocess.check_output(cmd_str, shell=True, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        return out
    except subprocess.CalledProcessError as e:
        return e.output if e.output else None
    except Exception as e:
        return None

def notify(summary, body=""):
    cfg = load_config()
    if not cfg.get("notify", True): 
        return
    if which("notify-send"):
        try:
            subprocess.run(["notify-send", summary, body], check=False)
        except Exception as e:
            logging.debug("notify-send failed: %s", e)

def which(name):
    import shutil
    return shutil.which(name)

# ----- Config / State management (local) -----
def ensure_files():
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
    if not os.path.exists(STATE_FILE):
        save_state({})

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def load_state():
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(st):
    with open(STATE_FILE, "w") as f:
        json.dump(st, f, indent=2)

def get_last_ssid():
    return load_state().get("last_ssid")

def set_last_ssid(ssid):
    s = load_state()
    s["last_ssid"] = ssid
    s["last_seen_at"] = datetime.utcnow().isoformat() + "Z"
    save_state(s)

# ----- nmcli parsing & network ops -----
def scan_networks():
    """
    Use nmcli multiline output for robust parsing.
    Returns list of dicts: {ssid, signal(int 0-100), secure(bool)}
    """
    rc, out = run_cmd_list(["nmcli", "-f", "SSID,SIGNAL,SECURITY", "-m", "multiline", "device", "wifi", "list"])
    if rc != 0 or not out:
        logging.warning("nmcli scan failed: rc=%s out=%s", rc, out)
        return []
    blocks = [b.strip() for b in out.split("\n\n") if b.strip()]
    nets = []
    seen = set()
    for block in blocks:
        ssid = None; signal = 0; security = None
        for line in block.splitlines():
            if line.startswith("SSID:"):
                ssid = line.split(":", 1)[1].strip()
            elif line.startswith("SIGNAL:"):
                try:
                    signal = int(line.split(":",1)[1].strip())
                except:
                    signal = 0
            elif line.startswith("SECURITY:"):
                security = line.split(":",1)[1].strip()
        if not ssid or ssid in seen:
            continue
        seen.add(ssid)
        nets.append({"ssid": ssid, "signal": signal, "secure": bool(security and security not in ("", "--"))})
    nets.sort(key=lambda x: x["signal"], reverse=True)
    return nets

def list_saved_connections():
    rc, out = run_cmd_list(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    saved = []
    if rc != 0 or not out:
        return saved
    for line in out.splitlines():
        if not line: continue
        parts = line.split(":", 1)
        if len(parts) != 2: continue
        name, typ = parts[0].strip(), parts[1].strip()
        if typ == "802-11-wireless":
            saved.append(name)
    return saved

def get_active_ssid():
    # Try connection show active, fallback to dev wifi
    rc, out = run_cmd_list(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,STATE", "connection", "show", "--active"])
    if rc == 0 and out:
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 4 and parts[1] == "802-11-wireless" and parts[3].lower().startswith("activated"):
                return parts[0]
    # fallback
    out2 = run_cmd("nmcli -t -f active,ssid dev wifi | grep '^yes' || true")
    if out2:
        try:
            return out2.strip().split(":")[1]
        except:
            return None
    return None

def connect_nmcli(ssid, password=None, timeout=25):
    cmd = ["nmcli", "device", "wifi", "connect", ssid]
    if password:
        cmd += ["password", password]
    rc, out = run_cmd_list(cmd, timeout=timeout)
    success = False
    if rc == 0:
        success = True
    return success, out or ""

def disconnect_network():
    # simple toggle to reset connections
    run_cmd("nmcli networking off && sleep 1 && nmcli networking on")

# ----- Keyring helpers -----
def save_password_keyring(ssid, password):
    if not KEYRING_AVAILABLE:
        return False
    try:
        keyring.set_password(KEYRING_SERVICE, ssid, password)
        return True
    except Exception as e:
        logging.warning("keyring set failed: %s", e)
        return False

def get_password_keyring(ssid):
    if not KEYRING_AVAILABLE:
        return None
    try:
        return keyring.get_password(KEYRING_SERVICE, ssid)
    except Exception:
        return None

def delete_password_keyring(ssid):
    if not KEYRING_AVAILABLE:
        return False
    try:
        keyring.delete_password(KEYRING_SERVICE, ssid)
        return True
    except Exception:
        return False

# ----- UI helpers -----
def signal_to_bars(sig):
    if sig >= 80: return "▂▄▆█"
    if sig >= 60: return "▂▄▆ "
    if sig >= 40: return "▂▄  "
    if sig >= 20: return "▂   "
    return "·    "

def print_networks(nets, active_ssid=None, saved_list=None, highlight=None):
    if not nets:
        print("No Wi-Fi networks found.")
        return
    saved_list = saved_list or []
    print()
    for i, n in enumerate(nets, start=1):
        tag = ""
        if n["ssid"] == active_ssid:
            tag = "(current)"
        elif n["ssid"] in saved_list:
            tag = "(saved)"
        if highlight and n["ssid"] == highlight:
            marker = ">>"
        else:
            marker = "  "
        lock = "🔒" if n["secure"] else "🔓"
        print(f"{marker} {i:2d}. {n['ssid'][:30]:30s} {lock} {signal_to_bars(n['signal'])} {n['signal']:3d}% {tag}")
    print()

def prompt_number_or_cmd(prompt, max_n):
    """Prompt until valid numeric selection or r/q."""
    while True:
        try:
            s = input(prompt).strip().lower()
        except KeyboardInterrupt:
            print("\nCancelled.")
            return None
        if s in ("q","quit","exit"):
            return None
        if s in ("r","rescan"):
            return "RESCAN"
        if s.isdigit():
            idx = int(s)
            if 1 <= idx <= max_n:
                return idx - 1
            else:
                print("Number out of range.")
                continue
        print("Enter a number, 'r' to rescan, or 'q' to cancel.")

# ----- Interaction flows (robust) -----
def interactive_connect_flow(preselected_index=None):
    """
    Full interactive scan + choose + connect flow.
    - If preselected_index is not None, try connecting that network index directly.
    - Handles password prompting and retry/cancel while keeping current network.
    """
    ensure_files()
    cfg = load_config()
    saved = list_saved_connections()
    while True:
        nets = scan_networks()
        active = get_active_ssid()
        print_networks(nets, active_ssid=active, saved_list=saved)
        if not nets:
            input("No networks found. Press Enter to return.")
            return
        suggested = nets[0]
        print(f"Suggested: {suggested['ssid']} ({suggested['signal']}%)")
        if preselected_index is not None:
            if preselected_index < 0 or preselected_index >= len(nets):
                preselected_index = None
            else:
                sel_ssid = nets[preselected_index]["ssid"]
                chosen = nets[preselected_index]
                # fall through to connect logic
        else:
            choice = prompt_number_or_cmd("Enter number to connect (r=rescan, q=cancel): ", len(nets))
            if choice is None:
                return
            if choice == "RESCAN":
                continue
            sel_ssid = nets[choice]["ssid"]
            chosen = nets[choice]

        # If user selected the currently connected SSID, show options
        if active and sel_ssid == active:
            print(f"You are already connected to '{active}'.")
            sub = input("Enter 'd' to disconnect, 'f' to forget, or Enter to return: ").strip().lower()
            if sub == "d":
                disconnect_network()
                print("Network disconnected.")
                continue
            elif sub == "f":
                forget_flow(sel_ssid)
                continue
            else:
                return

        # If chosen is secure, get password
        password = None
        saved_pw = get_password_keyring(sel_ssid) if KEYRING_AVAILABLE else None
        if chosen["secure"]:
            if saved_pw:
                use_saved = input("Saved password exists. Use saved password? (Y/n): ").strip().lower()
                if use_saved in ("", "y", "yes"):
                    password = saved_pw
            if password is None:
                # prompt user for password, but allow cancel
                pw = getpass.getpass(f"Password for '{sel_ssid}' (leave blank to cancel): ")
                if not pw:
                    print("Cancelled connect attempt.")
                    return
                password = pw

        # attempt connecting with retry behavior
        attempt = 0
        while attempt < cfg.get("max_retries", 3):
            attempt += 1
            print(f"Attempt {attempt} to connect to '{sel_ssid}' ...")
            ok, out = connect_nmcli(sel_ssid, password=password)
            logging.info("connect attempt %d to %s rc=%s", attempt, sel_ssid, ok)
            if ok:
                print(f"✅ Connected to {sel_ssid}")
                set_last_ssid(sel_ssid)
                # offer to save password if it's not already saved
                if KEYRING_AVAILABLE and chosen["secure"] and not saved_pw:
                    if cfg.get("auto_save_passwords", False):
                        savedok = save_password_keyring(sel_ssid, password)
                        if savedok:
                            print("Password saved to keyring.")
                    else:
                        saveq = input("Save password to system keyring? (y/N): ").strip().lower()
                        if saveq in ("y", "yes"):
                            savedok = save_password_keyring(sel_ssid, password)
                            if savedok: print("Password saved to keyring.")
                notify("Wi-Fi connected", sel_ssid)
                return
            else:
                print("❌ Connection failed.")
                logging.info("nmcli output: %s", out)
                if chosen["secure"]:
                    # allow user to retry entering password or cancel (stays on current network)
                    retry = input("Wrong password or failed. Try again? (y/N): ").strip().lower()
                    if retry in ("y","yes"):
                        password = getpass.getpass(f"Password for '{sel_ssid}': ")
                        continue
                    else:
                        print("Cancelled. Staying on current network.")
                        return
                else:
                    break
        print("Failed to connect after retries; returning to menu.")
        return

def forget_flow(ssid=None):
    """Forget connection profiles and keyring password for given SSID (or prompt)."""
    if not ssid:
        ssid = input("Enter exact SSID to forget (blank to cancel): ").strip()
        if not ssid:
            print("Cancelled.")
            return
    # remove nmcli connection(s) with matching name
    rc, out = run_cmd_list(["nmcli", "-t", "-f", "NAME,UUID", "connection", "show"])
    removed = False
    if rc == 0 and out:
        for line in out.splitlines():
            name = line.split(":",1)[0].strip()
            if name == ssid:
                run_cmd_list(["nmcli", "connection", "delete", name])
                removed = True
    if KEYRING_AVAILABLE:
        try:
            delete_password_keyring(ssid)
            removed = True
        except Exception:
            pass
    s = load_state()
    if s.get("last_ssid") == ssid:
        s.pop("last_ssid", None)
        save_state(s)
        removed = True
    print("Forgotten." if removed else "No saved data found for that SSID.")




def manage_saved_connections():
    saved = list_saved_connections()
    if not saved:
        print("No saved connections (NetworkManager has none).")
        return
    print("Saved connections:")
    for i, s in enumerate(saved, start=1):
        print(f"{i}. {s}")
    choice = input("Enter number to connect, 'f' to forget one, 'q' to return: ").strip().lower()
    if choice in ("q","quit","exit"):
        return
    if choice == "f":
        idx = input("Enter number to forget: ").strip()
        if idx.isdigit():
            idx = int(idx)-1
            if 0 <= idx < len(saved):
                forget_flow(saved[idx])
            else:
                print("Invalid number.")
        return
    if choice.isdigit():
        idx = int(choice)-1
        if 0 <= idx < len(saved):
            # connect to saved profile by name
            ssid = saved[idx]
            print(f"Connecting to saved profile '{ssid}' ...")
            saved_pw = get_password_keyring(ssid) if KEYRING_AVAILABLE else None
            ok, out = connect_nmcli(ssid, password=saved_pw)
            if ok:
                print("Connected.")
                set_last_ssid(ssid)
                notify("Wi-Fi connected", ssid)
            else:
                print("Failed to connect. You can try interactive connect for password prompt.")
        else:
            print("Invalid number.")

# ----- Interactive menu (main) -----
def interactive_menu():
    ensure_files()
    cfg = load_config()
    while True:
        active = get_active_ssid() or "None"
        last = get_last_ssid() or "None"
        print("\n=== Wi-Fi Manager Pro ===")
        print(f"Active: {active}    Last: {last}")
        print("1) Scan & connect (choose network)")
        print("2) Suggest strongest (ask to switch)")
        print("3) Saved networks (connect/forget)")
        print("4) Forget an SSID (profile & keyring)")
        print("5) Manage preferred / blacklist")
        print("6) Show live signal (press Ctrl+C to stop)")
        print("7) Run daemon (auto-manager)")
        print("q) Quit")
        choice = input("Choose an option: ").strip().lower()
        if choice in ("q", "quit", "exit"):
            print("Goodbye.")
            return
        if choice == "1":
            interactive_connect_flow()
        elif choice == "2":
            interactive_suggest_and_switch()
        elif choice == "3":
            manage_saved_connections()
        elif choice == "4":
            forget_flow()
        elif choice == "5":
            edit_pref_blacklist()
        elif choice == "6":
            live_signal_view()
        elif choice == "7":
            confirm = input("Start daemon now? (y/N): ").strip().lower()
            if confirm in ("y","yes"):
                daemon_mode()
            else:
                print("Daemon not started.")
        else:
            print("Invalid choice, try again.")

# ----- Interactive suggest (explicit s/c behavior) -----
def interactive_suggest_and_switch():
    ensure_files()
    cfg = load_config()
    saved = list_saved_connections()
    nets = scan_networks()
    if not nets:
        print("No networks found.")
        return
    active = get_active_ssid()
    strongest = nets[0]
    print_networks(nets, active_ssid=active, saved_list=saved, highlight=strongest["ssid"])
    print(f"Suggested strongest: {strongest['ssid']} ({strongest['signal']}%)")
    # If we're already on the strongest, inform and return
    if active and strongest["ssid"] == active:
        print("You are already on the strongest network.")
        return
    # Only show the s/c prompt if the strongest is stronger than current by configured threshold
    cfg = load_config()
    min_diff = cfg.get("min_signal_diff_to_switch", 10)
    current_signal = 0
    if active:
        # try to find current signal in scan
        for n in nets:
            if n["ssid"] == active:
                current_signal = n["signal"]
                break
    diff = strongest["signal"] - current_signal
    print(f"Current signal: {current_signal}%   Strongest: {strongest['signal']}%   Difference: {diff}%")
    if diff < min_diff:
        print(f"Note: strongest is less than {min_diff}% stronger than current; suggestion shown but you may skip.")
    cmd = input("Enter 's' to SWITCH to suggested, 'c' to cancel: ").strip().lower()
    if cmd != "s":
        print("Cancelled. Staying on current network.")
        return
    # If blacklisted, confirm
    cfg = load_config()
    if strongest["ssid"] in cfg.get("blacklist", []):
        confirm = input("This SSID is blacklisted. Force connect? (y/N): ").strip().lower()
        if confirm not in ("y","yes"):
            print("Cancelled.")
            return
    # proceed to connect with password handling + retry same as interactive flow
    if strongest["secure"]:
        saved_pw = get_password_keyring(strongest["ssid"]) if KEYRING_AVAILABLE else None
        password = None
        if saved_pw:
            use_saved = input("Saved password found. Use saved? (Y/n): ").strip().lower()
            if use_saved in ("", "y", "yes"):
                password = saved_pw
        if password is None:
            pw = getpass.getpass(f"Enter password for '{strongest['ssid']}' (blank to cancel): ")
            if not pw:
                print("Cancelled.")
                return
            password = pw
    else:
        password = None
    # try connect with retries
    attempts = 0
    max_retries = cfg.get("max_retries", 3)
    while attempts < max_retries:
        attempts += 1
        print(f"Attempt {attempts} to connect to {strongest['ssid']} ...")
        ok, out = connect_nmcli(strongest['ssid'], password=password)
        if ok:
            print("Connected.")
            set_last_ssid(strongest["ssid"])
            if KEYRING_AVAILABLE and strongest["secure"] and not get_password_keyring(strongest["ssid"]):
                if input("Save password to keyring? (y/N): ").strip().lower() in ("y","yes"):
                    save_password_keyring(strongest["ssid"], password)
            notify("Wi-Fi connected", strongest["ssid"])
            return
        else:
            print("Failed to connect.")
            logging.info("connect failed: %s", out)
            if strongest["secure"]:
                retry = input("Wrong password / failed. Try again? (y/N): ").strip().lower()
                if retry in ("y","yes"):
                    password = getpass.getpass(f"Enter password for '{strongest['ssid']}': ")
                    continue
                else:
                    print("Cancelled; staying on current network.")
                    return
            else:
                break
    print("Failed after retries; staying on current network.")

# ----- Live signal viewer -----
def live_signal_view():
    print("Live signal monitor. Press Ctrl+C to stop.")
    try:
        while True:
            nets = scan_networks()
            active = get_active_ssid()
            print_networks(nets, active_ssid=active, saved_list=list_saved_connections())
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nStopped live view.")

# ----- Preferred / blacklist editor -----
def edit_pref_blacklist():
    cfg = load_config()
    print("Preferred list:", cfg.get("preferred", []))
    print("Blacklist:", cfg.get("blacklist", []))
    mode = input("Enter 'p' to edit preferred, 'b' to edit blacklist, or Enter to cancel: ").strip().lower()
    if mode == "p":
        val = input("Enter preferred SSIDs as comma-separated list (empty to clear): ").strip()
        cfg["preferred"] = [s.strip() for s in val.split(",") if s.strip()] if val else []
        save_config(cfg)
        print("Preferred updated.")
    elif mode == "b":
        val = input("Enter blacklisted SSIDs as comma-separated list (empty to clear): ").strip()
        cfg["blacklist"] = [s.strip() for s in val.split(",") if s.strip()] if val else []
        save_config(cfg)
        print("Blacklist updated.")
    else:
        print("Cancelled.")

# ----- Daemon auto-manager -----
def daemon_mode():
    ensure_files()
    cfg = load_config()
    interval = cfg.get("check_interval", 20)
    logging.info("Daemon started with config: %s", cfg)
    notify("Wi-Fi Manager", "Daemon started")
    def on_sigint(sig, frame):
        print("\nDaemon stopping.")
        logging.info("Daemon stopped by user.")
        notify("Wi-Fi Manager", "Daemon stopped")
        sys.exit(0)
    signal.signal(signal.SIGINT, on_sigint)

    while True:
        cfg = load_config()  # reload for live editing
        nets = scan_networks()
        if not nets:
            logging.info("No networks found; sleeping.")
            time.sleep(interval)
            continue
        active = get_active_ssid()
        preferred = cfg.get("preferred", [])
        blacklist = set(cfg.get("blacklist", []))
        candidate = None
        reason = None

        # 1) last
        last = get_last_ssid()
        if last and last not in blacklist and any(n["ssid"] == last for n in nets):
            candidate = last
            reason = "last"

        # 2) preference list
        if not candidate and preferred:
            for p in preferred:
                if p not in blacklist and any(n["ssid"] == p for n in nets):
                    candidate = p
                    reason = "preferred"
                    break

        # 3) saved connections
        if not candidate:
            saved = list_saved_connections()
            for n in nets:
                if n["ssid"] in saved and n["ssid"] not in blacklist:
                    candidate = n["ssid"]
                    reason = "saved"
                    break

        # 4) strongest non-blacklisted
        if not candidate:
            for n in nets:
                if n["ssid"] not in blacklist:
                    candidate = n["ssid"]
                    reason = "strongest"
                    break

        if not candidate:
            logging.info("No candidate found (maybe all blacklisted). Sleeping.")
            time.sleep(interval)
            continue

        # If already active
        if active and candidate == active:
            logging.debug("Already connected to candidate %s", candidate)
            time.sleep(interval)
            continue

        # If candidate is 'strongest' but auto_switch disabled, notify and continue
        if reason == "strongest" and not cfg.get("auto_switch_in_daemon", False):
            notify("Wi-Fi Suggestion", f"Strongest: {candidate}")
            logging.info("Daemon suggests %s but auto-switch disabled.", candidate)
            time.sleep(interval)
            continue

        # Only auto-switch if the candidate is sufficiently stronger than current
        min_diff = cfg.get("min_signal_diff_to_switch", 10)
        current_signal = 0
        for n in nets:
            if n["ssid"] == active:
                current_signal = n["signal"]
                break
        candidate_signal = next((n["signal"] for n in nets if n["ssid"] == candidate), 0)
        if active and (candidate_signal - current_signal) < min_diff and reason == "strongest":
            logging.info("Candidate not sufficiently stronger (delta %s < min %s). Not switching.", candidate_signal-current_signal, min_diff)
            time.sleep(interval)
            continue

        # Attempt connection with retries & backoff
        attempt = 0
        success = False
        password = get_password_keyring(candidate) if KEYRING_AVAILABLE else None
        while attempt < cfg.get("max_retries", 3):
            attempt += 1
            logging.info("Daemon attempt %d to connect to %s (reason=%s)", attempt, candidate, reason)
            ok, out = connect_nmcli(candidate, password=password)
            if ok:
                logging.info("Daemon connected to %s", candidate)
                set_last_ssid(candidate)
                notify("Wi-Fi connected", candidate)
                success = True
                break
            else:
                logging.warning("Daemon connect failed: %s", out)
                time.sleep(cfg.get("backoff_base", 3) * attempt)
        if not success:
            logging.warning("Daemon could not connect to %s after retries.", candidate)
            notify("Wi-Fi manager", f"Failed to connect to {candidate}")
        time.sleep(interval)

# ----- Startup checks & entrypoint -----
def check_prereqs():
    if not which("nmcli"):
        print("Error: nmcli (NetworkManager CLI) not found in PATH. This tool requires NetworkManager/nmcli.")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Manager Pro (portable)")
    parser.add_argument("--daemon", action="store_true", help="Run non-interactive daemon auto-manager")
    args = parser.parse_args()
    check_prereqs()
    ensure_files()
    if args.daemon:
        daemon_mode()
    else:
        interactive_menu()

if __name__ == "__main__":
    main()
