

````markdown
# 🛜 Python Wi-Fi Manager for Linux

A user-friendly, terminal-based Wi-Fi manager for Linux that allows you to:
- Scan available Wi-Fi networks
- Automatically connect to the strongest saved network
- Interactively connect to new networks
- Save and reconnect to networks automatically
- Switch networks manually
- Run in daemon mode to auto-switch to the strongest available network
- Blacklist networks you don’t want to connect to
- View signal strength and encryption status

---

## ✨ Features

- Automatic strongest-network connection (Daemon mode)
- Interactive network selection (choose via number)
- Connection retry on failure
- Password verification (shows if password is incorrect)
- Blacklist unwanted networks (avoid auto-connect)
- Remember last successful network even if not in NetworkManager
- No root required for basic operations
- Works anywhere — no `/etc` or `/bin` modifications
- Advanced user control for network management

---

## 📦 Requirements

- Python 3.6+
- `nmcli` (comes pre-installed on most Linux distros with NetworkManager)
- A Linux system with NetworkManager enabled

Check if `nmcli` is available:
```bash
nmcli -v
````

If not installed:

```bash
sudo apt install network-manager  # Ubuntu/Debian/Linux Mint
sudo dnf install NetworkManager   # Fedora
sudo pacman -S networkmanager     # Arch
```

---

## 🟢 Quick Start for Linux Mint

1. Open the terminal
   Press <kbd>Ctrl</kbd> + <kbd>Alt</kbd> + <kbd>T</kbd>

2. Update your system

   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

3. Install dependencies (Python & NetworkManager tools)

   ```bash
   sudo apt install python3 python3-pip network-manager -y
   ```

4. Download the script

   ```bash
   git clone https://github.com/yourusername/linux-wifi-manager.git
   cd linux-wifi-manager
   ```

5. Make the script executable

   ```bash
   chmod +x wifi_manager.py
   ```

6. Run the script

   ```bash
   python3 wifi_manager.py
   ```

---

## 🚀 Usage

### Normal Mode

Run the script and it will:

 Show available networks
 Suggest the strongest network
 Ask if you want to connect

```bash
python3 wifi_manager.py
```

---

### Daemon Mode (Auto-switch to strongest network)

```bash
python3 wifi_manager.py --daemon
```

This will run in the background and automatically switch to the strongest saved network.

---

### Interactive Commands

While running the script, you can:

 `s` — Switch to strongest suggested network
 `c` — Cancel and stay connected
 `r` — Rescan for networks
 `q` — Quit program

---

## ⚡ Example Output

```
Available networks:
 1. MyHomeWiFi                 🔒 ▂▄▆█ 98%
 2. OfficeNet                   🔒 ▂▄▆_ 75%
 3. CoffeeShop                  ▂▄__ 50%

Suggested: MyHomeWiFi (98%)
Enter number to connect (r=rescan, q=cancel): s

Connecting to MyHomeWiFi...
✅ Connected successfully!
```

---

## ❗ Troubleshooting

 Authentication prompt keeps appearing:
  This can happen if your system's keyring/password manager requests credentials.
  Make sure the password is correct and stored in NetworkManager.

 Incorrect password error:
  The script will show `"Incorrect password"` and allow you to retry.

 No networks found:
  Ensure Wi-Fi is enabled:

  ```bash
  nmcli radio wifi on
  ```



## 📝 TODO / Planned Features

 Export & import saved Wi-Fi credentials
 Better daemon performance with less CPU usage
 GUI version for desktop users

---

## 📜 License

MIT License — You’re free to use, modify, and share.

---

## ❤️ Contributing

Pull requests are welcome!
If you have suggestions for improvement, feel free to open an issue or PR.
