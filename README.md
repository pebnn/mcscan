# Minecraft Server Scanner
A fast Minecraft java server scanner written in Python, with Masscan at it's core. Includes loads of useful features to filter and search through thousands of servers in an easy to use web interface.

![](https://i.imgur.com/FjuFpU9.png)

> [!IMPORTANT]
> **Disclaimer of Warranty and Liability**  
> This software is provided "as is" for educational and research use. **No warranty** of any kind, express or implied, including but not limited to merchantability, fitness for a particular purpose, and non-infringement.  
>
> By using this software, **you accept full responsibility** for all actions and outcomes. The authors and contributors **are not liable** for any direct, indirect, incidental, special, exemplary, or consequential damages, including loss of data, service disruption, account bans, or legal claims, arising from use or misuse of this project.  
>
> **Not legal advice.** Ensure your usage complies with all applicable laws, contracts, ISP/AUP terms, and third-party policies. Use only against assets you own or have **explicit written permission** to test.  
>
> If you do not agree, **do not use** this software.

# Installation (Linux)
`mcscan.py` handles server scanning and `app.py` handles the webui (viewing the scanned servers).
1. **System packages**
   ```bash
   sudo apt update
   sudo apt install -y git python3-venv python3-pip masscan
   ```

2. **Clone**
   ```bash
   git clone https://github.com/pebnn/mcscan.git
   cd mcscan
   ```

3. **Python venv + dependencies**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Optional: GeoLite2 Country database**
   ```bash
   # requires a free MaxMind license key
   export MM_LICENSE_KEY=YOUR_KEY
   curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=$MM_LICENSE_KEY&suffix=tar.gz" -o GeoLite2-Country.tar.gz
   tar -xzf GeoLite2-Country.tar.gz
   find . -name 'GeoLite2-Country.mmdb' -exec cp {} ./GeoLite2-Country.mmdb \;
   ```

5. **Run the scanner**

   Masscan needs raw-socket privileges. Pick one:

   **A) Already root**  
   Activate the venv and run normally.
   ```bash
   cd /path/to/mcscan
   source .venv/bin/activate
   python3 mcscan.py --rate 50000 --ports 25565
   ```

   **B) Non-root (grant caps once)**
   ```bash
   sudo setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)"
   python3 mcscan.py --rate 50000 --ports 25565
   # verify: getcap "$(command -v masscan)"
   ```

   **C) One-shot with sudo**
   ```bash
   sudo .venv/bin/python mcscan.py --rate 50000 --ports 25565
   ```

  - `--rate` is packets per second sent by Masscan. Masscan’s very slow default value is **100 pps** if you omit it. Pick a rate your link and ISP can safely handle. Start low (e.g., 10k-40k pps) and increase cautiously. On Linux bare metal ~1.6M pps is possible;   Windows/VMs ~300k pps.
  - `--ports` accepts a single port, a range, or a comma-list of both, e.g. `25565`, `25560-25570`, or `25565,25566-25570,1-65535`. If you omit `--ports`, the script uses port `25565` by default.

  **All options**
  - `--rate, -r <int>`  
    Masscan transmit rate in packets/second. If not given, Masscan uses its default of **100 pps**.
  - `--ports <str>`  
    Comma-separated ports and/or ranges, e.g. `25565,25566-25570,1-65535`. If omitted, uses the script’s built-in common ports.
  - `--random[=<seed>]`  
    Use Masscan’s randomization seed. With no value, the script auto-picks a seed; with a value, it passes that integer to Masscan’s `--seed`. Different seeds change probe order.{index=7}
  - `--resume <paused.conf>`  
    Resume a previously paused Masscan run (created when Masscan exits with a saved state).
  - `--threads <int>`  
    Worker threads for Minecraft status verification. Defaults to the script’s internal setting; you usually don’t need to set this.

    >### Troubleshooting for Debian masscan issues
    >If masscan fails to load try installing the following packages:
    >```bash
    >sudo apt update && sudo apt install -y libpcap0.8 libpcap-dev
    >```

6. **Run the web UI**
   ```bash
   source .venv/bin/activate
   python3 app.py
   # open http://localhost:5000
   ```

   
# Installation (Windows)
`mcscan.py` handles server scanning and `app.py` handles the webui (viewing the scanned servers).
> Requires Python 3.10+, Git, and admin rights for packet capture.

1. **Clone**
   ```powershell
   git clone https://github.com/pebnn/mcscan.git
   cd mcscan
   ```

2. **Python venv + deps**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Create project folders**
   ```powershell
   New-Item -ItemType Directory -Force .\instance, .\static\server_icons | Out-Null
   ```

4. **Install Npcap (packet capture driver)**
   - Download and install Npcap. During setup, select **“Install Npcap in WinPcap API-compatible Mode.”**
   - Reboot if prompted.

5. **Build Masscan**
   - Option A (Visual Studio):
     ```powershell
     git clone https://github.com/robertdavidgraham/masscan.git
     cd masscan\vs10
     # Open masscan.sln in Visual Studio and Build → Build Solution (Release x64)
     # The binary will be in ..\bin\masscan.exe
     ```
   - Option B (MinGW via MSYS2, from MSYS2 MinGW shell):
     ```bash
     pacman -S --needed base-devel mingw-w64-x86_64-gcc
     git clone https://github.com/robertdavidgraham/masscan.git
     cd masscan
     make -j
     # binary: .\bin\masscan.exe
     ```

6. **Add Masscan to PATH**
   ```powershell
   # assuming you copied masscan.exe to C:\Tools\masscan
   setx PATH "$env:PATH;C:\Tools\masscan"
   # open a NEW terminal for PATH changes to apply
   ```

7. **Optional: GeoLite2 Country database**
   ```powershell
   # requires a free MaxMind license key
   $env:MM_LICENSE_KEY="YOUR_KEY"
   curl.exe -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=$env:MM_LICENSE_KEY&suffix=tar.gz" -o GeoLite2-Country.tar.gz
   tar -xzf GeoLite2-Country.tar.gz
   Get-ChildItem -Recurse -Filter GeoLite2-Country.mmdb | Select-Object -First 1 | ForEach-Object { Copy-Item $_.FullName .\GeoLite2-Country.mmdb -Force }
   ```

8. **Run the scanner**  *(PowerShell as Administrator recommended)*
   ```powershell
   cd <path-to>\mcscan
   .\.venv\Scripts\Activate.ps1
   python mcscan.py --rate 50000 --ports 25565
   ```
   - `--rate` is packets per second sent by Masscan. Masscan’s default is **100 pps** if you omit it. Pick a rate your link and ISP can safely handle. Start low (e.g., 10k-40k pps) and increase cautiously. On Linux bare metal ~1.6M pps is possible;   Windows/VMs ~300k pps.
  - `--ports` accepts a single port, a range, or a comma-list of both, e.g. `25565`, `25560-25570`, or `25565,25566-25570,1-65535`. If you omit `--ports`, the script uses its built-in common Minecraft ports list.

  **All options**
  - `--rate, -r <int>`  
    Masscan transmit rate in packets/second. If not given, Masscan uses its default of **100 pps**.
  - `--ports <str>`  
    Comma-separated ports and/or ranges, e.g. `25565,25566-25570,1-65535`. If omitted, uses the script’s built-in common ports.
  - `--random[=<seed>]`  
    Use Masscan’s randomization seed. With no value, the script auto-picks a seed; with a value, it passes that integer to Masscan’s `--seed`. Different seeds change probe order.
  - `--resume <paused.conf>`  
    Resume a previously paused Masscan run (created when Masscan exits with a saved state).
  - `--threads <int>`  
    Worker threads for Minecraft status verification. Defaults to the script’s internal setting; you usually don’t need to set this.

9. **Run the web UI**
   ```powershell
   cd <path-to>\mcscan
   .\.venv\Scripts\Activate.ps1
   python app.py
   # then open http://localhost:5000
   ```

# Web UI guide (`app.py`) and whitelist checks

## Start the app
```bash
python app.py
# defaults to http://localhost:5000
```

## UI overview
- **Table columns:** Icon, IP:Port, Whitelist, MOTD, Version, Players, Country, Date Added, Actions, Reachable.
- **Search and sort:** Use the search box. Click headers to sort. Change page size with the selector.
- **Actions per row:**
  - **Refresh:** Re-ping and update the row.
  - **Players:** View last seen player sample if available.
  - **Whitelist:** Run a join test with your token (see below).
  - **Delete:** Remove the entry.
- **Batch actions:** Refresh or whitelist-check the current page. Uses pacing and retries to avoid rate limits.
- **Favorites:** Star items and filter to favorites.
- **Settings:** Paste your Minecraft Java token, adjust per-page batch sizes, and other UI options.

## Whitelist checks: how it works
- The checker performs a **real login** handshake and **session join** with your Java access token.
- Result categories include typical outcomes like:
  - `allowed` — join accepted
  - `not_whitelisted` — server whitelists players
  - `banned` or `server_full` — server response explains refusal
  - `version_mismatch` — protocol not compatible
  - `timeout` or `unknown_disconnect`
  - `join_forbidden` (HTTP 403 from session join)
  - `rate_limited` (HTTP 429 from auth services)
- Tips:
  - Tokens expire roughly every 24 hours. If checks start failing with 403s, refresh your token.
  - Use page-level checks to throttle. Avoid parallelizing many checks from the same IP.

## Configure auth for whitelist checks
Open **Settings → Minecraft Token** and paste a **3-part Java access token** (format `aaa.bbb.ccc`). Save. The app verifies your ownership and caches your profile for join attempts.

---

# How to Get Your Minecraft Java “ygg” Token

This token is the 3-part JWT used by Mojang’s Java session APIs. It usually looks like:

`eyJ...`.`eyJ...`.`gJV...`

Notes:
- Valid for about 24 hours. If it expires, refresh in your launcher and grab it again.
- Do not use 5-part JWE/Xbox tokens (they look like `aaa.bbb.ccc.ddd.eee`). Those will not work for Java session join.

---

## Official Minecraft Launcher (Microsoft account)

The launcher stores tokens in `launcher_accounts.json` (location depends on OS). The Java token you want is the 3-part `accessToken` for the active account.

Typical paths by OS:
- Windows: `%AppData%/.minecraft/launcher_accounts.json`
- Linux: `~/.minecraft/launcher_accounts.json`
- macOS: `~/Library/Application Support/minecraft/launcher_accounts.json`

Steps:
1) Open the official launcher and make sure you’re logged in. Launch Java Edition once to refresh tokens, then close the game and the launcher.
2) Open `launcher_accounts.json` in a text editor.
3) Find your active profile/account block.
4) Copy the `accessToken` value that looks like a 3-part JWT (`eyJ...`.`eyJ...`.`...`).

If you only see 5-part tokens (Xbox/JWE), relaunch Java Edition again—after a successful refresh, the 3-part Java access token should be present.

---

## Prism Launcher (and MultiMC/PolyMC forks)

Your account info is stored in an `accounts.json` file. The correct field is `ygg.token`.

Typical paths by OS:
- Linux (Flatpak): `~/.var/app/org.prismlauncher.PrismLauncher/data/PrismLauncher/accounts.json`
- Linux (AppImage/regular): `~/.local/share/PrismLauncher/accounts.json`
- Windows: `%AppData%/PrismLauncher/accounts.json` (e.g., `C:\Users\<you>\AppData\Roaming\PrismLauncher\accounts.json`)
- macOS: `~/Library/Application Support/PrismLauncher/accounts.json`

Steps:
1) Close Prism if it’s running (to flush latest token).
2) Open `accounts.json` in a text editor.
3) Find the entry with `"active": true`.
4) Copy the value of `ygg.token` (it should be a 3-part JWT starting with `eyJ...`).

---

