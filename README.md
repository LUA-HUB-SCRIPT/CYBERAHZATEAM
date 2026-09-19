# CYBERAHZATEAM

Defensive/authorized cybersecurity CLI toolkit for Kali Linux and other Linux systems.

## Run

```bash
python3 cybertool.py
```

Optional command name:

```bash
sudo install -m 755 cybertool.py /usr/local/bin/CYBERAHZATEAM
CYBERAHZATEAM
```

## Notes

- Use scanning features only on systems and networks you own or have explicit permission to test.
- Nmap is required for the local-network device discovery features.
- Nearby Wi-Fi listing uses `iw` or `nmcli` when available.
- The toolkit does not include DDoS/flooding functionality.

## Nmap

On Kali Linux:

```bash
sudo apt update
sudo apt install nmap
```
