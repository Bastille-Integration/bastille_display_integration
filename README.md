# Clone Git Repository

Below instructions assumes you are in the /home/bn directory.

git clone https://github.com/dalybastille/bastille_display_integration.git

# Requirements

Latest running on Ubuntu 24.04.

Running Python 3.12.

Run the following:
- sudo apt install python3-fastapi
- sudo apt install python3-httpx
- python3 -m pip install ndjson --break-system-packages
- python3 -m pip install PyYAML --break-system-packages

# Config

Edit config.yaml


# Make daemon

sudo cp bastille_display_integration.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start bastille_display_integration.service 
