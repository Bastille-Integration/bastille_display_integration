# Requirements

python3.8 -m pip install -r requirements.txt


# Config

Edit config.yaml


# Make daemon
   
mv algo_api.service to /etc/systemd/system/

Run the following:

sudo systemctl daemon-reload

sudo systemctl start algo_api
