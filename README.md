# Clone Git Repository

git clone https://github.com/dalybastille/algo_integration.git

# Requirements

Need to be running Python 3.8.

Pip needs to be 3.8: https://stackoverflow.com/questions/61717006/pip-for-python-3-8.

Run:

pip install -r requirements.txt

# Config

Edit config.yaml


# Make daemon

Make changes to algo_api.service file. Following directory paths need to be where you install:

WorkingDirectory=/home/bn/algo_integration

ExecStart=/usr/bin/python3.8 /home/bn/algo_integration/algo.py

Copy service file:
   
cp algo_api.service /etc/systemd/system/

Run the following:

sudo systemctl daemon-reload

sudo systemctl start algo_api
