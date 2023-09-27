# Requirements

Need to be running Python 3.8 (https://stackoverflow.com/questions/61717006/pip-for-python-3-8).

pip install -r requirements.txt

# Clone Git Repository

git clone https://github.com/dalybastille/algo_integration.git


# Config

Edit config.yaml


# Make daemon
   
mv algo_api.service to /etc/systemd/system/

Run the following:

sudo systemctl daemon-reload

sudo systemctl start algo_api
