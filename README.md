Minimalistic python https proxy.

git clone https://github.com/kimasplund/minimal-proxy.git 
pip install -r requirements.txt 
python3 proxy.py <target_http_host>

Or to run in the background with no logging. 
nohup python3 proxy.py <target_http_host> > /dev/null 2>&1 &