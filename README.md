# BLCred

(intro)

---

## Offline version

> An offline implement of BLCred system based on python

### Prerequisites and setup:

(All available at Pypi)

* [bplib](https://github.com/gdanezis/bplib)
* [petlib](https://github.com/gdanezis/petlib)

``` bash
export OPENSSL_CONF=/usr/local/ssl/openssl.cnf
sudo apt-get install libssl-dev
pip3 install petlib
pip3 install bplib
```


All the algorithm has been implemented as Lib*.py in folder /BLCred_offline/lib/

BLCred.py will call them and complete a typical usage process.

to run the project

``` bash
cd BLCred_offline
python3 BLCred.py
```

## Online version

> An online implement of BLCred system with HyperlederFabric based on go and javascript
