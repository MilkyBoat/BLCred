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

### to run the project

``` bash
cd BLCred_offline
python3 BLCred.py
```

## Online version

> An online implement of BLCred system with HyperlederFabric based on go and nodejs

### Prerequisites and setup:

* go 1.13.4
* nodejs 8.10.0 & npm 3.5.2
* docker 20.10.0
* Fabric 2.2.0

You can find a basic tutorials on environment configuration here: [Getting Started](https://hyperledger-fabric.readthedocs.io/en/latest/getting_started.html)

### to run the project

```bash
cd BLCred_online/app
./startFabric.sh
./testBLCred.sh
./stopFabric.sh
```

startFabric.sh will start a Fabric network and install the chaincode, then testBLCred.sh will execute the NodeJS script one by one, enrollAdmin, registerUser, and executes the chaincode function one by one.

If all goes well, it will print the time spent by each chaincode function and finally print "credverify successful"
