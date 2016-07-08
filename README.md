# SonarWan

#### Recognize devices of a private network by sniffing NAT'd traffic

This project's objective is to process NAT'd traffic only and be able to detect and classify devices connected to the private network behind the NAT.

## How to run

**Python 3 is required.**

[OPTIONAL]
Create a virtual environment and activate it:
```bash
$ virtualenv -p /path-to-bin-python-3 env
$ source env/bin/activate
```

Install dependencies:

```bash
$ pip install -r requirements.txt
```

Run:
```bash
$ python sonarwan.py path/to/pcap-file
```

## 🚧 work in progress 🚧
