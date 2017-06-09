# SSLParse

### Description
SSLParse generates an HTML report using sslscan's XML output.

### Dependencies:

SSLPARSE.PY has been tested with, and works with
the following tools.

```
apt-get install sslscan
pip3 install xmltodict
```

+ PYTHON

    Version: 2.7.13

+ SSLSCAN

    Version: 1.11.10-static
	
    OpenSSL 1.0.2-chacha (1.0.2g-dev)

+ XMLTODICT

    Version: 0.11.0


### Usage:
```
python sslparse.py -f list.txt
```
### Output:

Folder with current week number e.g. Week23/

Folder containts the following:

+ Week23/

    output.xml
	
    report.html
	
	
### Important:

Every entry in your hosts file should end with [ENTER] a.k.a. (\r\n), including the last one.


### Known Bugs:

File with hosts must contain more than 1 resolvable hostname.

