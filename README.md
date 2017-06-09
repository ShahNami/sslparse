# SSLPARSE

### DEPENDENCIES:

SSLPARSE.PY has been tested with, and works with
the following tools.

+ PYTHON
	Version: 2.7.13

+ SSLSCAN
	Version: 1.11.10-static
	OpenSSL 1.0.2-chacha (1.0.2g-dev)

+ XMLTODICT
	Version: 0.11.0


### FIRST:

pip3 install xmltodict

### USAGE:

python sslparse.py -f list.txt

### OUTPUT:

Folder with current week number e.g. Week23/
Folder containts the following:
Week23/
	output.xml
	report.html
	
	
### IMPORTANT:

Every entry in your hosts file should end with [ENTER] a.k.a. (\r\n), including the last one.


### BUGS:

File with hosts must contain more than 1 resolvable hostname.

