import xmltodict #pip3 install xmltodict
import optparse
import datetime
import os
    
def toBoolean(nonBoolValue, trueString, falseString):
    if(nonBoolValue == "1" or nonBoolValue == "0"):
        return (nonBoolValue == "1") and trueString or falseString
    elif(nonBoolValue == "True" or nonBoolValue == "False"):
        return (nonBoolValue == "True") and trueString or falseString
    elif(nonBoolValue == "preferred" or nonBoolValue == "accepted"):
        return (nonBoolValue == "preferred") and trueString or falseString
    else:
        return (nonBoolValue == "TLSv1.0") and trueString or falseString
        
def checkRC4(cipher):
    
    return (cipher=="RC4-SHA") and "<span class='text-danger'>" + cipher + "</span>" or "<span class='text-muted'>" + cipher + "</span>"
    
def parse_xml(directory, xmloutput):
    with open(directory+xmloutput) as fd:
        doc = xmltodict.parse(fd.read())
        
        table="<thead><tr><th class='col-xs-1'>Website</th><th class='col-xs-1'>TLS renegotiation</th><th class='col-xs-1'>TLS compression</th><th class='col-xs-2'>Heartbleed</th><th class='col-xs-3'>Supported Server Ciphers</th><th class='col-xs-4'>SSL certificate</th></tr></thead>"
        
        for ssltest in doc['document']['ssltest']:
            hostport = ssltest['@host'] + " on port " + ssltest['@port']
            negotiation = toBoolean(ssltest["renegotiation"]["@supported"], "<span class='text-success'>Supported</span>", "<span class='text-danger'>Not supported</span>") + "<br/>" + toBoolean(ssltest["renegotiation"]["@secure"], "<span class='text-success'>Secured</span>", "<span class='text-danger'>Not secured</span>")
            compression = toBoolean(ssltest["compression"]["@supported"], "<span class='text-success'>Supported</span>", "<span class='text-success'>Disabled</span>")
            heartbleeds = ""
            for heartbleed in ssltest['heartbleed']:
                heartbleeds += heartbleed['@sslversion'] + " is " + toBoolean(heartbleed["@vulnerable"], "<span class='text-danger'>vulnerable</span>", "<span class='text-success'>not vulnerable</span>") + "</br>"
            ciphers = ""
            for cipher in ssltest['cipher']:
                ciphers += toBoolean(cipher['@status'], "<span class='text-success'>"+cipher['@status']+"</span>", "<span class='text-primary'>"+cipher['@status']+"</span>") + "\t\t" + toBoolean(cipher['@sslversion'], "<span class='text-danger'>"+cipher['@sslversion']+"</span>", "<span class=''>"+cipher['@sslversion']+"</span>") + "\t\t<span class='text-info'>" + cipher['@bits'] + "</span>\t\t" + checkRC4(cipher['@cipher']) + "</br>"
                
            certificate = "Signature algorithm: / <br/>";
            try:
                certificate = "Signature algorithm: <span class='text-primary'>" + ssltest['certificate']['signature-algorithm'] + "</span><br/>" + ssltest['certificate']['pk']['@type'] + " Key Strength: <span class='text-primary'>" + ssltest['certificate']['pk']['@bits'] + "</span><br/>" + " Subject: <span class='text-primary'>" + ssltest['certificate']['subject'] + "</span><br/>"  + " Alternative names: <span class='text-primary'>" + ssltest['certificate']['altnames']+ "</span><br/>"  + " Issuer: <span class='text-primary'>" + ssltest['certificate']['issuer'] + "</span><br/>"  + " Self-Signed: " + toBoolean(ssltest['certificate']['self-signed'], "<span class='text-danger'>True</span>", "<span class='text-success'>False</span>")+ "<br/>"  + " Not Valid Before: <span class='text-primary'>" + ssltest['certificate']['not-valid-before'] + "</span><br/>"  + " Not Valid After: <span class='text-primary'>" + ssltest['certificate']['not-valid-after'] + "</span><br/>"  + " Expired: " + toBoolean(ssltest['certificate']['expired'], "<span class='text-danger'>True</span>", "<span class='text-success'>False</span>") + "<br/>"
            except:
                print("Unable to parse Certificate information for: " + hostport)

            table += "<tbody><tr><th scope='row'>"+hostport+"</th><td>"+negotiation+"</td><td>"+compression+"</td><td>"+heartbleeds+"</td><td>"+ciphers+"</td><td>"+certificate+"</td></tr></tbody>"
         
        html = """
            <!DOCTYPE html>
            <head>
                <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
                
                <!-- Latest compiled and minified CSS -->
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">

                <!-- Optional theme -->
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">

                <!-- Latest compiled and minified JavaScript -->
                <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
            </head>
            <body>
            <table class="table table-striped table-responsive">
            {0}
            </table>
            </body>
            </html>
        """
        f = open(directory+'report.html', 'w')
        f.write(html.format(table))
        f.close()

def start_scan(targets):
	week_number = str(datetime.date.today().isocalendar()[1])
	directory = "Week" + week_number + os.sep
	if not os.path.exists(directory):
		os.makedirs(directory)
	os.system('sslscan --targets=' + targets + ' --xml=' + directory + 'output.xml')
	parse_xml(directory,'output.xml')

def main():
	parser = optparse.OptionParser('Specify some arguments. Use -h for more information.')
	parser.add_option('-f', dest='file', type='string', help='specify file with hostname')
	(options, args) = parser.parse_args()
	targets = options.file
	if(targets==None):
		print(parser.usage)
		exit(0)
	
	start_scan(targets)

if __name__ == '__main__':
	main()
