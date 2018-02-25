import socket
import time
import re
import pytz
import sys
from urllib.parse import urlsplit
from datetime import datetime
from dateutil import parser
from OpenSSL import SSL
PORT = 443


def chk_crl_file(sn):
    """Simple look up to see if the cert serial number is in the
    offending list file

    Args:
        sn: serial number of certificate.
    Returns: true if sn is in file

    """
    with open('crlfile.txt') as f:
        crlnums = [sns.strip() for sns in f]
        for crl in crlnums:
            if crl == sn:
                return True


def check_state_cert(cert, numdays):
    """Assuming allow stale certs option is passed, checks to see if
    cert is > numdays days old

    Args:
        cert: certificate from server
        numdays: how many days old you are willing to accept old certs
    Returns: nothing, but writes to stderr if the cert is too old
    """

    expdate = (cert.get_notAfter())
    expdate = expdate.decode()
    expdate = parser.parse(expdate)
    dt = datetime.now()
    utc = pytz.UTC
    dt = utc.localize(dt)
    if expdate < dt:
        diff = expdate - dt
        if int(abs(diff.days)) > int(numdays):
            sys.stderr.write("This certificate is greater than "+numdays+" days old")
            sys.exit(2)


def verify_callback(connection, x509, errnum, errdepth, ok):
    """Standard OpenSSL callback function
       Args: Figure out what to do with connection and x509

    """
    if not ok:
        print("Bad Certs" + str(errnum) + ' ' + str(errdepth))
    else:
        print("Certs are fine")
        return ok


def recv_timeout(the_socket, timeout=2):
    """Admittedly something I got online to help download content"""
    #make socket non blocking
    the_socket.setblocking(0)

    #total data partwise in an array
    total_data = []

    #beginning time
    begin = time.time()
    while 1:
        #if you got some data, then break after timeout
        if total_data and time.time()-begin > timeout:
            break

        #if you got no data at all, wait a little longer, twice the timeout
        elif time.time()-begin > timeout*2:
            break

        #recv something
        try:
            data = the_socket.recv(8192)
            if data:
                total_data.append(data)
                #change the beginning time for measurement
                begin=time.time()
            else:
                #sleep for sometime to indicate a gap
                time.sleep(0.1)
        except:
            pass

    #join all parts to make final string
    return b''.join(total_data)


def main():
    ciphs = ''
    useCrl = 0
    numDays = 0
    protver = ''
    address = ''
    #Parse any command line arguments
    for param in sys.argv:
        if param[:6] == '--tlsv' or param[:6] == '--sslv':
            protver = param
        if param == '--ciphers':
            ind = sys.argv.index(param)
            ciphs = sys.argv[ind+1]
        if param[:4] == 'http':
            address = param
        if param == '--crlfile':
            useCrl = 1
        if param == '--allow-stale-certs':
            ind = sys.argv.index(param)
            numDays = sys.argv[ind+1]

    if not re.match(r'https\:', address):
        sys.stderr.write('Non HTTPS address\n')
        exit(1)
    parsed = urlsplit(address)
    HOST = parsed.netloc

    #If no protocol specified, default to TLSv1.2
    context = SSL.Context(SSL.TLSv1_2_METHOD)
    if protver == '--tlsv1.0':
        context = SSL.Context(SSL.TLSv1_METHOD)
    if protver == '--tlsv1.1':
        context = SSL.Context(SSL.TLSv1_1_METHOD)
    if protver == '--tlsv1.2':
        context = SSL.Context(SSL.TLSv1_2_METHOD)
    if re.match('--ssl.*', protver):
        sys.stderr.write('Can only use TLS, not SSL\n')
        exit(1)

    context.load_verify_locations("cacerts.txt")
    context.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback)
    context.set_options(SSL.OP_NO_SSLv2)

    if ciphs:
        ciphlist = ciphs.encode()
        context.set_cipher_list(ciphlist)
    sock = socket.socket()
    sock = SSL.Connection(context, sock)
    sock.set_tlsext_host_name(HOST.encode())
    sock.connect((HOST, PORT))
    sock.do_handshake()

    sock.sendall('GET / HTTP/1.1\r\nHost: '+HOST+'\r\n\r\n')
    if int(numDays) > 0:
        cert = sock.get_peer_certificate()
        check_state_cert(cert, numDays)
    sn = str(sock.get_peer_certificate().get_serial_number())
    if useCrl == 1:
        if chk_crl_file(sn):
            sys.stderr.write("Certificate was in CRLFILE")
            sys.exit(2)

    print("\n")
    print(recv_timeout(sock))

if __name__ == '__main__':
    main()
