#!/usr/bin/python3

import argparse
import time
import sys

from hashlib import sha512
import hmac
import base64

import urllib.request
from urllib.parse import urljoin, urlencode
import http.client
import json

#http.client.HTTPConnection.debuglevel = 1

class BitBoxRest:
	def __init__(self, key = None, secret = None):
		self.key = key
		self.secret = secret
		self.nonce = int(time.time())
		self.toplevel_url = "https://bitbox.mx/rest/"

	def get_nonce(self):
		self.nonce = self.nonce + 1
		return self.nonce

	def get_unsigned_request(self, url):
		request = urllib.request.Request(url)
		#REST api will return forbidden with python3's default User-Agent
		request.add_header('User-Agent', 'Mozilla/5.0')
		return request

	def get_signed_request(self, url):
		if self.key is None or self.secret is None:
			raise Exception("get_signed_request called with no key or no secret")
		nonce = self.get_nonce()
		#not putting param into url.  if passing as data to request python makes it a POST which the REST api doesn't like
		url = urljoin(url, "?nonce=%d" % nonce)
		request = self.get_unsigned_request(url)
		urldata = urlencode({"nonce" : nonce})
		hmac_obj = hmac.new(base64.b64decode(secret), bytes(urldata.encode("utf-8")), sha512)
		request.add_header('Rest-Key', key)
		request.add_header('Rest-Sign', base64.b64encode(hmac_obj.digest()))
		return request

	def do_request(self, request):
		try:
			fobj = urllib.request.urlopen(request)
		except urllib.error.HTTPError as e:
			print("HTTP Error doing request")
			print("http error code: " + str(e.code))
			print("http reason: " + str(e.reason))
			error_dict = json.loads(e.read().decode())
			print("rest api error code: %d" % error_dict['error']['code'])
			print("rest api error message: %s" % error_dict['error']['message'])
			sys.exit(1)
		raw_data = fobj.read()
		decode_data = raw_data.decode()
		return json.loads(decode_data)
	
	def do_unsigned_request(self, url):
		url = urljoin(self.toplevel_url, url)
		request = self.get_unsigned_request(url)
		return self.do_request(request)
	
	def orderbook(self, currency_pair = "BTCUSD"):
		url = urljoin(self.toplevel_url, "orderbook/%s" % currency_pair)
		request = self.get_unsigned_request(url)
		return self.do_request(request)

	def compat_orderbook(self, currency_pair = "BTCUSD"):
		url = urljoin(self.toplevel_url, "compat/orderbook/%s" % currency_pair)
		request = self.get_unsigned_request(url)
		return self.do_request(request)

	def compat_trades(self, currency_pair = "BTCUSD"):
		url = urljoin(self.toplevel_url, "compat/trades/%s" % currency_pair)
		request = self.get_unsigned_request(url)
		return self.do_request(request)

	def verify_credentials(self):
		url = urljoin(self.toplevel_url, "verify-credentials")
		request = self.get_signed_request(url)
		return self.do_request(request)

	def bitcoin_address(self):
		url = urljoin(self.toplevel_url, "bitcoin-address")
		request = self.get_signed_request(url)
		d = self.do_request(request)
		return d['address']

	def accounts(self):
		url = urljoin(self.toplevel_url, "accounts")
		request = self.get_signed_request(url)
		return self.do_request(request)

	def user_open(self):
		url = urljoin(self.toplevel_url, "orders/open")
		request = self.get_signed_request(url)
		return self.do_request(request)

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("--orderbook", action = "store_true")
	parser.add_argument("--compat_orderbook", action = "store_true")
	parser.add_argument("--address", action = "store_true")
	parser.add_argument("--accounts", action = "store_true")
	parser.add_argument("--verify", action = "store_true")
	parser.add_argument("--user_open", action = "store_true")
	if len(sys.argv) < 2:
		parser.print_usage()
		sys.exit(1)
	args = parser.parse_args()

	secret = "secret"
	key = "key"
	
	bbr = BitBoxRest(key, secret)

	if args.verify:
		d = bbr.verify_credentials()
		print("Verify successful")

	if args.orderbook:
		d = bbr.orderbook()
		for k1,v1 in d.items():
			for k2 in v1.keys():
				print(k2)
				orders = v1[k2]
				for order in orders:
					for j in order.keys():
						print("\t%s\t\t%s" % (j.ljust(20), order[j]))
					print("\n")

	if args.address:
		d = bbr.bitcoin_address()
		print(d)

	if args.accounts:
		d = bbr.accounts()
		print(d)

	if args.compat_orderbook:
		d = bbr.compat_orderbook()
		print (d)

	if args.user_open:
		d = bbr.user_open()
		print (d)
