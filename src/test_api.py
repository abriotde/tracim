#!/usr/bin/env python3

import requests
import yaml

TRACIM_API_URL = "https://algoo.tracim.fr/api/"

def search():
	"""Test the search endpoint of the Tracim API.
		Exp: curl -X GET "https://demo.tracim.fr/api/search/content" -H  "accept: application/json"
	"""
	response = requests.get(
		TRACIM_API_URL + "search/content", 
		headers={"accept": "application/json"}
	)
	print(response.json())

def login():
	""" Test the login endpoint of the Tracim API.
		Exp: curl -X POST "https://demo.tracim.fr/api/auth/login" 
		-H  "accept: application/json" 
		-H  "Content-Type: application/json"
		-d "{  \"email\": \"hello@tracim.fr\",  \"password\": \"8QLa$<w\",  \"username\": \"My-Power_User99\"}"
	"""
	print("Testing login endpoint...")
	data = {}
	with open("tracim.yaml") as stream:
		try:
			config = yaml.safe_load(stream)
			data = config.get("user", {})
			print(config)
		except yaml.YAMLError as exc:
			print(exc)
			return False
	response = requests.post(
		TRACIM_API_URL + "auth/login", 
		headers={
			"accept": "application/json",
			"Content-Type": "application/json"
		},
		json=data
	)
	if response.status_code == 200:
		vals = response.json()
		# print("Login successful:", vals)
	elif response.status_code == 403:
		vals = response.json()
		code = vals.get("code", 0)
		if code != 200:
			print("Login failed : ",code," : ",vals)
			return False
	else:
		print("Login failed:", response.status_code, response.text)
		return False
	return True

if login():
	print("Login successful, testing API endpoints...")
	# test_api()
	search()

