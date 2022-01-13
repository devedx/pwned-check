#!/bin/python

"""
Checks if a password has ever been contained in a data breach using the "haveibeenpwned" API.

:Data: 2022-01-13
:Version: 1.0
:Authors:
	- devedx@pm.me
"""

API_URL = "https://api.pwnedpasswords.com/range/"


from argparse import ArgumentParser
from getpass import getpass
from hashlib import sha1
import requests
import re


def check_pw(pw: str = None) -> int:
	if pw is None:
		pw = getpass("Enter password to be checked: ")

	hash = sha1(pw.encode()).hexdigest()

	res = requests.get(API_URL + hash[:5], headers={"Add-Padding": "true"})

	if res.status_code != 200:
		return -1

	return int(match.group(1)) if (match := re.search(f"{hash[5:]}:(\\d+)", res.text, re.IGNORECASE)) is not None else 0


if __name__ == "__main__":
	parser = ArgumentParser(
		prog="Pwned Check",
		usage="pwned_check.py [password]",
		description="Checks if a password has ever been contained in a data breach")
	parser.add_argument("password", type=str, nargs="?", help="password to check")

	args = parser.parse_args()

	matches = check_pw(args.password)

	if matches < 0:
		print("Request failed")
	elif matches == 0:
		print("Password not found in any breaches")
	else:
		print(f"Password found in {matches} breaches")
