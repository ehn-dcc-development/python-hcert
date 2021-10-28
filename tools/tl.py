"""Export trusted list from SE Digital Covid Certificate Trust Point as JWKS"""

import json

import jwt as pyjwt
import requests

response = requests.get("https://dgcg.covidbevis.se/tp/trust-list")
response.raise_for_status()


tl = pyjwt.decode(response.text, options={"verify_signature": False})

with open("tl.json", "wt") as output_file:
    json.dump(tl, output_file, indent=True)

dsc_trust_list = tl["dsc_trust_list"]

keys = []
for country, data in dsc_trust_list.items():
    for jwk_dict in data.get("keys", []):
        keys.append({"issuer": country, **jwk_dict})

with open("tl-jwks.json", "wt") as output_file:
    json.dump({"keys": keys}, output_file, indent=True)
