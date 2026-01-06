#!/usr/bin/python

import requests
# import subprocess
import xml.dom.minidom

USERNAME = "24BDS051"
PASSWORD = "1!Quantum"

#  this is example data. fill it up with your ids :)
data = {
        "example": ["27BDS001", "Abc@123"],
        }


# profile = subprocess.run(
#         ["fzf", f"{keys}" for ]
#         )
url = "http://172.16.16.16:8090/httpclient.html"
user = "example"
payload = {
    "mode": "191",
    "username": data[user][0],
    "password": data[user][1],
    "a": "1551345153461"
}

response = requests.post(url, data=payload)

def pretty_print(xml_string):
    # Parse the string
    dom = xml.dom.minidom.parseString(xml_string)
    # Pretty print with indentation
    pretty_xml = dom.toprettyxml(indent="  ")
    print(pretty_xml)

if response.ok:
    print("Request successful!")
    # print("Response:", response.text)
    pretty_print(response.text.replace("username", user))
else:
    print("Request failed!")
    print("Status Code:", response.status_code)



# for logout
# queryString = “mode=193&username=” + encodeURIComponent(document.frmHTTPClientLogin.username.value) + “&a=” + (new Date).getTime() + producttype;
