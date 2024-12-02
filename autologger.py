import requests

USERNAME = ""
PASSWORD = ""



url = "http://172.16.16.16:8090/httpclient.html"
payload = {
    "mode": "191",
    "username": USERNAME,
    "password": PASSWORD,
    "a": "1551345153461"
}

response = requests.post(url, data=payload)

if response.ok:
    print("Request successful!")
    print("Response:", response.text)
else:
    print("Request failed!")
    print("Status Code:", response.status_code)



# for logout
# queryString = “mode=193&username=” + encodeURIComponent(document.frmHTTPClientLogin.username.value) + “&a=” + (new Date).getTime() + producttype;
