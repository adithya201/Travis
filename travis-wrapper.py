import sys
import os
import requests


appName = sys.argv[1]
appID = "84ec261c79529994ba4858020d1ecdc5"
token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMiwiZW1haWwiOiJuZXdAYWNjZW50dXJlLmNvbSIsInVzZXJuYW1lIjoibmV3IiwiZXhwIjoxNTQ4ODUwOTM5LCJvcmlnX2lhdCI6MTU0ODc2NDUzOX0.jfgHdPI50EiK5xiwr0a6fqhl034v6LzVLtWO0kv4590"
token = str(token).strip()
appID = str(appID).strip()

url = 'https://bc587ece.ngrok.io/api/scan_binary/'

path = appName  #travis path 

files = {'binaryFile': open(path,'rb')}

values = {
		  'Uid' : appID,
           }

authtoken = "JWT "+str(token)

headers = { "Authorization" : authtoken }

response = requests.post(url, data=values,files=files,headers=headers)

print(response.json())
data = response.json()

if data['status'] == 'Failed':
	print(" Build Failed - "+str(data['error'])+" !")
	exit(1)

x = str(data['message']).split("=")
x = x[1]

checkurl = 'https://bc587ece.ngrok.io/api/executive_report/'
values = {'appId' : x, }
authtoken = "JWT "+str(token)
headers = { "Authorization" : authtoken }
response = requests.post(checkurl, data=values,headers=headers)
x = response.json()
vuldetail =  x["vulnerabilitiesSummary"]
issuefound =  len(vuldetail)
highissues = 0
mediumissues = 0 
lowissues = 0 
while issuefound:
	severity =  vuldetail[str(issuefound)]["severity"]
	if severity == "High":
		highissues = highissues+1
	if severity == "Low":
		lowissues = lowissues+1
	if severity == "Medium":
		mediumissues = mediumissues+1	
	issuefound = issuefound - 1 
if highissues > 5:
	print("Build Failed because "+str(highissues)+" high security issues detected in your application! ")
	exit(1)
if highissues >=3 and mediumissues >=3:
	print("Build Failed because "+str(highissues)+" high security issues and " +str(mediumissues)+" medium security issues detected in your application! ") 
	exit(1)
	
print("Your Application has "+str(highissues)+ " high issues, "+str(mediumissues)+" medium issues, "+str(lowissues)+" low issues. ")
