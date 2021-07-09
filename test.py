import requests

# api key: 28d7825c30ddf367f2ae5e3dc7bcba83a555a734f4fd42b7194a542d5d3fb78a

#
# import requests
#
# url = 'https://www.virustotal.com/vtapi/v2/file/report'
#
# params = {'apikey': '28d7825c30ddf367f2ae5e3dc7bcba83a555a734f4fd42b7194a542d5d3fb78a', 'resource': 'ad04e313410dd865916b720e03e6b77e'}
#
# response = requests.get(url, params=params)
# response = response.json()
# print(response)

# list = []
# for i in range(0, 5):
#     a = i
#     b = i * 2
#     c = i * 3
#     list.append({"a": a, "b": b, "c": c})
# print(list)
import os

path = './savedFiles'
files = os.listdir(path)
f2 = open('./savedFiles/'+files[0], "r")
lines = f2.readlines()
hashesArray=[]
for hashes in lines:
    hashesArray.append(hashes.strip('\n'))
lines = f2.readlines()
