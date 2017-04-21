import json
from pymongo import MongoClient

"""This script exports mongodb data in a json dump that is read by
   migration script and imported into postgresql
   This file is put aside because there is a naming conflict between the 
   mongodb bson library and the standard pip bson library.
"""


def mongo_data(ip='127.0.0.1',port=27017):

    mongo_client = MongoClient(ip,port)
    db = mongo_client.wapt
    hosts = db.hosts
    result = []
    for h in hosts.find():
        h.pop("_id")
        result.append(h)
    return result

#with open('/tmp/wapt-mongodb-data.json','w') as foutput:
data = json.dumps(mongo_data())
print data
    #foutput.write(data)
