from fastapi import FastAPI, Query
import pandas as pd
from stix2 import CustomObject, properties
from stix2 import Relationship
from stix2 import Bundle



@CustomObject('anomalies', [
    ('error_type', properties.StringProperty()),
    ('imsi', properties.StringProperty()),
    ('ip', properties.StringProperty()),
    ('trust_score', properties.IntegerProperty()),
])

class Anomalies(object):
    def __init__(self, error_type=None, **kwargs):
        if error_type and error_type not in ['re-registration', 'reconfig']:
            raise ValueError("'%s' is not a recognized error" % error_type)


@CustomObject('networkentity', [
('name', properties.StringProperty()),
('ip', properties.StringProperty()),
])

class Network(object):
   def __init__(self, name=None, **kwargs):
        if name and name not in ['amf', 'smf']:
            raise ValueError("'%s' is not a recognized entity" % name)

app = FastAPI()
df = pd.read_csv("imsiTrustScore.csv")

@app.get("/target")
async def find_row(value: int = Query(..., description="Target to search for")):
  try:
    row = df[df['IMSI'] == value].iloc[0].to_dict()
    
    anomaly = Anomalies(error_type = 're-registration', 
                        imsi = row['IMSI'],
                        ip = row['IP'],
                        trust_score = row['Trust Score'] )
    entity = Network(name = 'amf',
                    ip = row['Alert Location'])
    relationship = Relationship(anomaly, 'indicates', entity)
    bundle = Bundle(anomaly,entity,relationship)
    return bundle
  except IndexError:
    return {}