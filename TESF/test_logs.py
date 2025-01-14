import os
import subprocess 

# command = 'sudo docker logs cb47db64fe8e'
# with open("/home/lenovo/TESF/amf.log", "w") as file:
#     # Run the command and redirect the output to the file
#     subprocess.run(command, shell=True, stdout=file, stderr=subprocess.STDOUT)
# with open('/home/lenovo/TESF/amf.log') as f:
#                     while True:
#                         line = f.readline()
#                         word = "Subscription"
#                         if word in line:
#                             print(line)
# import re

# imsi = "999170000000002"
# word = "UE SUPI"
# with open('/home/lenovo/TESF/smf.log') as f:
#         while True:
#             line_smf = f.readline()
#             if imsi and word in line_smf:
#                   ipv4_match = re.search(r"IPv4\[(.*?)\]", line_smf)
#                   ipv4_address = ipv4_match.group(1)
#                   print(ipv4_address)

# import pandas as pd 
# value = 999170000000002
# df = pd.read_csv("imsiTrustScore.csv")
# row = df[df['IMSI'] == value].iloc[0].to_dict()
# print(row)
# print(row['Trust Score'])
# print(row['IP'])

# from kafka import KafkaAdminClient

# admin_client = KafkaAdminClient(bootstrap_servers='155.54.95.245:31400')
# topic_list = admin_client.list_topics()

# print("Topics in the Kafka cluster:")
# for topic in topic_list:
#     print(topic)


from flask import Flask, request, jsonify
import subprocess
import re
import pandas as pd
import os
from fastapi import FastAPI, Query
import pandas as pd
from stix2 import CustomObject, properties
from stix2 import Relationship
from stix2 import Bundle
import json
from kafka import KafkaProducer


app = Flask(__name__)

# Constants
AMF_LOG_PATH = '/home/lenovo/TESF/amf.log'
SMF_LOG_PATH = '/home/lenovo/TESF/smf.log'
IMSI_CSV_PATH = 'imsiTrustScore.csv'

# Precompiled regular expressions
IMSI_PATTERN = re.compile(r'\[imsi-(.+?)\]')
IPV4_PATTERN = re.compile(r"IPv4\[(.*?)\]")


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

# Utility Functions
def extract_imsi(line):
    match = IMSI_PATTERN.search(line)
    return match.group(1) if match else None

def extract_ip(line):
    match = IPV4_PATTERN.search(line)
    return match.group(1) if match else None

def run_command(command, output_file=None):
    with open(output_file, "w") if output_file else subprocess.PIPE as file:
        subprocess.run(command, shell=True, stdout=file, stderr=subprocess.STDOUT)

def update_trust_score(imsi, ip, alert_loc, imsi_violation_dict):
    if imsi not in imsi_violation_dict:
        imsi_violation_dict[imsi] = {'Trust Score': 100, 'IP': ip, 'Alert Location': alert_loc}
    else:
        imsi_violation_dict[imsi]['Trust Score'] = max(0, imsi_violation_dict[imsi]['Trust Score'] - 5)  # Prevent negative trust score
    print(f"Updated IMSI {imsi}: Trust Score={imsi_violation_dict[imsi]['Trust Score']}, IP={ip}, Alert Location={alert_loc}")
    save_trust_scores(imsi_violation_dict)

def save_trust_scores(imsi_violation_dict):
    # Convert dictionary to DataFrame with IMSI as the index and other fields as columns
    df = pd.DataFrame([
        {'IMSI': imsi, 'Trust Score': info['Trust Score'], 'IP': info['IP'], 'Alert Location': info['Alert Location']}
        for imsi, info in imsi_violation_dict.items()
    ])
    df.to_csv(IMSI_CSV_PATH, index=False)

def restart_services():
    run_command('sudo systemctl restart prometheus')
    run_command('sudo systemctl restart alertmanager.service')


def gen_stix(value,df):
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

def send_stix(value,df):
    # Initialize the Kafka producer
    producer = KafkaProducer(
    bootstrap_servers='155.54.95.245:31400',
    value_serializer=lambda v: json.dumps(v).encode('utf-8'))

    data = gen_stix(value,df)
    # Send the JSON data to the Kafka topic
    producer.send('TESF-AID', data.serialize())
    # Ensure all messages are sent
    producer.flush()
    # Close the producer
    producer.close()

# def check_threshold_action(value, df = IMSI_CSV_PATH):
#     row = df[df['IMSI'] == value].iloc[0].to_dict()
#     if row['Trust Score'] <= 50:
#         send_stix(value,df)
#     else: 
#         print('All Trust Scores within range')

value = 999170000000001


df = pd.read_csv("imsiTrustScore.csv")
row = df[df['IMSI'] == value].iloc[0].to_dict()
if row['Trust Score'] <= 50:
    send_stix(value,df)
else: 
    print('All Trust Scores within range')




# # Flask Routes
# @app.route("/")
# def main():
#     return "Welcome to Flask TESF server"

# @app.route('/prometheus', methods=['POST'])
# def webhook_api_prometheus():
#     if request.headers.get('Content-Type') != 'application/json':
#         return jsonify({"error": "Content-Type must be application/json"}), 400

#     imsi_violation_dict = {}
#     data = request.json
#     alerts = data.get('alerts', [])
#     print("JSON file received and processed.")

#     for alert_info in alerts:
#         alert = alert_info['labels'].get('alertname')
#         alert_loc = alert_info['labels'].get('instance')
#         alert_job = alert_info['labels'].get('job')

#         if alert == "UeConfUpdateExceed" and alert_job == "open5gs-amfd":
#             # Run log commands
#             run_command('sudo docker logs --tail 100 amf', AMF_LOG_PATH)
#             run_command('sudo docker logs --tail 100 smf', SMF_LOG_PATH)

#             # Process AMF log
#             with open(AMF_LOG_PATH) as amf_file, open(SMF_LOG_PATH) as smf_file:
#                 for line_amf in amf_file:
#                     if "Configuration update" in line_amf:
#                         imsi = extract_imsi(line_amf)
#                         if not imsi:
#                             continue
#                         # Process SMF log for corresponding IP
#                         for line_smf in smf_file:
#                             if imsi in line_smf and "UE SUPI" in line_smf:
#                                 ip = extract_ip(line_smf)
#                                 update_trust_score(imsi, ip, alert_loc, imsi_violation_dict)
#                                 check_threshold_action(imsi)
#                                 break  # Stop searching SMF log for this IMSI
#             # Restart services
#             # restart_services()

#     return jsonify(data)

# if __name__ == "__main__":
#     app.run(debug=True, host="0.0.0.0", port=5004)


def check_threshold_action(value, df=None):
    # Load the DataFrame if df is not provided
    if df is None:
        df = pd.read_csv(IMSI_CSV_PATH)
    
    # Ensure df is a DataFrame
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame or None.")
    
    try:
        # Filter the DataFrame and check the trust score
        row = df[df['IMSI'] == value].iloc[0].to_dict()
        print(df['IMSI'].dtype)
        if row['Trust Score'] <= 50:
            send_stix(value, df)
        else: 
            print('All Trust Scores within range')
    except IndexError:
        print(f"No entry found for IMSI: {value}")
    except KeyError as e:
        print(f"Missing expected column in DataFrame: {e}")

