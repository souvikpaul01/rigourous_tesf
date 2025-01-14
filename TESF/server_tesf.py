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
import pandas as pd
from venv import logger
import pyshark
import logging
import logging.handlers
from netfilterqueue import NetfilterQueue
from scapy.all import IP



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
        imsi_violation_dict[imsi]['Trust Score'] = max(0, imsi_violation_dict[imsi]['Trust Score'] - 5)
        imsi_violation_dict[imsi]['IP'] = ip  # Prevent negative trust score
    print(f"Updated IMSI {imsi}: Trust Score={imsi_violation_dict[imsi]['Trust Score']}, IP={ip}, Alert Location={alert_loc}")
    save_trust_scores(imsi_violation_dict)

def save_trust_scores(imsi_violation_dict):
    df = pd.DataFrame([
        {'IMSI': imsi, 'Trust Score': info['Trust Score'], 'IP': info['IP'], 'Alert Location': info['Alert Location']}
        for imsi, info in imsi_violation_dict.items()
    ])
    df.to_csv(IMSI_CSV_PATH, index=False)

def restart_services():
    run_command('sudo systemctl restart prometheus')
    run_command('sudo systemctl restart alertmanager.service')

def UESwicthOff(imsi):
    imsi_value = 'imsi-' + imsi
    run_command('./UERANSIM/build/nr-cli'+ imsi_value +'--exec "deregister switch-off"')


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
    data = gen_stix(value,df)
    print(data)
    # Initialize the Kafka producer
    producer = KafkaProducer(
    bootstrap_servers='155.54.95.79:31400',
    value_serializer=lambda v: json.dumps(v).encode('utf-8'))

    # data = gen_stix(value,df)

    # Send the JSON data to the Kafka topic
    producer.send('TESF-AID', data.serialize())
    # Ensure all messages are sent
    producer.flush()
    # Close the producer
    producer.close()


# def check_threshold_action(value, df=None):
#     # Load the DataFrame if df is not provided
#     if df is None:
#         df = pd.read_csv(IMSI_CSV_PATH)
    
#     # Ensure df is a DataFrame
#     if not isinstance(df, pd.DataFrame):
#         raise ValueError("df must be a pandas DataFrame or None.")
    
#     try:
#         # Filter the DataFrame and check the trust score
#         value = int(value)
#         row = df[df['IMSI'] == value].iloc[0].to_dict()
#         if row['Trust Score'] <= 95:
#             send_stix(value, df)
#         else: 
#             print('All Trust Scores within range')
#     except IndexError:
#         print(f"No entry found for IMSI: {value}")
#     except KeyError as e:
#         print(f"Missing expected column in DataFrame: {e}")

#Set to track IMSIs for which alerts have been sent
alerted_imsis = set()

def check_threshold_action(value, df=None):
    global alerted_imsis  # Ensure we use the global set
    
    # Load the DataFrame if df is not provided
    if df is None:
        df = pd.read_csv(IMSI_CSV_PATH)
    
    # Ensure df is a DataFrame
    if not isinstance(df, pd.DataFrame):
        raise ValueError("df must be a pandas DataFrame or None.")
    
    try:
        # Filter the DataFrame and check the trust score
        value = int(value)
        row = df[df['IMSI'] == value].iloc[0].to_dict()
        
        # Check if the IMSI's trust score is below the threshold and if an alert has already been sent
        if row['Trust Score'] <= 95:
            if value not in alerted_imsis:
                send_stix(value, df)  # Send alert
                alerted_imsis.add(value)  # Add to alerted IMSIs
                print(f"Sending Alert for IMSI: {value}")
                # Initiate de-attach procedure
                # UESwicthOff(row['IMSI'])
            else:
                print(f"Alert already sent for IMSI: {value}, skipping.")
        else:
            # Optional: Remove IMSI from alerted_imsis if trust score improves
            if value in alerted_imsis:
                alerted_imsis.remove(value)
                print(f"Trust score improved for IMSI: {value}, removed from alerted set.")
    except IndexError:
        print(f"No entry found for IMSI: {value}")
    except KeyError as e:
        print(f"Missing expected column in DataFrame: {e}")

def packet_process(imsi):
    
    capture = pyshark.LiveCapture(interface = 'br-62880435c882' ,display_filter='nas-5gs')

    for packet in capture:
        if hasattr(packet.ngap, 'nas_pdu'): 
                try:
                    nas_pdu = packet.ngap.nas_pdu.raw_value
                    # if it's plain registration request message.
                    if nas_pdu.startswith('7e0041'):
                        id_length = int(nas_pdu[8:12],16)
                        suci:str = nas_pdu[12:12+id_length*2]
                        # print(' its plain registration request message.')
                    # elif it's identity response during GUTI attach.
                    elif nas_pdu.startswith('7e01') and nas_pdu[14:20] == '7e005c':
                        # print(' its identity response during GUTI attach.')
                        id_length = int(nas_pdu[20:24], 16)
                        suci: str = nas_pdu[24:24 + id_length * 2]
                    bcd_supi:str = ''   # BCD string of plain SUPI
                except Exception as e:
                    logger.error("failed to get SUCI content, operation aborted.\n")
                    logger.error(f"the error info is : {str(e)}\n")
                # if SUPI is IMSI format:
                if suci[0] =='0':
                    # if suci is not encrypted:
                    if suci[13] == '0':
                        bcd_supi = suci[2:8] + suci[16:]  # BCD string of SUPI, for example:'13001341000021f0'
                # if SUPI is NAI format:
                elif suci[0] =='1':
                    pass
                if bcd_supi:
                    supi = bcd_supi[1] + bcd_supi[0] + bcd_supi[3] + bcd_supi[5] + bcd_supi[4] + \
                            bcd_supi[2] + bcd_supi[7] + bcd_supi[6] + bcd_supi[9] + bcd_supi[8] + \
                            bcd_supi[11] + bcd_supi[10] + bcd_supi[13] + bcd_supi[12] + \
                            bcd_supi[15] + bcd_supi[14]
                    supi = supi.replace('f', '')
                    if (supi == imsi):
                        return packet.ip.src, packet.ip.dst



imsi_violation_dict = {}
# Flask Routes
@app.route("/")
def main():
    return "Welcome to Flask TESF server"

@app.route('/prometheus', methods=['POST'])
def webhook_api_prometheus():
    if request.headers.get('Content-Type') != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 400


    data = request.json
    alerts = data.get('alerts', [])
    print("JSON file received and processed.")

    for alert_info in alerts:
        alert = alert_info['labels'].get('alertname')
        alert_loc = alert_info['labels'].get('instance')
        alert_job = alert_info['labels'].get('job')

        if alert == "UeConfUpdateExceed" and alert_job == "open5gs-amfd":
            # Run log commands
            run_command('sudo docker logs --tail 100 amf', AMF_LOG_PATH)
            run_command('sudo docker logs --tail 100 smf', SMF_LOG_PATH)

            # Process AMF log
            with open(AMF_LOG_PATH) as amf_file, open(SMF_LOG_PATH) as smf_file:
                for line_amf in amf_file:
                    if "Configuration update command" in line_amf:
                        imsi = extract_imsi(line_amf)
                        print(imsi)
                        if not imsi:
                            continue
                        else:
                            src , dest = packet_process(imsi)
                            print(src,dest,imsi)
                            update_trust_score(imsi, src, dest, imsi_violation_dict)
                            check_threshold_action(imsi)
                       
                       
                        # if not imsi:
                        #     continue
                        # Process SMF log for corresponding IP
                        # src , dest = packet_process(imsi)
                        # print(src,dest,imsi)
                        # for line_smf in smf_file:
                        #     if imsi in line_smf and "UE SUPI" in line_smf:
                        #         ip = extract_ip(line_smf)
                        #         print(ip)
                        #         update_trust_score(imsi, ip, alert_loc, imsi_violation_dict)
                        #         check_threshold_action(imsi)
                        #         break  # Stop searching SMF log for this IMSI

    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5004)
