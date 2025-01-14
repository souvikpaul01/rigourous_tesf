from flask import json
from flask import request
from flask import Flask
import subprocess
import sys
import os
import re
import json
import pandas as pd
import docker
from docker.models.containers import Container
from typing import List
import os
import subprocess 


def find_imsi(input):
    found = re.search('\[imsi-(.+?)\]', input)
    return found.group(1)

def find_ip(input):
    ipv4_match = re.search(r"IPv4\[(.*?)\]", input)
    ipv4_address = ipv4_match.group(1)
    return ipv4_address


app = Flask(__name__)

@app.route("/")
def main():
    return "Welcome to Flask TESF server"

@app.route('/prometheus', methods=['POST'])
def webhook_api_prometheus():
    imsi_violation_dict = {}
    if request.headers['Content-Type'] == 'application/json':
        print ("json file received ")
        my_data = json.dumps(request.json)
        with open('data.json', 'w', encoding='utf-8') as jf:
            json.dump(my_data, jf, ensure_ascii=True, indent=4)
        dict_info = json.loads(my_data)
        for i in dict_info['alerts']:
            alert =i['labels']['alertname']
            alert_loc = i['labels']['instance']
            alert_job = i['labels']['job']
            if (alert == "UeConfUpdateExceed" and alert_job == "open5gs-amfd"):
                command_amf = 'sudo docker logs --since 5m cb47db64fe8e'
                command_smf = 'sudo docker logs --since 5m  smf'
                with open("/home/lenovo/TESF/amf.log", "w") as file:
                    subprocess.run(command_amf, shell=True, stdout=file, stderr=subprocess.STDOUT)
                with open("/home/lenovo/TESF/smf.log", "w") as file:
                    subprocess.run(command_smf, shell=True, stdout=file, stderr=subprocess.STDOUT)
                with open('/home/lenovo/TESF/amf.log') as f:
                    while True:
                        line_amf = f.readline()
                        word_amf = "Configuration update"
                        if word_amf in line_amf:
                            print(line_amf)
                            imsi = find_imsi(line_amf)
                            word_smf = "UE SUPI"
                            with open('/home/lenovo/TESF/smf.log') as f:
                                    while True:
                                        line_smf = f.readline()
                                        if imsi and word_smf in line_smf:
                                            ip = find_ip(line_smf)
                                            if imsi not in imsi_violation_dict.keys():
                                                imsi_violation_dict.update({ imsi : 100})
                                            else:
                                                print("Trust score reduction algorithm initialted for UE with IMSI " + imsi +  + " associated with AMF:" , alert_loc)
                                                imsi_violation_dict[imsi] -= 5
                                            print("Trust score reduction algorithm completed for UE with IMSI " + imsi  + " associated with AMF:" , alert_loc)
                                            print(imsi_violation_dict)
                                            data_csv_raw = pd.DataFrame(imsi_violation_dict.items(), columns=['IMSI', 'Trust Score'])
                                            data_csv_raw.to_csv('imsiTrustScore.csv',index=False)
                                            # command_prometheus = 'sudo systemctl restart prometheus'
                                            # subprocess.run(command_prometheus, shell=True, stdout=file, stderr=subprocess.STDOUT)
                                            # command_alertmanager = 'sudo systemctl restart alertmanager.service'
                                            # subprocess.run(command_alertmanager, shell=True, stdout=file, stderr=subprocess.STDOUT)
    return(my_data)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5004)