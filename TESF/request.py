import requests
import json

url = "http://localhost:8765/target" 
value_to_find = "999170000000001"  # Replace with the value you want to search for
response = requests.get(url, params={"value": value_to_find})

if response.status_code == 200:
  data = response.json()  # Assuming the response is in JSON format
  pretty_response = json.dumps(data, indent=4)
  print(pretty_response)  # This will print the retrieved row or an empty dictionary if not found
else:
  print("Request failed with status code:", response.status_code)