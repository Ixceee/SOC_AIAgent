import csv
import json
import os

input_path = os.path.join('test-data', 'logs.csv')
output_path = os.path.join('test-data', 'logs.json')

with open(input_path, 'r') as f:
    reader = csv.DictReader(f)
    data = list(reader)

with open(output_path, 'w') as f:
    json.dump(data, f, indent=2)

print(f"Converted {len(data)} alerts to {output_path}")