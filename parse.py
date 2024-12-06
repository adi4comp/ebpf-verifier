import json

file_path = "data.json"


with open(file_path, 'r') as file:
    data = json.load(file)


if isinstance(data, list):

    for i, obj in enumerate(data):
        field = obj.get("request")
        print(f"Request {i + 1}: {field}")
else:
    print("Error")
