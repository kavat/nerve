from core.redis import rds
from packaging import version

data = rds.get_inspec_data()

tipo_report = "inspec"

data = {k: v for k, v in sorted(data.items(),
        key=lambda item: version.parse(item[1]['control_id_numeric']),
        reverse=False)}

print("HOST;PROFILE;ID;CONTROL TITLE;CONTROL DESCRIPTION;TEST DESCRIPTION;RESULT")
for key, value in data.items():
  print("{};{};{};{};{};{}".format(value['host'],value['profile'],value['control_id_numeric'],value['control_title'].replace("\n",""),value['control_desc'].replace("\n",""),value['result_desc'].replace("\n",""),value['result_status']))
