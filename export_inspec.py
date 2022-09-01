from core.redis import rds

data = rds.get_inspec_data()
data = {k: v for k, v in sorted(data.items(),
        key=lambda item: item[1]['rule_sev'],
        reverse=True)}

print("HOST;PROFILE;CONTROL TITLE;CONTROL DESCRIPTION;TEST DESCRIPTION;RESULT")
for key, value in data.items():
  print("{};{};{};{};{};{}".format(value['host'],value['profile'],value['control_title'].replace("\n",""),value['control_desc'].replace("\n",""),value['result_desc'].replace("\n",""),value['result_status']))
