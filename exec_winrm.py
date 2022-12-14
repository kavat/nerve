import base64
import sys

from core.windows_sender import WindowsSender

credentials = base64.b64decode(sys.argv[2].encode("ascii")).decode("ascii").split("__|||__")
host = credentials[0].strip()
username = credentials[1].strip()
password = credentials[2].strip()

comando = base64.b64decode(sys.argv[1].encode("ascii")).decode("ascii")

ws = WindowsSender(host, username, password)
if ws.connect():
  if ws.put_requirements():
    out, err = ws.exec(comando)
    print("__|||__{}__|||__".format(out))
    if err != None:
      sys.stderr.write(err)
  else:
    sys.stderr.write("Error uploading requirements")
else:
  sys.stderr.write("Error connecting")
