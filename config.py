import os

CVE_SCAN_SERVICE_HOST = "172.17.0.2"
CVE_SCAN_SERVICE_PORT = 5000
CVE_SCAN_USE_THREADS = 0
CVE_SCAN_MAX_THREADS = 5
PROFILE_SERVICE_HOST = "172.17.0.3"
PROFILE_SERVICE_PORT = 5000
SESSION_MAX_CHECKS = 120
SESSION_TIME_SLEEP_CHECK = 30

# Logger Configuration
LOG_LEVEL = 'DEBUG'

# Webserver Configuration
WEB_HOST = '0.0.0.0'
WEB_PORT = 8080
WEB_DEBUG = False
WEB_USER = os.environ.get('username', 'admin')
WEB_PASSW = os.environ.get('password', 'admin')
WEB_LOG = 'nerve.log'

# Web Security
# Setting this to True will return all responses with security headers.
WEB_SECURITY = True
WEB_SEC_HEADERS = {
  'CSP':'default-src \'self\' \'unsafe-inline\'; object-src \'none\'; img-src \'self\' data:',
  'CTO':'nosniff',
  'XSS':'1; mode=block',
  'XFO':'DENY',
  'RP':'no-referrer',
  'Server':'NERVE'
}

# Maximum allowed attempts before banning the remote origin
MAX_LOGIN_ATTEMPTS = 3

# Redis Configuration
# This should not be set to anything else except localhost unless you want to do a multi-node deployment.
RDS_HOST = '127.0.0.1'
RDS_PORT = 6379
RDS_PASSW = None

# Scan Configuration
USER_AGENT = 'NERVE'

# COMMAND FOR OS RPM BASED TO LIST ALL SHARED LIBRARIES RELATED TO A SOFTWARES AND SOFTWARES WITH A TCP OR UDP STREAM EXPOSED
CPE_GENERATION_RPM = 'echo PiAvdG1wL2FwcG9nZ2lvCgpmb3IgSU5PREUgaW4gJChjYXQgL3Byb2MvbmV0L3RjcCB8IGdyZXAgLXYgcmVtX2FkZHJlc3MgfCBhd2sgLUYnICcgJ3twcmludCAkMTB9Jyk7IGRvCgogIGxpYnJlcmllPSQoZmluZCAvcHJvYyAtbG5hbWUgInNvY2tldDpcXFskSU5PREVcXF0iIDI+L2Rldi9udWxsIHwgaGVhZCAtbiAxIHwgYXdrIC1GICIvIiAne3ByaW50ICJjYXQgL3Byb2MvIiQzIi9tYXBzIn0nIHwgYmFzaCB8IGdyZXAgIlwuc28iIHwgYXdrIC1GJyAnICd7cHJpbnQgJDZ9JyB8IHNvcnQgLXUpCiAgZm9yIGxpYnJlcmlhIGluICRsaWJyZXJpZTsgZG8KICAgIHJwbSAtLXF1ZXJ5Zm9ybWF0ICIle05BTUV9OiV7VkVSU0lPTn1cbiIgLXFmICRsaWJyZXJpYSA+PiAvdG1wL2FwcG9nZ2lvCiAgZG9uZQoKICBzb2Z0d2FyZXM9JChmaW5kIC9wcm9jIC1sbmFtZSAic29ja2V0OlxcWyRJTk9ERVxcXSIgMj4vZGV2L251bGwgfCBoZWFkIC1uIDEgfCBhd2sgLUYgIi8iICd7cHJpbnQgImNhdCAvcHJvYy8iJDMiL2NvbW0ifScgfCBiYXNoKQogIGZvciBzb2Z0d2FyZSBpbiAkc29mdHdhcmVzOyBkbwogICAgZmluZCAvIC10eXBlIGYgLWV4ZWN1dGFibGUgLW5hbWUgJHNvZnR3YXJlIDI+L2Rldi9udWxsfCBhd2sgLUYnICcgJ3twcmludCAicnBtIC0tcXVlcnlmb3JtYXQgXCIle05BTUV9OiV7VkVSU0lPTn1cXG5cIiAtcWYgIiQxfScgfCBiYXNoID4+IC90bXAvYXBwb2dnaW8KICBkb25lICAKCmRvbmUKCmZvciBJTk9ERSBpbiAkKGNhdCAvcHJvYy9uZXQvdWRwIHwgZ3JlcCAtdiByZW1fYWRkcmVzcyB8IGF3ayAtRicgJyAne3ByaW50ICQxMH0nKTsgZG8KCiAgbGlicmVyaWU9JChmaW5kIC9wcm9jIC1sbmFtZSAic29ja2V0OlxcWyRJTk9ERVxcXSIgMj4vZGV2L251bGwgfCBoZWFkIC1uIDEgfCBhd2sgLUYgIi8iICd7cHJpbnQgImNhdCAvcHJvYy8iJDMiL21hcHMifScgfCBiYXNoIHwgZ3JlcCAiXC5zbyIgfCBhd2sgLUYnICcgJ3twcmludCAkNn0nIHwgc29ydCAtdSkKICBmb3IgbGlicmVyaWEgaW4gJGxpYnJlcmllOyBkbwogICAgcnBtIC0tcXVlcnlmb3JtYXQgIiV7TkFNRX06JXtWRVJTSU9OfVxuIiAtcWYgJGxpYnJlcmlhID4+IC90bXAvYXBwb2dnaW8KICBkb25lCgogIHNvZnR3YXJlcz0kKGZpbmQgL3Byb2MgLWxuYW1lICJzb2NrZXQ6XFxbJElOT0RFXFxdIiAyPi9kZXYvbnVsbCB8IGhlYWQgLW4gMSB8IGF3ayAtRiAiLyIgJ3twcmludCAiY2F0IC9wcm9jLyIkMyIvY29tbSJ9JyB8IGJhc2gpCiAgZm9yIHNvZnR3YXJlIGluICRzb2Z0d2FyZXM7IGRvCiAgICBmaW5kIC8gLXR5cGUgZiAtZXhlY3V0YWJsZSAtbmFtZSAkc29mdHdhcmUgMj4vZGV2L251bGx8IGF3ayAtRicgJyAne3ByaW50ICJycG0gLS1xdWVyeWZvcm1hdCBcIiV7TkFNRX06JXtWRVJTSU9OfVxcblwiIC1xZiAiJDF9JyB8IGJhc2ggPj4gL3RtcC9hcHBvZ2dpbwogIGRvbmUKCmRvbmUKCmNhdCAvdG1wL2FwcG9nZ2lvIHwgZ3JlcCAiW146XVwrXDpbMC05XC5dXCsiIC1vIHwgc2VkICJzL1wuJC8vZyIgfCBzb3J0IC11Cg== | base64 -d | bash | xargs echo -n'

# COMMAND FOR OS DEB BASED TO LIST ALL SHARED LIBRARIES RELATED TO A SOFTWARES AND SOFTWARES WITH A TCP OR UDP STREAM EXPOSED
CPE_GENERATION_DPKG = 'echo PiAvdG1wL2FwcG9nZ2lvCgpmb3IgSU5PREUgaW4gJChjYXQgL3Byb2MvbmV0L3RjcCB8IGdyZXAgLXYgcmVtX2FkZHJlc3MgfCBhd2sgLUYnICcgJ3twcmludCAkMTB9Jyk7IGRvIAoKICBsaWJyZXJpZT0kKGZpbmQgL3Byb2MgLWxuYW1lICJzb2NrZXQ6XFxbJElOT0RFXFxdIiAyPi9kZXYvbnVsbCB8IGhlYWQgLW4gMSB8IGF3ayAtRiAiLyIgJ3twcmludCAiY2F0IC9wcm9jLyIkMyIvbWFwcyJ9JyB8IGJhc2ggfCBncmVwICJcLnNvIiB8IGF3ayAtRicgJyAne3ByaW50ICQ2fScgfCBhd2sgLUYnLycgJ3twcmludCAkTkZ9JyB8IHNvcnQgLXUpCiAgZm9yIGxpYnJlcmlhIGluICRsaWJyZXJpZTsgZG8KICAgIGRwa2cgLVMgJGxpYnJlcmlhIHwgYXdrIC1GJzonICd7cHJpbnQgJDF9JyB8IHNvcnQgLXUgfCBhd2sgLUYnICcgJ3twcmludCAiZHBrZy1xdWVyeSAtVyAiJDF9JyB8IGJhc2ggfCBzZWQgInMvW1x0IF1cKy9fX18vZyIgPj4gL3RtcC9hcHBvZ2dpbwogIGRvbmUKCiAgc29mdHdhcmVzPSQoZmluZCAvcHJvYyAtbG5hbWUgInNvY2tldDpcXFskSU5PREVcXF0iIDI+L2Rldi9udWxsIHwgaGVhZCAtbiAxIHwgYXdrIC1GICIvIiAne3ByaW50ICJjYXQgL3Byb2MvIiQzIi9jb21tIn0nIHwgYmFzaCkKICBmb3Igc29mdHdhcmUgaW4gJHNvZnR3YXJlczsgZG8KICAgIGZpbmQgLyAtdHlwZSBmIC1leGVjdXRhYmxlIC1uYW1lICRzb2Z0d2FyZSAyPi9kZXYvbnVsbHwgYXdrIC1GJyAnICd7cHJpbnQgImRwa2ctcXVlcnkgLVMgIiQxfScgfCBiYXNoIHwgYXdrIC1GJzonICd7cHJpbnQgJDF9JyB8IHNvcnQgLXV8IGF3ayAtRicgJyAne3ByaW50ICJkcGtnLXF1ZXJ5IC1XICIkMX0nIHwgYmFzaCB8IHNlZCAicy9bXHQgXVwrL19fXy9nIiA+PiAvdG1wL2FwcG9nZ2lvCiAgZG9uZQoKZG9uZSAKCmZvciBJTk9ERSBpbiAkKGNhdCAvcHJvYy9uZXQvdWRwIHwgZ3JlcCAtdiByZW1fYWRkcmVzcyB8IGF3ayAtRicgJyAne3ByaW50ICQxMH0nKTsgZG8KCiAgbGlicmVyaWU9JChmaW5kIC9wcm9jIC1sbmFtZSAic29ja2V0OlxcWyRJTk9ERVxcXSIgMj4vZGV2L251bGwgfCBoZWFkIC1uIDEgfCBhd2sgLUYgIi8iICd7cHJpbnQgImNhdCAvcHJvYy8iJDMiL21hcHMifScgfCBiYXNoIHwgZ3JlcCAiXC5zbyIgfCBhd2sgLUYnICcgJ3twcmludCAkNn0nIHwgYXdrIC1GJy8nICd7cHJpbnQgJE5GfScgfCBzb3J0IC11KQogIGZvciBsaWJyZXJpYSBpbiAkbGlicmVyaWU7IGRvCiAgICBkcGtnIC1TICRsaWJyZXJpYSB8IGF3ayAtRic6JyAne3ByaW50ICQxfScgfCBzb3J0IC11IHwgYXdrIC1GJyAnICd7cHJpbnQgImRwa2ctcXVlcnkgLVcgIiQxfScgfCBiYXNoIHwgc2VkICJzL1tcdCBdXCsvX19fL2ciID4+IC90bXAvYXBwb2dnaW8KICBkb25lCgogIHNvZnR3YXJlcz0kKGZpbmQgL3Byb2MgLWxuYW1lICJzb2NrZXQ6XFxbJElOT0RFXFxdIiAyPi9kZXYvbnVsbCB8IGhlYWQgLW4gMSB8IGF3ayAtRiAiLyIgJ3twcmludCAiY2F0IC9wcm9jLyIkMyIvY29tbSJ9JyB8IGJhc2gpCiAgZm9yIHNvZnR3YXJlIGluICRzb2Z0d2FyZXM7IGRvCiAgICBmaW5kIC8gLXR5cGUgZiAtZXhlY3V0YWJsZSAtbmFtZSAkc29mdHdhcmUgMj4vZGV2L251bGx8IGF3ayAtRicgJyAne3ByaW50ICJkcGtnLXF1ZXJ5IC1TICIkMX0nIHwgYmFzaCB8IGF3ayAtRic6JyAne3ByaW50ICQxfScgfCBzb3J0IC11fCBhd2sgLUYnICcgJ3twcmludCAiZHBrZy1xdWVyeSAtVyAiJDF9JyB8IGJhc2ggfCBzZWQgInMvW1x0IF1cKy9fX18vZyIgPj4gL3RtcC9hcHBvZ2dpbwogIGRvbmUKCmRvbmUKCmNhdCAvdG1wL2FwcG9nZ2lvIHwgc2VkICJzL1w6XCguKlwpX19fL19fXy9nIiB8IHNlZCAicy9fX19bXlw6XVwrXDovX19fL2ciIHwgZ3JlcCAiXCguKlwpX19fWzAtOVwuXVwrIiAtbyB8IHNlZCAicy9cLiQvL2ciIHwgc2VkICJzL19fXy9cOi9nIiB8IHNvcnQgLXUK | base64 -d | bash | xargs echo -n'

# Default scan configuration
# This will be used in the "Quick Start" scan.
DEFAULT_SCAN = {
  'type':'network',
  'ip_peer_static':'10.0.2.2',
  'type_ie':'external',
  'targets':{
    'networks':[],
    'excluded_networks':[],
    'domains':[]
  },
  'config':{
    'name':'Default',
    'description':'My Default Scan',
    'engineer':'Andrea',
    'allow_aggressive':3,
    'allow_dos':False,
    'allow_bf':False,
    'allow_internet':True,
    'dictionary':{
      'usernames':[],
      'passwords':[]
    },
    'scan_opts':{
      'interface':None,
      'max_ports':100,
      'custom_ports':[],
      'parallel_scan':50,
      'parallel_attack':30,
    },
    'post_event':{
      'webhook':None
    },
    'frequency':'once'
  }
}
