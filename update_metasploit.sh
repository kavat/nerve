#!/bin/bash

msfupdate
echo "/opt/nerve/update_metasploit.sh" | at now + 24 hours
