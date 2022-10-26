# RESET TEMP FILES
> /tmp/appoggio
> /tmp/ritorno

for protocol in tcp udp; do

  # GET INODE IN ORDER TO CHECK SPECIFIC PROCESS
  for INODE in $(cat /proc/net/$protocol | grep -v rem_address | grep " 0[ ]\+$" | awk -F' ' '{print $10}'); do

    ip_binding_for_inode=$(cat /proc/net/$protocol | grep " 0[ ]\+$" | grep " $INODE " | awk -F' ' '{print $2}' | awk -F":" '{print $1}')
    type_vuln="internal"
    if [ "$ip_binding_for_inode" != "0100007F" ] && [ "$ip_binding_for_inode" != "7F000001" ] && [ "$ip_binding_for_inode" != "3500007F" ] && [ "$ip_binding_for_inode" != "7F000035" ]; then
      type_vuln="external"
    fi

    # LIBRARIES RELATED TO SPECIFIC INODE
    librerie=$(find /proc -lname "socket:\\[$INODE\\]" 2>/dev/null | head -n 1 | awk -F "/" '{print "cat /proc/"$3"/maps"}' | bash | grep "\.so" | awk -F' ' '{print $6}' | sort -u)
    for libreria in $librerie; do
      for file_returned in $(rpm --queryformat "%{NAME}:%{VERSION}\n" -qf $libreria); do
        echo "${type_vuln};used;${file_returned}" >> /tmp/appoggio
      done
    done

    # OR LINKED LIBRARIES RELATED TO SPECIF INODE
    for libreria in $librerie; do
      for libreria_linked in $(find / -type l -name $libreria 2>/dev/null | awk -F' ' '{print "ls -l "$1}' | bash | awk '{print $NF}'); do
        for file_returned in $(rpm --queryformat "%{NAME}:%{VERSION}\n" -qf $libreria_linked); do
          echo "${type_vuln};used;${file_returned}" >> /tmp/appoggio
        done
      done
    done

    # FILES CAN BE DIRECTLY EXECUTABLES
    softwares=$(find /proc -lname "socket:\\[$INODE\\]" 2>/dev/null | head -n 1 | awk -F "/" '{print "cat /proc/"$3"/comm"}' | bash)
    for software in $softwares; do
      for file_returned in $(find / -type f -executable -name $software 2>/dev/null| awk -F' ' '{print "rpm --queryformat \"%{NAME}:%{VERSION}\\n\" -qf "$1}' | bash); do
        echo "${type_vuln};executable;${file_returned}" >> /tmp/appoggio
      done
    done  

    # OR LINKS A SPECIFIC EXECUTABLE FILES
    for software in $softwares; do
      for software_linked in $(find / -type l -name $software 2>/dev/null | awk -F' ' '{print "ls -l "$1}' | bash | awk '{print $NF}'); do
        for file_returned in $(find / -type f -executable -name $software_linked 2>/dev/null| awk -F' ' '{print "rpm --queryformat \"%{NAME}:%{VERSION}\\n\" -qf "$1}' | bash); do
          echo "${type_vuln};executable;${file_returned}" >> /tmp/appoggio
        done
      done
    done

  done

done

for riga in $(cat /tmp/appoggio | grep "[^:]\+\:[0-9\.]\+[a-zA-Z0-9]\+" -o | sed "s/\.$//g" | sort -u); do

  type_vuln=$(echo $riga | awk -F';' '{print $1}')
  type_package=$(echo $riga | awk -F';' '{print $2}')
  pacchetto=$(echo $riga | awk -F';' '{print $3}' | awk -F':' '{print $1}')
  version=$(echo $riga | awk -F';' '{print $3}' | awk -F':' '{print $2}')

  usability=$(grep ";${pacchetto}:${version}" /tmp/appoggio | awk -F';' '{print $1";"$2}' | sort -u | head -n1)
  echo "${usability};${pacchetto}:${version}" >> /tmp/ritorno

done

cat /tmp/ritorno | grep "[^:]\+\:[0-9\.]\+[a-zA-Z0-9]\+" -o | sed "s/\.$//g" | sort -u | sed "s/external;used/external_used/g" | sed "s/external;executable/external_executable/g" | sed "s/internal;used/internal_used/g" | sed "s/internal;executable/internal_executable/g"
