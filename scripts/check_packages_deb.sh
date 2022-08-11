> /tmp/appoggio
> /tmp/ritorno

for protocol in tcp udp; do


  # GET INODE IN ORDER TO CHECK SPECIFIC PROCESS
  for INODE in $(cat /proc/net/$protocol | grep -v rem_address | grep " 0[ ]\+$" | awk -F' ' '{print $10}'); do 

    ip_binding_for_inode=$(cat /proc/net/$protocol | grep " 0[ ]\+$" | grep " $INODE " | awk -F' ' '{print $2}' | awk -F":" '{print $1}')
    type_vuln="internal"
    if [ "$ip_binding_for_inode" != "0100007F" ] && [ "$ip_binding_for_inode" != "7F000001" ]; then
      type_vuln="external"
    fi

    # LIBRARIES RELATED TO SPECIFIC INODE
    librerie=$(find /proc -lname "socket:\\[$INODE\\]" 2>/dev/null | head -n 1 | awk -F "/" '{print "cat /proc/"$3"/maps"}' | bash | grep "\.so" | awk -F' ' '{print $6}' | awk -F'/' '{print $NF}' | sort -u)
    for libreria in $librerie; do
      for file_returned in $(dpkg -S $libreria | awk -F':' '{print $1}' | sort -u | awk -F' ' '{print "dpkg-query -W "$1}' | bash | sed "s/[\t ]\+/___/g"); do
        echo "$type_vuln;$file_returned" >> /tmp/appoggio
      done
    done

    # OR LINKED LIBRARIES RELATED TO SPECIF INODE
    for libreria in $librerie; do
      for libreria_linked in $(find / -type l -name $libreria 2>/dev/null | awk -F' ' '{print "ls -l "$1}' | bash | awk '{print $NF}'); do
        for file_returned in $(dpkg -S $libreria_linked | awk -F':' '{print $1}' | sort -u | awk -F' ' '{print "dpkg-query -W "$1}' | bash | sed "s/[\t ]\+/___/g"); do
          echo "$type_vuln;$file_returned" >> /tmp/appoggio
        done
      done
    done

    # FILES CAN BE DIRECTLY EXECUTABLES
    softwares=$(find /proc -lname "socket:\\[$INODE\\]" 2>/dev/null | head -n 1 | awk -F "/" '{print "cat /proc/"$3"/comm"}' | bash)
    for software in $softwares; do
      for file_returned in $(find / -type f -executable -name $software 2>/dev/null| awk -F' ' '{print "dpkg-query -S "$1}' | bash | awk -F':' '{print $1}' | sort -u| awk -F' ' '{print "dpkg-query -W "$1}' | bash | sed "s/[\t ]\+/___/g"); do
        echo "$type_vuln;$file_returned" >> /tmp/appoggio
      done
    done

    # OR LINKS A SPECIFIC EXECUTABLE FILES
    for software in $softwares; do
      for software_linked in $(find / -type l -name $software 2>/dev/null | awk -F' ' '{print "ls -l "$1}' | bash | awk '{print $NF}'); do
	for file_returned in $(find / -type f -executable -name $software_linked 2>/dev/null| awk -F' ' '{print "dpkg-query -S "$1}' | bash | awk -F':' '{print $1}' | sort -u| awk -F' ' '{print "dpkg-query -W "$1}' | bash | sed "s/[\t ]\+/___/g"); do
          echo "$type_vuln;$file_returned" >> /tmp/appoggio
        done
      done
    done

  done 

done

cat /tmp/appoggio | sed "s/\:\(.*\)___/___/g" | sed "s/___[^\:]\+\:/___/g" | grep "\(.*\)___[0-9\.]\+" -o | sed "s/\.$//g" | sed "s/___/\:/g" | sort -u

for riga in $(cat /tmp/appoggio | grep "[^:]\+\:[0-9\.]\+" -o | sed "s/\.$//g" | sort -u); do

  type_vuln=$(echo $riga | awk -F';' '{print $1}')
  pacchetto=$(echo $riga | awk -F';' '{print $2}' | awk -F':' '{print $1}')
  version=$(echo $riga | awk -F';' '{print $2}' | awk -F':' '{print $2}')

  check_lines=$(grep ";$pacchetto:$version" /tmp/appoggio | wc -l)
  if [ $check_lines -eq 1 ]; then
    echo $riga >> /tmp/ritorno
  else
    echo "external;${pacchetto}:${version}" >> /tmp/ritorno
  fi

done
