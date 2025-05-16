#!/bin/bash
# FortiGate Log Analyzer Script
# Author : Cresp0 (Harun Mansor)
# Date   : May 16, 2025

log_file=$1

while getopts 'h' OPTION;do
    case "$OPTION" in
        h)
            echo 'Usage: $0 /path/to/logfile.log'
            exit 0
        ;;
        ?) 
            echo "Invalid option: -$OPTARG"
            echo "Usage: $0 /path/to/logfile.log"
            exit 1
        ;;
    esac
done

if [[ $# -eq 0 ]]; then
    echo "Please use -h to see usage"
    exit 1
fi

#just useless function to display output in colored, boxed format
draw_box() {
    local content="$1"
    local color="$2"  # ANSI color code
    local length=$(echo "$content" | awk '{print length}')
    local border=$(printf '%*s' $((length + 4)) '' | tr ' ' '-')

    echo "+$border+"
    echo -e "|  \033[1;${color}m${content}\033[0m  |"
    echo "+$border+"
    echo ""
}

TODAY=$(date)
USER=$(whoami)

draw_box "F O R T I L Y Z E R" 36  #Cyan
echo "Date : ${TODAY}"
echo "User : ${USER}"
echo ""

if [[ ! -f "$log_file" ]]; then
    draw_box "ERROR: The file does not exist" 31  #Red
    exit 1
fi

echo "Please enter IP addresses authorized to access the network:"
read authorized
echo ""

file_count=$(wc -l < "$log_file")
draw_box "Total lines in log file: $file_count" 34  # Blue

echo "[+] Checking for unauthorized access by other IPs..."
unauthorized=$(grep "$authorized" "$log_file" | wc -l)
if [[ $unauthorized -ne $file_count ]]; then
    draw_box "Unauthorized sessions saved in unauthorized_session.txt!" 31  # Red
    grep -v "$authorized" $log_file > unauthorized_session.txt
    echo "Unauthorized IPs :"
    unauthorized_ip=$(grep -v $authorized $log_file | grep -oP 'srcip=\K[\d\.]+')
    for ip in $unauthorized_ip;do
        echo " - $ip"
    done
else
    draw_box "No unauthorized access detected" 32  # Green
fi

echo ""

# Check for security levels
echo "[+] Checking for sessions with 'critical' & 'warning' security levels..."
warning_seclevel=$(grep 'level="warning"' "$log_file" | wc -l)
critical_seclevel=$(grep 'level="critical"' "$log_file" | wc -l)

if [[ $warning_seclevel -eq 0 && $critical_seclevel -eq 0 ]]; then
    draw_box "No sessions with critical or warning security level" 32  # Green
else 
    if [[ $critical_seclevel -eq 0 ]]; then
        draw_box "Critical sessions: 0" 33  # Yellow
    else
        grep 'level="critical"' "$log_file" > critical_session.txt
        draw_box "$critical_seclevel critical session(s) saved to critical_session.txt" 31  # Red
    fi

    if [[ $warning_seclevel -eq 0 ]]; then
        draw_box "Warning sessions: 0" 33  # Yellow
    else
        grep 'level="warning"' "$log_file" > warning_session.txt
        draw_box "$warning_seclevel warning session(s) saved to warning_session.txt" 33  # Yellow
    fi
fi

echo "[+] Checking for denied logins..."
denied_logins=$(grep 'action="deny"' $log_file | grep 'login')
if [[ -n $denied_logins ]];then
    echo $denied_logins > denied_logins.txt
    draw_box "Denied logins have been saved to denied_logins.txt" 31
else
    draw_box "No denied logins" 32
fi

echo "[+] Checking for SSH logins..."
ssh_logins=$(grep "ssh" $log_file)
#echo $ssh_logins > ssh_logins.txt
if [[ -n $ssh_logins ]];then
    sshlogins_ip=$(echo "$ssh_logins" | grep -oP 'srcip=\K[0-9\.]+' | sort -u)
    for ip in $sshlogins_ip;do
        echo $ssh_logins | grep "srcip=$ip" > ssh_${ip}.txt
        draw_box "$ip SSH sessions saved to ssh_${ip}.txt" 31
    done
else
    draw_box "No SSH logins" 32
fi

echo "[+] Checking for uncommon ports"
common_ports=(80 443 22 21 25 110 53 445 3389 1433)
grep -oP 'dstport=\K\d+' "$log_file" | sort -n | uniq > ports_accessed.txt
while read port;do
    if [[ ! " ${common_ports[@]} " =~ " $port " ]]; then
        echo "$port" >> uncommon_ports.txt
    fi
done < ports_accessed.txt

if [[ -f uncommon_ports.txt ]];then
    draw_box "Uncommon ports accessed saved to uncommon_ports.txt" 31
    echo 'Uncommon ports accessed: '
    cat uncommon_ports.txt
else
    echo 'No uncommon ports accessed '
fi
