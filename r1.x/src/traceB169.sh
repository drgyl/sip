#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
today=$(date +%m/%d/%Y)
pattern1=' bytes)'
pattern2='^FINE.*% $'
pattern3='^% '
pattern4='^INFO|^FINE|^FINER|^FINEST'
pattern5='^Received |^Sent '
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

## TODO: extract syslog messages from PCAP using tshark

function usage ()  {
    echo "traceB169.sh $version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t    created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceB169.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the SIP msg buffer taken from IPDECTSC SIP device\'s WebUI,"
	echo -e "\t\t\tor SYSLOG capture of an IPDECTSC device. SYSLOG can be either extracted from"
	echo -e '\t\t\tWireshark using "Follow UDP stream", or collected by a remote SYSLOG server'
	echo -e "\t\t\tSupported SYSLOG servers: KIWI, Mega, tftpd64"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"			
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution or result of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
	echo -e "Note: IPDECTSC device may log some SIP messages in syslog incomplete (while traceSM can still present it)"
	echo -e "May also set IPdest=0.0.0.0:0 when sending SIP messages over Syslog (could be fixed in later FW releases)"	
#   echo -e 'Note: due to SIP msg split into multiple parts [Part 0X of 0N], do not expect presenting 100% msgs converted.'	
    echo ''
} # usage()

function reset_sipmsg () {
	dirdefined=0
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	sipyear=""
} # reset_sipmsg()

function sip_startmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	siplines=$((siplines+1))
	if [[ $((voutput)) == 1 ]]; then 
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -en "$NL$line" >> "$newfile"
	elif [[ $((voutput)) == 3 ]]; then
		echo -en "$line\x0d$NL" >> "$newfile"
	fi

	sipword=$(echo "$line" | cut -d' ' -f1)
	if [[ $sipword == "SIP/2.0" ]]; then
	   sipword=$(echo "$line" | awk -F"SIP/2.0 " '{print $2}' | tr -d "\r")
	fi
	if [[ $sipwordlist != *$sipword* ]]; then
		sipwordlist="$sipwordlist | $sipword"
	fi
fi
} # sip_startmsg()

function complete_sipmsg () {
if [[ $((sipstart)) != 0 ]]; then	
	sipmsg=$((sipmsg+1))
	
	if [[ $((sipsplit)) != 0 ]]; then
		sipmaxsplit=$((sipmaxsplit+1))
		if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
			sipmaxpart=${maxpart#0}
		fi
		partnum="00"
		maxpart="99"
	fi
	if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then	
		sipmaxlines=$siplines
		longestmsg=$sipmsg
	fi
	
	if [[ $((dirdefined)) == 1 ]]; then	
		sipin=$((sipin+1))
	elif [[ $((dirdefined)) == 2 ]]; then
		sipout=$((sipout+1))
	fi

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile.b64" ]]; then
		base64 -d "$newfile.b64" >> "$newfile"
		blines=$(base64 -d "$newfile.b64" | wc -l)
		siplines=$((siplines+$blines))
		rm "$newfile.b64"
		base64found=0
		base64msg=$((base64msg+1))
	fi

	if [[ $((voutput)) == 1 ]]; then
		echo -e "[$sipstream] }\x0d$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -e "$NL}$NL" >> "$newfile"
	elif [[ $((voutput)) == 3 ]]; then
		echo -e "--------------------" >> "$newfile"
	fi

	reset_sipmsg
fi
} # complete_sipmsg()

function sipmsg_header () {
	if [[ $((dirdefined)) != 0 ]]; then
		n=$((n+1))
		sipstart=0
		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$var => $n/$rec Msgs converted            \r"
		fi
		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} # sipmsg_header() 

function sip_partnum () {
	if [[ $line == *"[Part "* ]]; then
		partnum=$(echo "$line"     | awk -F "Part " '{print $2}' | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
			maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | awk '{print $3}' | cut -d']' -f1)   # awk -F ']' '{print $1}')
			# maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d' ' -f3)
		fi	
		sipsplit=1
	fi
} # sip_partnum()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line == *"Received "* ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70
		dirdefined=1
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="RECEIVED"
			dirstring2="from"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="RECEIVED"
			dirstring2="from"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="<--"
			dirstring2="egress"			
#			dirstring1="-->"
#			dirstring2="ingress"
		fi		
	elif [[ $line == *"Sent "* ]]; then
		## elif [[ $direction == 'Outbound' ]]; then
		sipstream=1474
		dirdefined=2
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="SENT"
			dirstring2="to"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="SENDING"
			dirstring2="to"
		elif [[ $((voutput)) == 3 ]]; then
#			dirstring1="<--"
#			dirstring2="egress"			
			dirstring1="-->"
			dirstring2="ingress"
		fi
	fi
		##ip=$(echo $line | awk '{print $5}')

#	if [[ $((dirdefined)) != 0 ]]; then
	if [[ $((vsyslog)) == 10 ]]; then        			# ade_ipdect_SipDebug1.txt (native SIP buffer)
		ip1=$(echo "$line" | cut -d' ' -f3)				# Received from tcp:8.33.237.43:5060 at 08/10/2019 10:34:26  (431 bytes)
		ip2=$(echo $ip1    | cut -d':' -f3)
		ip1=$(echo $ip1    | cut -d':' -f2)
		ip="$ip1:$ip2"
		siplength=$(echo "$line" | cut -d'(' -f2 | cut -d' ' -f1)
#		localip="1.1.1.1:1111"			
	elif [[ $((vsyslog)) == 11 ]]; then      			# ade_ipdect_syslog_traces.txt (UDP stream from wireshark)
        if [[ $line == *"Sky 00000 -[SIP"* ]]; then		# ade_ipdect_syslog_traces.txt
# <133>1 2018-08-04T15:14:42Z 10.16.12.46 00087b132e32 Sky 00000 -[SIP message Sent to tcp:0.0.0.0:0 at 04/08/2018 15:14:42  (1336 bytes)
		   ip1=$(echo "$line" | cut -d' ' -f10)  		# awk '{print $11}')
		else # ade_ipdectsc_syslog1.txt - there is no MSEC after "Sky 00000" !!!
# <133>1 2018-12-22T14:48:21Z 10.16.12.68 00087b14fa3a Sky 00000 00343 -[SIP message Sent to tcp:10.16.26.88:5060 at 22/12/2018 14:48:21  (568 bytes)
		   ip1=$(echo "$line" | cut -d' ' -f11) 		# awk '{print $11}')			
        fi
	    ip2=$(echo $ip1 | cut -d':' -f3)
	    ip1=$(echo $ip1 | cut -d':' -f2)
	    ip="$ip1:$ip2"
		if [[ $((dirdefined)) == 2 ]] && [[ $ip == "0.0.0.0:0" ]] && [[ $foundipaddr != "" ]]; then
		   ip=$foundipaddr
		fi
	    siplength=$(echo "$line" | cut -d'(' -f2 | cut -d' ' -f1)	
        localip=$(echo "$line"   | cut -d' ' -f2)
		localip="$localip:1111"
#		localip=$ip1:$ip2
	elif [[ $((vsyslog)) == 12 ]]; then     			  # ade_ipdect_SyslogCatchAll1.txt (KIWI syslog)
# 2018-08-04 14:25:28	Local0.Notice	10.16.12.46	1 2018-08-04T15:14:42Z 10.16.12.46 00087b132e32 Sky 00000 -[SIP message Sent to tcp:0.0.0.0:0 at 04/08/2018 15:14:42  (1336 bytes)
        if [[ $line == *"Sky 00000 -[SIP"* ]]; then 
		   ip1=$(echo "$line" | cut -d' ' -f15)  		  # awk '{print $11}')
		else
		   ip1=$(echo "$line" | cut -d' ' -f16)			  # awk '{print $11}')
		fi
		ip2=$(echo $ip1  | cut -d':' -f3)
		ip1=$(echo $ip1  | cut -d':' -f2)
		ip="$ip1:$ip2"
#		if [[ $((dirdefined)) == 2 ]] && [[ $ip == "0.0.0.0:0" ]] && [[ $foundipaddr != "" ]]; then
#		   ip=$foundipaddr
#		fi
		siplength=$(echo $line | cut -d'(' -f2 | cut -d' ' -f1)					
        localip=$(echo $line | cut -d' ' -f4)
        localip="$localip:1111"		
	elif [[ $((vsyslog)) == 13 ]]; then     			  # PCAP extracted: continous_ringing_V480B2_Nov\ 08th.pcapng.syslog3
# LOCAL0.NOTICE: 1 2019-11-08T09:03:30Z 10.16.12.68 00087b14fa3a Sky 00000 03943 -[SIP message Received from tcp:10.128.196.226:5060 at 08/11/2019 09:03:30  (343 bytes)\n\nSIP/2.0 100 Trying\r\nVia: SIP/2.0/TCP 1
# 1 2019-11-08T09:03:30Z 10.16.12.68 00087b14fa3a Sky 00000 03920 -[SIP message Sent to tcp:10.128.196.226:5060 at 08/11/2019 09:03:30  (1042 bytes)\n\nINVITE sip:2701@10.128.196.226
        if [[ $line == *"Sky 00000 -[SIP"* ]]; then 
		   ip1=$(echo "$line" | cut -d' ' -f11)  		  # awk '{print $11}')
		else
		   ip1=$(echo "$line" | cut -d' ' -f12)			  # awk '{print $11}')
		fi
		ip2=$(echo $ip1  | cut -d':' -f3)
		ip1=$(echo $ip1  | cut -d':' -f2)
		ip="$ip1:$ip2"		
#		if [[ $ip == "0.0.0.0:0" ]] && [[ $foundipaddr != "" ]]; then
#		   ip=$foundipaddr
#		fi
		siplength=$(echo $line | cut -d'(' -f2 | cut -d' ' -f1)					
        localip=$(echo $line | cut -d' ' -f4)
        localip="$localip:1111"		

	elif [[ $((vsyslog)) == 111 ]]; then    			# ???
 		ip="6.6.6.6:6666"  								# ip=$(echo $line | cut -d' ' -f20)
		siplength="666"									# siplength=$(echo $line | cut -d' ' -f17)
	fi
fi	
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # sip_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 10 ]]; then 						# Native IPDECT log buffer - no msec value provided, using "000" instead
		foundipaddr=$(echo $line | cut -d' ' -f5)
		sipyear=$(echo "$line"   | cut -d' ' -f5)			# Sent to tcp:8.33.237.43:5060 at 08/10/2019 10:34:27  (482 bytes)
		sipday=$(echo $sipyear   | cut -d'/' -f1)
		sipmonth=$(echo $sipyear | cut -d'/' -f2)
		sipyear=$(echo $sipyear  | cut -d'/' -f3)

		sipmsec=$(echo "$line"  | cut -d' ' -f6) 
		siphour=$(echo $sipmsec | cut -d':' -f1)
		sipmin=$(echo $sipmsec  | cut -d':' -f2)
		sipsec=$(echo $sipmsec  | cut -d':' -f3)
		sipmsec="000"

	elif [[ $((vsyslog)) == 11 ]]; then  ## Wireshark Syslog from UDP stream	??
	    if [[ $line == *"Sky 00000 -[SIP"* ]]; then 
		   sipyear=$(echo "$line"  | cut -d' ' -f12)     			 # awk '{print $13}')
		   sipsec=$(echo "$line"   | cut -d' ' -f13)     			 # awk '{print $14}')
		   sipmsec="000"
		else
		   sipyear=$(echo "$line"  | cut -d' ' -f13)      			 # awk '{print $14}')
		   sipsec=$(echo "$line"   | cut -d' ' -f14)      			 # awk '{print $15}')
           sipmsec=$(echo "$line"  | awk '{printf "%03i",$7}')
#		   if [[ $((sipmsec)) -lt 10 ]]; then
#			  sipmsec="00$((sipmsec))"
#		   elif [[ $((sipmsec)) -lt 100 ]]; then
#			  sipmsec="0$((sipmsec))"
#		   fi			
		fi

		sipday=$(echo $sipyear   | cut -d'/' -f1)
		sipmonth=$(echo $sipyear | cut -d'/' -f2)
		sipyear=$(echo $sipyear  | cut -d'/' -f3)
		
		siphour=$(echo $sipsec | cut -d':' -f1)
		sipmin=$(echo $sipsec  | cut -d':' -f2)
		sipsec=$(echo $sipsec  | cut -d':' -f3)		
		
	elif [[ $((vsyslog)) == 12 ]]; then  							   # KIWI syslog					
		## convtime=$(echo $line | awk '{print $10}')
		## siptime=${convtime//./:}  ## replace "." with ":"
	    if [[ $line == *"Sky 00000 -[SIP"* ]]; then 
		   sipyear=$(echo "$line" | cut -d' ' -f17)    				   # awk '{print $13}')
		   sipsec=$(echo "$line"  | cut -d' ' -f18)    				   # awk '{print $14}')
		   sipmsec="000"
		else
		   sipyear=$(echo "$line" | cut -d' ' -f18)    				   # awk '{print $14}')
		   sipsec=$(echo "$line"  | cut -d' ' -f19)     			   # awk '{print $15}')
           sipmsec=$(echo "$line" | awk '{printf "%03i",$8/10}')
		fi

		sipday=$(echo $sipyear   | cut -d'/' -f1)
		sipmonth=$(echo $sipyear | cut -d'/' -f2)
		sipyear=$(echo $sipyear  | cut -d'/' -f3)
		
		siphour=$(echo $sipsec | cut -d':' -f1)
		sipmin=$(echo $sipsec  | cut -d':' -f2)
		sipsec=$(echo $sipsec  | cut -d':' -f3)
				
#		siptmp=$(echo $line    | cut -d' ' -f10)  # awk '{print $10}')
#		tzhour=$(echo $siptmp  | cut -d':' -f1)   # awk -F ':' '{print $1}')  	# adjusting only the hour value based on TZ
#		tzmin=$(echo $siptmp   | cut -d':' -f2)   # awk -F ':' '{print $2}')

		## ip=$(echo $line | awk '{print $NF}')
	elif [[ $((vsyslog)) == 13 ]]; then  							   # PCAP syslog, extracted via tshark
# LOCAL0.NOTICE: 1 2019-11-08T09:03:30Z 10.16.12.68 00087b14fa3a Sky 00000 03943 -[SIP message Received from tcp:10.128.196.226:5060 at 08/11/2019 09:03:30  (343 bytes)\n\nSIP/2.0 100 Trying\r\nVia: SIP/2.0/TCP 1
# 1 2019-11-08T09:03:30Z 10.16.12.68 00087b14fa3a Sky 00000 03920 -[SIP message Sent to tcp:10.128.196.226:5060 at 08/11/2019 09:03:30  (1042 bytes)\n\nINVITE sip:2701@10.128.196.226
	    if [[ $line == *"Sky 00000 -[SIP"* ]]; then 
		   sipyear=$(echo "$line" | cut -d' ' -f13)    				   # awk '{print $13}')
		   sipsec=$(echo "$line"  | cut -d' ' -f14)    				   # awk '{print $14}')
		   sipmsec="000"
		else
		   sipyear=$(echo "$line" | cut -d' ' -f14)    				   # awk '{print $14}')
		   sipsec=$(echo "$line"  | cut -d' ' -f15)     			   # awk '{print $15}')
           sipmsec=$(echo "$line" | awk '{printf "%03i",$7/10}')
		fi

		sipday=$(echo $sipyear   | cut -d'/' -f1)
		sipmonth=$(echo $sipyear | cut -d'/' -f2)
		sipyear=$(echo $sipyear  | cut -d'/' -f3)
		
		siphour=$(echo $sipsec | cut -d':' -f1)
		sipmin=$(echo $sipsec  | cut -d':' -f2)
		sipsec=$(echo $sipsec  | cut -d':' -f3)
	fi

	if [[ $((adjusthour)) == 1 ]]; then
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') 	# TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) 										# TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) 											# TODO need to print 2 digits
		fi
	fi

	if [[ $((voutput)) == 1 ]]; then
		sipdate=$(echo $sipmonth/$sipday/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec)		
	elif [[ $((voutput)) == 2 ]]; then
		sipdate=$(echo $sipyear/$sipmonth/$sipday)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec)		
	elif [[ $((voutput)) == 3 ]]; then
		sipdate=$(echo $sipday/$sipmonth/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec.$sipmsec)		
	fi
} # get_sip_datetime()

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbf:s" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	e)  
	    endptaddr=${OPTARG};;
    :)
		echo -e "error: -${OPTARG} requires an argument.$NL"
		usage
		exit 0;;
	*)
		echo -e "error: -${OPTARG} is an unknown option.$NL"
		usage
		exit 0;;
	esac
  done
fi

skipper=0

base64 --version >/dev/null
if [[ $((base64decode)) != 0 ]]; then
   base64 --version >/dev/null
   if [[ $? != 0 ]]; then
	  base64decode=0
   fi
fi

for var in "$@"
	do
	
	if [[ $var == "-"* ]]; then
  		if [[ $var == "-f"* ]]; then
			skipper=1
		elif [[ $var == "-e"* ]]; then
		    skipper=2
		else
			skipper=0
		fi
		continue
	elif [[ $skipper != 0 ]]; then
	    if [[ $((skipper)) == 2 ]]; then
		   endptaddr=$var
		else		
		   voutput=$var
		   if [[ $((voutput)) -lt 1 ]] || [[ $((voutput)) -gt 3 ]]; then
			  voutput=1
		   fi
		fi
		skipper=0
		continue
	fi

	file=$var
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0
	tmpfile=
	outfile=""

	if [ -f "$file" ]; then
	    echo -en "Exploring content in $var... stand by\r"

		filetype=$(file -b "$file")
		filecontent="ACDC"

		if [[ $filetype == *"capture"* ]]; then
			if [[ $filetype == *"tcpdump"* ]] || [[ $filetype == *"pcap"* ]]; then
		  		line=$(whereis tshark)

				if [[ ${#line} -gt 10 ]]; then
					if [[ $endptaddr != "" ]]; then
				    	tshark -r $file -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else
		    		    tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi
					sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
#					sed 's/[[:blank:]]\[truncated\]//' < "$file.syslog2" | sed 's/^Syslog message:\ //' > "$file.syslog3"
					outfile="$file"
					rm "$file.syslog2"
					file="$file.syslog"
					filecontent="syslog"
					tmpfile=1
#					vsyslog=13
		      	else
		     		echo "error: unable to locate 'tshark' command."
					echo "'tshark' is required to extract syslog messages from $var wireshark capture into text file"
					echo ''
					error=10; # exit $error
					continue
				fi
			fi
		else
			outfile=$var
		fi

		rec=$(egrep -c "\[SIP message " "$file")

		if [[ $rec == 0 ]];	then
			rec=$(egrep -c "^Sent\ |^Received\ " "$file")
			if [[ $rec == 0 ]];	then
		        echo "error: $var file is empty - no TX/RX SIP messages found."
  			    rec=$(egrep -c -e "^CSeq:*" "$file")
				error=1
			    if [[ $rec == 0 ]]; then
				    echo 'In fact, no sign of any "CSeq:" lines in '$var
					error=2
			    else
				    echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages in '$var				
				    rec=0
				fi
				echo "Verify source and content of $var"
				echo ''; continue
			else				
				vsyslog=10
			fi
		else
		    pattern1='\[SIP message '
			line=$(egrep -m 1 -e "\[SIP message" "$file")
			if [[ $line =~ Local[0-9]\. ]]; then 								# KIWI syslog
              	vsyslog=12
			elif [[ $line =~ \<1[3567][0-9]\> ]]; then  						# Wireshark syslog UDP stream (manually)
			   	vsyslog=11
			elif [[ $line =~ ^1\ .*SIP\ message* ]]; then  						# Wireshark syslog UDP stream (manually)
			   	vsyslog=13			   				   
			fi
			line=""
		fi

		if [[ $rec != 0 ]] && [[ $((vsyslog)) != 0 ]]; then
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			prevline=""
			partnum="00"
			maxpart="99"
			nlines=0
			sipmonth=""
			sipday=""
			siphour=""
			sipmin=""
			sipsec=""
			sipmsec=""
			n=0
			sipmsg=0
			siptotalmsg=0
			sipmaxlines=0
			sipmaxpart=0
			sipmaxsplit=0
		    sipwordlist=""									
			longestmsg=0			
			sipin=0
			sipout=0
	
	        reset_sipmsg

			##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
			if [[ $((vsyslog)) != 10  ]]; then	
#				conv=$(awk -e '/\[SIP message /{flag=1} flag; /}/{flag=0}' "$file")
				conv=$(awk -W source='/\[SIP message /{flag=1} flag; /}/{flag=0}' "$file")
			else
#    	    	conv=$(awk -e '/ bytes)/{flag=1} flag; /}/{flag=0}' "$file")
    	    	conv=$(awk -W source='/ bytes)/{flag=1} flag; /}/{flag=0}' "$file")
			fi

			check=$(egrep -e "<1[3567][34567]>" < "$file" | wc -l)
			if [[ $((vsyslog)) == 11 ]] && [[ $((check)) == 0 ]]; then
				echo "ALERT: expecting SYSLOG extracted from Wireshark but did not find any lines with <13X>/<166> pattern."
				echo "Could $var be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
				echo "Verify content of input file and/or launch parameters of this tool. Also refer to Usage screen. ABORTing..."
				exit 0
#			elif [[ $((vsyslog)) != 11 ]] && [[ $((check)) != 0 ]]; then
#				echo "ALERT: expecting ANDROID: and D/DeskPhoneServiceAdaptor lines but instead found some lines with <166> pattern."
#				echo "Could $file be a SYSLOG extracted from Wireshark instead of vantage.log from a K1xx debugreport?"
#				echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
#				exit 0
			fi
		
			if [[ $outfile != "" ]]; then
				newfile="$outfile.asm.tmp"
			else
				newfile="$file.asm.tmp"
			fi
			if [ -f "$newfile" ]; then
				rm "$newfile"
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

		    if [[ $var != $file ]]; then
			    echo -e "# Input file: $var --> $file -> $outfile.asm\n" >> "$newfile"
		    else 
			    echo -e "# Input file: $var -> $var.asm\n" >> "$newfile"
		    fi

			while IFS= read -r line
			do
				linelength=$(echo "$line" | wc -c)
				linelength=${#line}
				nlines=$((nlines+1))

				if [[ $((vsyslog)) == 10 ]]; then 
					if [[ $line == *" bytes)"* ]]; then
						if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then	
							reset_sipmsg; continue							
						elif [[ $((sipstart)) == 1 ]]; then
							complete_sipmsg
						fi
						siptotalmsg=$((siptotalmsg+1))	
						base64found=0
						get_sip_datetime
						sip_direction
						sipmsg_header
					elif [[ $((sipstart)) == 0 ]]; then
						if [[ ${#line} -gt 1 ]]; then
							sip_startmsg
						fi
					elif [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then
						base64found=1
						echo "# Base64 dump found" >> "$newfile"
						if [[ -f "$newfile.b64" ]]; then
							rm "$newfile.b64"
						fi
					elif [[ $((base64found)) != 0 ]]; then
							echo "$line" >> "$newfile.b64"
					else 
						echo "$line" >> "$newfile"
						siplines=$((siplines+1))
						get_useragent
					fi
				elif [[ $((vsyslog)) -gt 10 ]]; then						# 11, 12, 13
#				elif [[ $((vsyslog)) == 11 ]] || [[ $((vsyslog)) == 12 ]]; then
				    if [[ $((vsyslog)) == 11 ]] && [[ $line =~ $pattern1 ]]; then
					    line=$(echo "$line" | awk -F '] <1[3567][0-9]>1 ' '{print $NF}')
				    fi
					if [[ $line == *" Sky 00000 "* ]] && [[ $((sipstart)) != 0 ]]; then
						complete_sipmsg
					elif [[ $((vsyslog)) == 12 ]] && [[ $((linelength)) == 4 ]] && [[ $line == *"] "* ]]; then
					   if [[ $line == *"] "* ]]; then
					      complete_sipmsg
					   fi
					fi
					if [[ $line == *"[SIP message "* ]]; then
						if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then	
							reset_sipmsg; continue
						fi
						siptotalmsg=$((siptotalmsg+1))	
						base64found=0
						get_sip_datetime
						sip_direction
						sipmsg_header

					elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
						if [[ ${#line} -gt 1 ]]; then
							sip_startmsg
						fi
					elif [[ $((sipstart)) != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then
							base64found=1
							echo "# Base64 dump found" >> "$newfile"
							if [[ -f "$newfile.b64" ]]; then
								rm "$newfile.b64"
							fi
						elif [[ $((base64found)) != 0 ]]; then
							echo "$line" >> "$newfile.b64"
						else 
							if [[ $((vsyslog)) == 12 ]]; then
								echo -e "$line\x0d" >> "$newfile"
							else
								echo "$line" >> "$newfile"
							fi

							siplines=$((siplines+1))
							get_useragent
						fi
					fi
				fi
			done <<< "$conv"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $outfile == "" ]]; then
			outfile=$var
		fi

        if [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $outfile.asm file"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $var file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    have been converted for addr=$endptaddr into $outfile.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				echo -e "$NL\tUser-Agent: $useragent"
				if [[ $foundipaddr != "" ]]; then
					echo -e "\tusing ipaddr = $foundipaddr"
				fi
			fi

			echo -e "\tTotal # of lines digested:\t\t\t $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg"
				echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg" >> "$newfile"
				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
				fi
			fi		
		fi

		echo '' >> "$newfile"
	    if [[ $sipwordlist != "" ]]; then
		   echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
	    fi
		echo ''
		echo -e "\tTask started: $currtime - completed: $(date +%R:%S)"
		echo ''

		if [ -f "$outfile.asm" ]; then
			mv "$outfile.asm" "$outfile.asm.bak"
		fi
		mv "$newfile" "$outfile.asm"
		pwd;ls -l "$outfile.asm"
		if [[ $tmpfile == 1 ]] && [[ $file != $var ]]; then
			rm "$file"
		fi
		echo ''
	fi
else
	echo "error: file $var was not found."
	echo ''	
	error=3
fi
done