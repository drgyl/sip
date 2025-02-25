#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
sipstat=1
enckey=""
alllogs=0
noINFO=0
adjusthour=0
localtime=1
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

# TODO: ANB missing IP port + missing YEAR + locatime vs syslog time

# 2) EndpointLog.txt, SparkEmulator
# <166>Nov 17 14:25:18 192.168.7.112 SIPMESSAGE: +02:00 2020 463 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061
# 2) pcap syslog
# 166>Apr 27 09:07:11 172.16.55.213 SIPMESSAGE: +02:00 2021 798 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 172.16.51.139:5061

# 8) tftpf64 syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

# 9) interactive syslog viewer - ALERT: export will save logs reverse order - crap
# INFO	LOCAL4	1/25/2022 4:32:48 PM	192.168.7.113		SIPMESSAGE: +01:00 2022 622 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061 TX SIP/2.0 200 OK

# vsyslog:
# DEBUG	LOCAL4	2/11/2022 4:28:37 PM	135.105.129.244		SIPMESSAGE: +01:00 2022 361 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061

# visual syslog
# 135.105.167.18	Jan 25 16:52:13	192.168.7.113	local4	info	SIPMESSAGE	+01:00 2022 513 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 135.64.253.72 port: 5061 RX SIP/2.0 100 Trying Call-ID: 19_26df340f2d5f91f03v1p522u5m1q1a60k1s315x_I1100 CSeq: 25 INVITE From: <sips:1100@vsip.com>;tag=26df340f-612f6bfb446j2a5a1f5262382o44o3u_F1100 To: <sips:1100@vsip.com;avaya-cm-fnu=off-hook> Via: SIP/2.0/TLS 135.105.167.18:1025;alias;branch=z9hG4bK19_26df340f-7294205d2y2u6515s3c302g1w1d6ab_I1100;keep Content-Length: 0   

# 10) avaya_phone.log
# Jul 29 06:39:11 ANB[779 MSM]:<167>Jul 29 08:38:57 10.11.10.90 SIPMESSAGE: +02:00 2022 319 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 10.11.10.205:5061 TX REGISTER sips:sip.intranet.geiger.de 

# 11) SIP7.1.15 pcap syslog
# Sep 30 08:14:20 135.124.167.102 SIPMESSAGE: +01:00 2022 912 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061\nTX INVITE sip:1111@vsip.com;avaya-cm-fnu=off-hook SIP/2.0\r\nFrom: <sip:1111@vsip.com>;tag=6336974c655526cd4h5w1y5n3h6k4y2j5e472m6w_F1111\r\nTo: <sip:1111@vsip.com;avaya-cm-fnu=off-hook>\r\nCall-ID: d_6336974cad4f69d2l6ka5o5c6o5tz394i6t39_I1111\r\nCSeq: 13 INVITE\r\nMax-Forwards: 70\r\nVia: SIP/2.0/TLS 135.124.167.102:22606;alias;branch=z9hG4bKd_6336974c-c52b94f10k4u4ym2i3x514i1t6e4d_I1111\r\nSupported: 100rel,eventlist,feature-ref,replaces,sdp-anat,tdialog\r\nAllow: INVITE,ACK,BYE,CANCEL,SUBSCRIBE,NOTIFY,MESSAGE,REFER,INFO,PRACK,PUBLISH,UPDATE\r\nUser-Agent: Avaya one-X Deskphone 7.1.15.1.3 b4475ea2e9a0\r\nContact: <sip:1111@135.124.167.102:22606;transport=tls>;+avaya-cm-line=1\r\nAccept-Language: en\r\nExpires: 30\r\nContent-Length: 0\r\n\r\n\n

# MEGA syslog
# 2022-02-11 16:48:54	20	7	1	135.105.129.244				Feb 11 16:48:52 135.105.129.244 SIPMESSAGE: +01:00 2022 369 1 .TEL | 0 [Part 01 of 02]				

# 20) KIWI syslog
# 2022-02-11 17:33:11	Local4.Debug	135.105.129.244	Feb 11 16:33:09 135.105.129.244 SIPMESSAGE: +01:00 2022 653 1 .TEL | 0 [Part 01 of 02]<010>CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061<010>TX 

function usage ()  {
    echo "trace96xx.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: trace96xx.sh [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis an EndpointLog.txt or avaya_phone.log or phonereport taken from either"
	echo -e "\t\t\t96x1SIP, J1xxSIP, SparkEmulator, VDIC or H175 (EndpointLog_B+sig_CPS.txt)"
	echo -e "\t\t\tor, it can also be a syslog stream sent by these clients captured"
	echo -e "\t\t\teither via a remote SYSLOG server (refer to doc) or via wireshark tool."
	echo -e "\t\t\tSyslog can be also extracted manually from pcap using \"Follow UDP stream\" function."
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: \"a.b.c.d\""
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-I:\t\tignore all SIP INFO messages (used in sharedcontrol session)"
#	echo -e "\t-i ipaddr:\tconvert syslog messages only sent by SM IP addr: a.b.c.d"	
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-A:\t\tconvert all log files in logreport where any SIP msg were found (avaya_phone.logX)"		
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	partnum="00"
	maxpart="99"
	currpartnum="555"
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	dirdefined=0	
	emptyline=0
	badmsg=0
	foundipaddr=""
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then
	sipstart=1
	siplines=$((siplines+1))
	if [[ $((voutput)) == 1 ]]; then 
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -en "$NL$line$NL" >> "$newfile"	
	elif [[ $((voutput)) == 3 ]]; then
		echo -en "$line\x0d$NL" >> "$newfile"
	fi

	sipword=$(echo "$line" | cut -d' ' -f1)
	if [[ $sipword == "SIP/2.0" ]]; then
	   sipword=$(echo "$line" | awk -F"SIP/2.0 " '{print $2}' | tr -d '\r')
	fi
	if [[ $sipwordlist != *$sipword* ]]; then
		sipwordlist="$sipwordlist | $sipword"
	fi
fi	
} # start_sipmsg()

function complete_sipmsg () {
if [[ $((sipstart)) != 0 ]]; then
	sipmsg=$((sipmsg+1))
	if [[ $siptimeprev != "" ]]; then
		if [[ $siptime < $siptimeprev ]]; then
			sipbadtime=$((sipbadtime+1))
			if [[ $sipbadtimemsg == "" ]]; then
				sipbadtimemsg="$sipmsg $siptimeprev $siptime"
			fi
		fi
	fi
	siptimeprev=$siptime

	if [[ $((sipsplit)) != 0 ]]; then
		sipmaxsplit=$((sipmaxsplit+1))
		splitparts=$((splitparts+10#$maxpart-1))			
		if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
			sipmaxpart=${maxpart#0}
			sipmaxpartmsg=$sipmsg
		fi
		if [[ $partnum != $maxpart ]]; then
			badmsg=1
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
		fi
#		partnum="00"
#		maxpart="99"
	elif [[ $partnum != "00" ]]; then
		echo -e "error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime"
	fi

	if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then	
		sipmaxlines=$siplines
		longestmsg=$sipmsg		
	fi

	if [[ $((dirdefined)) == 1 ]]; then	
		sipin=$((sipin+1))
		if [[ $((sipsplit)) != 0 ]]; then
			splitin=$((splitin+1))
		fi
	else
		sipout=$((sipout+1))
		if [[ $((sipsplit)) != 0 ]]; then
			splitout=$((splitout+1))
		fi
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

	if [[ $((badmsg)) != 0 ]]; then
		echo -e "# This is a BAD message\n" >> "$newfile"
		sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadmsgnum == "" ]]; then
			sipbadmsgnum="$siptotalmsg $siptime"
		fi
	fi

	lastfoundip=$foundipaddr
	reset_sipmsg
fi	
} # complete_sipmsg()

function sipmsg_header () {
if [[ $foundipddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
	reset_sipmsg
else	
	n=$((n+1))
	sipstart=0
	if [[ $((sipstat)) != 0 ]]; then		
		echo -en "$var => $n/$rec Msgs converted            \r"
	fi

	if [[ $((sipsplit)) != 0 ]]; then
		echo -e "# msgno: $((sipmsg+1)) (split)" >> "$newfile"
	else
		echo -e "# msgno: $((sipmsg+1))" >> "$newfile"
	fi

	if [[ $((voutput)) == 1 ]]; then
		echo -e "[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -e "[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
	elif [[ $((voutput)) == 3 ]]; then
		echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
	fi
fi	
} # sipmsg_header()

function sip_partnum () {
	if [[ $line =~ \[Part\  ]]; then
		currpartnum=$partnum	
		partline=$(echo "$line"    | awk -F "Part " '{print $2}')
		partnum=$(echo "$partline" | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
#		if [[ $partnum == "01" ]] && [[ $((sipsplit)) == 0 ]]; then
#			if [[ $((sipsplit)) != 0 ]]; then			# existing split SIP msg, but it starts with 01 - could be BAD
#				currpartnum="661"
#			fi
			maxpart=$(echo "$partline" | awk '{printf "%02i",$3}')
		elif [[ $currpartnum == "00" ]]; then										# new SIP msg split, but does not start with 01 - BAD
			currpartnum="660"
		elif [[ ${partnum#0} != $((${currpartnum#0}+1)) ]]; then
			currpartnum="663"
		elif [[ ${partnum#0} -gt ${maxpart#0} ]]; then
			currpartnum="666"			
		fi
		sipsplit=1
	else
		currpartnum="555"		
	fi
} # sip_partnum()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then
	if [[ $line == *"Inbound SIP"* ]] || [[ $line == *" <- "* ]]; then
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
			dirstring1="-->"
			dirstring2="ingress"
		fi

	elif [[ $line == *"Outbound SIP"* ]] || [[ $line == *" -> "* ]]; then
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
			dirstring1="<--"
			dirstring2="egress"			
		fi
	fi

	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $foundipaddr == "" ]]; then
			if [[ $((vsyslog)) == 10 ]]; then
				foundipaddr=$(echo "$line" | cut -d' ' -f1)
				localip="$foundipaddr:1111"
			elif [[ $((vsyslog)) == 9 ]]; then
				foundipaddr=$(echo "$line" | cut -d' ' -f6)
				localip="$foundipaddr:1111"				
			else
				foundipaddr=$(echo "$line" | awk '{print $4}')
				localip="$foundipaddr:1111"
			fi
		fi

		if [[ $((vsyslog)) == 1 ]]; then
			if [[ $line == *"port:"* ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f3)
				ip2=$(echo "$ip"  | awk '{printf "%i",$5}')
				ip=$ip1:$ip2
			else
				ip=$(echo "$line" | awk '{print $NF}')
				ip1=$(echo $ip | cut -d':' -f1)
				ip2=$(echo $ip | awk -F":" '{printf "%i",$2}')
				ip=$ip1:$ip2
			fi
		
		elif [[ $((vsyslog)) == 2 ]] || [[ $((vsyslog)) == 3 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from ip = " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f1)
				ip2=$(echo "$ip"  | awk '{printf "%i",$3}')				# cut -d' ' -f3  | tr -d "\n")
				ip=$ip1:$ip2
			else
				ip=$(echo "$line" | awk '{print $NF}')
				ip1=$(echo "$ip"  | cut -d':' -f1)
				ip2=$(echo "$ip"  | awk -F":" '{printf "%i",$2}')	#cut -d':' -f2  | tr -d "\n")
				ip=$ip1:$ip2					
			fi
		elif [[ $((vsyslog)) == 6 ]]; then
# DEBUG	LOCAL4	2/11/2022 4:28:37 PM	135.105.129.244		SIPMESSAGE: +01:00 2022 065 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 10.134.117.194 port: 5061
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from ip = " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f1)
				ip2=$(echo "$ip"  | awk '{printf "%i",$3}')			# cut -d' ' -f3 | tr -d "\n")
				ip=$ip1:$ip2					
			else 
				ip=$(echo "$line" | awk '{print $NF}')
				ip1=$(echo "$ip"  | cut -d':' -f1)
				ip2=$(echo "$ip"  | awk -F":" '{printf "%i",$2}')
				ip=$ip1:$ip2
			fi

		elif [[ $((vsyslog)) == 7 ]]; then
# 2022-02-11 16:48:54	20	7	1	135.105.129.244				Feb 11 16:48:52 135.105.129.244 SIPMESSAGE: +01:00 2022 695 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 10.134.117.194 port: 5061				
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from ip = " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f1)
				ip2=$(echo "$ip"  | awk '{printf "%i",$3}')			# cut -d' ' -f3 | tr -d "\n")
				ip=$ip1:$ip2
			else 
				ip=$(echo "$line" | awk '{print $(NF-1)}')
				ip1=$(echo "$ip"  | cut -d':' -f1)
				ip2=$(echo "$ip"  | awk -F":" '{printf "%i",$2}')
				ip=$ip1:$ip2					
			fi

		elif [[ $((vsyslog)) == 8 ]]; then
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061		
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from ip = " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f1)
				ip2=$(echo "$ip"  | awk '{printf "%i",$3}')
				ip=$ip1:$ip2					
			else 
#				ip=$(echo "$line" | awk '{print $NF}' | tr -d "\n")		 # TODO: strip off ^M from the end (if any)				
				ip=$(echo "$line" | awk '{print $NF}')
				ip1=$(echo "$ip"  | cut -d':' -f1)
				ip2=$(echo "$ip"  | awk -F":" '{printf "%i",$2}')
				ip=$ip1:$ip2					
			fi

		elif [[ $((vsyslog)) == 9 ]]; then
			if [[ $line == *"port:"* ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f3)
				ip2=$(echo "$ip"  | awk '{printf "%i,$5}')
				ip=$ip1:$ip2
			else
				ip=$(echo "$line" | awk '{print $NF}')
				ip1=$(echo $ip | cut -d':' -f1)
				ip2=$(echo $ip | awk -F":" '{printf "%i",$2}')
				ip=$ip1:$ip2
			fi
		elif [[ $((vsyslog)) == 10 ]]; then
			ip1=$(echo $line | awk '{printf "%i",$3}')			# cut -d' ' -f3 | tr -d "\r")	# TODO: ANB missing port
			ip="$ip1:5061"

		elif [[ $((vsyslog)) == 20 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(echo "$line" | awk -F" from ip = " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f1)
				ip2=$(echo "$ip"  | awk '{printf "%i",$3}')			#cut -d' ' -f3 | tr -d "\n")
				ip=$ip1:$ip2
			elif [[ $line == *"bound SIP message "* ]]; then
				ip=$(echo "$line" | awk '{print $NF}')
				ip1=$(echo $ip | cut -d':' -f1)
				ip2=$(echo $ip | awk -F":" '{printf "%i",$2}')
				ip=$ip1:$ip2
			else
				ip=""
				echo "error: could not determine IP address in sip_direction() for msg#$n at $siptime"
			fi
		fi
	fi
fi
} # sip_direction()

function get_sipmonth () {
	sipmonth="666"	
	case $month in
 	"Jan") sipmonth="01";;
 	"Feb") sipmonth="02";;
 	"Mar") sipmonth="03";;
 	"Apr") sipmonth="04";;
 	"May") sipmonth="05";;
 	"Jun") sipmonth="06";;
 	"Jul") sipmonth="07";;
 	"Aug") sipmonth="08";;
 	"Sep") sipmonth="09";;
 	"Oct") sipmonth="10";;
 	"Nov") sipmonth="11";;
 	"Dec") sipmonth="12";;
	esac
# if [[ $sipmonth == "666" ]]; then
# echo BADMONTH: $month
# echo $line
# fi
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
#	timezone=$(echo $siptmp | cut -d':' -f1)					# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
#	siptmp=$(echo $siphour"=="$timezone | awk -F '==' '{print $1+$2}')
	siptmp=""
	if [[ $((vsyslog)) -lt 6 ]]; then 								# syslog UDP stream from wireshark or SparkEmulator (1)
# <166>Nov 17 14:25:18 192.168.7.112 SIPMESSAGE: +02:00 2020 463 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061

#		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(echo "$line" | awk '{print $4}')	
			sipyear=$(echo "$line"     | awk '{print $7}')
			sipday=$(echo "$line"      | awk '{printf "%02i",$2}')
			if [[ $line =~ ^\<1[0-9][0-9] ]]; then
				month=$(echo "$line"       | awk -F"<16[34567]>" '{print $2}' | cut -d' ' -f1)
#				month=$(echo "$line"       | cut -d'>' -f2 | cut -d' ' -f1)				
			else
				month=$(echo "$line"       | cut -d' ' -f1)
			fi
			get_sipmonth
#		fi

		siphour=$(echo "$line"  | awk '{print $3}')	
		sipmin=$(echo $siphour  | cut -d':' -f2)	# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour  | cut -d':' -f3)	# awk -F ':' '{print $3}')
		siphour=$(echo $siphour | cut -d':' -f1)	# awk -F ':' '{print $1}')
		sipmsec=$(echo "$line"  | awk '{print $8}')
		siptmp=$(echo "$line"   | awk '{print $6}')

	elif [[ $((vsyslog)) == 6 ]]; then 								 ## visual syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

		foundipaddr=$(echo "$line" | awk '{print $6}')
#		if [[ $((n)) == 0 ]]; then	
			sipyear=$(echo "$line"     | awk '{print $3}')		# cut -d' ' -f1)
			sipday=$(echo "$sipyear"   | awk -F"/" '{printf "%02i", $1}')
			sipmonth=$(echo "$sipyear" | awk -F"/" '{printf "%02i", $2}')
			sipyear=$(echo "$sipyear"  | cut -d'/' -f3)
#		fi

		siphour=$(echo "$line"  | awk '{print $4}')
		sipmin=$(echo $siphour  | cut -d':' -f2)	# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour  | cut -d':' -f3)	# awk -F ':' '{print $3}')
		siphour=$(echo $siphour | cut -d':' -f1)	# awk -F ':' '{print $1}')
		sipmsec=$(echo "$line"  | awk '{print $10}')
		siptmp=$(echo "$line"   | awk '{print $8}')
		pm=$(echo $line | awk '{print $5}')
		if [[ $pm == "PM" ]]; then
			siphour=$(($((siphour))+12))
			if [[ $((siphour)) -gt 23 ]]; then
				echo ''
				echo "error: found invalid HOUR in $file at line #$nlines: hour=$siphour pm=$PM"
				exit 1;
			fi
		fi

	elif [[ $((vsyslog)) == 7 ]]; then 								 ## mega syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

		foundipaddr=$(echo "$line" | awk '{print $6}')
#		if [[ $((n)) == 0 ]]; then	
			sipyear=$(echo "$line"     | awk '{print $1}')		# cut -d' ' -f1)
			sipday=$(echo "$sipyear"   | cut -d'-' -f3)
			sipmonth=$(echo "$sipyear" | cut -d'-' -f2)
			sipyear=$(echo "$sipyear"  | cut -d'-' -f1)
#		fi

		siphour=$(echo "$line"  | awk '{print $2}')
		sipmin=$(echo $siphour  | cut -d':' -f2)	# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour  | cut -d':' -f3)	# awk -F ':' '{print $3}')
		siphour=$(echo $siphour | cut -d':' -f1)	# awk -F ':' '{print $1}')
		sipmsec=$(echo "$line"  | awk '{print $14}')
		siptmp=$(echo "$line"   | awk '{print $12}')

	elif [[ $((vsyslog)) == 8 ]]; then 								 ## tftpd64 syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

		foundipaddr=$(echo "$line" | awk '{print $4}')
#		if [[ $((n)) == 0 ]]; then	
			sipyear=$(echo "$line"  | cut -d' ' -f7)
			sipday=$(echo "$line"   | awk '{printf "%02i",$2}')		# cut -d' ' -f2)
			month=$(echo "$line"    | cut -d' ' -f1)
			get_sipmonth
#		fi

		siphour=$(echo "$line"  | awk '{print $3}')
		sipmin=$(echo $siphour  | cut -d':' -f2)	# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour  | cut -d':' -f3)	# awk -F ':' '{print $3}')
		siphour=$(echo $siphour | cut -d':' -f1)	# awk -F ':' '{print $1}')
		sipmsec=$(echo "$line"  | awk '{print $8}')
		siptmp=$(echo "$line"   | awk '{print $6}')

	elif [[ $((vsyslog)) == 9 ]]; then 								 ## interactive syslog viewer
# INFO	LOCAL4	1/25/2022 4:32:48 PM	192.168.7.113		SIPMESSAGE: +01:00 2022 622 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061
		foundipaddr=$(echo "$line" | awk '{print $6}')
#		if [[ $((n)) == 0 ]]; then
			sipyear=$(echo "$line"     | awk '{print $3}')
			sipday=$(echo "$sipyear"   | awk -F"/" '{printf "%02i",$2}')
			sipmonth=$(echo "$sipyear" | awk -F"/" '{printf "%02i",$1}')
			sipyear=$(echo "$sipyear"  | cut -d'/' -f3)
#		fi

		sipmsec=$(echo "$line"  | awk '{print $10}')
		siphour=$(echo "$line"  | awk '{print $4}')			
		sipmin=$(echo $siphour  | cut -d':' -f2)	# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour  | cut -d':' -f3)	# awk -F ':' '{print $3}')
		siphour=$(echo $siphour | awk -F":" '{printf "%02i",$1}')

		pm=$(echo $line | awk '{print $5}')
		if [[ $pm == "PM" ]]; then
			siphour=$(($((siphour))+12))
			if [[ $((siphour)) -gt 23 ]]; then
				echo ''
				echo "error: found invalid HOUR in $file at line #$nlines: hour=$siphour pm=$PM"
				exit 1;
			fi
		fi

		siptmp=$(echo "$line" | awk '{print $8}')

	elif [[ $((vsyslog)) == 10 ]]; then 								 ## avaya_phone.log ANB
# Jul 29 06:39:11 ANB[779 MSM]:<167>Jul 29 08:38:57 10.11.10.90 SIPMESSAGE: +02:00 2022 319 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 10.11.10.205:5061 TX REGISTER sips:sip.intranet.geiger.de 
# Jul 29 08:38:57.319
		sipday=$(echo "$line"      | awk '{printf "%02i",$2}')
		month=$(echo "$line"       | cut -d' ' -f1)
		get_sipmonth

		sipmsec=$(echo "$line"   | awk '{print $3}')
		siphour=$(echo $sipmsec  | cut -d':' -f1)						# awk -F ':' '{print $1}')		
		sipmin=$(echo $sipmsec   | cut -d':' -f2)						# awk -F ':' '{print $2}')
		sipsec=$(echo $sipmsec   | cut -d':' -f3)						# awk -F ':' '{print $3}')
		sipmsec=$(echo "$sipsec" | awk -F'.' '{printf "%03i",$2}')		# cut -d'.' -f2)
		sipsec=$(echo "$sipsec"  | cut -d'.' -f1)		

	elif [[ $((vsyslog)) == 20 ]]; then 								 ## KIWI syslog aka SyslogCatchAll
# 2022-02-11 17:33:11	Local4.Debug	135.105.129.244	Feb 11 16:33:09 135.105.129.244 SIPMESSAGE: +01:00 2022 653 1 .TEL | 0 [Part 01 of 02]<010>CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061<010>TX 
# TODO: date format can depend on Windows / KIWI server locale
		foundipaddr=$(echo "$line" | awk '{print $4}')
#		if [[ $((n)) == 0 ]]; then
			sipyear=$(echo "$line"     | cut -d' ' -f1 )					#| cut -d'-' -f1)	# awk -F'-' '{print $1}')
			sipmonth=$(echo "$sipyear" | cut -d'-' -f2)						# awk -F'-' '{print $2}')			
			sipday=$(echo "$sipyear"   | cut -d'-' -f3)						# awk -F'-' '{print $3}')			
			sipyear=$(echo $sipyear    | cut -d'-' -f1)			
#		fi

		if [[ $localtime == 1 ]]; then
			sipmsec=$(echo "$line" | awk '{print $2}')
		else
			sipmsec=$(echo "$line" | awk '{print $7}')
		fi

		sipmin=$(echo $sipmsec | cut -d':' -f2) 				# awk -F ':' '{print $2}')
		sipsec=$(echo $sipmsec | cut -d':' -f3) 				# awk -F ':' '{print $3}')
		siphour=$(echo $sipmsec| cut -d':' -f1) 				# awk -F ':' '{print $1}')
		sipmsec=$(echo "$line" | awk '{print $12}')
		siptmp=$(echo "$line"  | awk '{print $10}')
	fi

	if [[ $((adjusthour)) == 1 ]] && [[ $siptmp != "" ]]; then
		tzhour=$(echo $siptmp | cut -d':' -f1)		# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
		tzmin=$(echo $siptmp  | cut -d':' -f2)		# awk -F ':' '{print $2}')
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24))            # TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60))              # TODO need to print 2 digits
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

function convert_syslog_tftpd64 () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *"SIPMESSAGE:"* ]]; then
		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
# VDIC				
			elif [[ $line =~ ^[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			    dummy=0
			elif [[ $line =~ Part\  ]]; then
				echo "$line" | awk -F "[MTWFS][orehau][neduitn] [JFMASOND][[:lower:]][[:lower:]] " '{print $1}' >> "$newfile"
				siplines=$((siplines+1))
#				line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
				if [[ $partnum == $maxpart ]]; then
					complete_sipmsg
				fi
			else
				complete_sipmsg
			fi
		fi

		if [[ $line =~ \<16[3-7]\> ]]; then
			line=$(echo "$line" | awk -F"<16[3-7]>" '{print $2}')
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then												# ???
			badmsg=1
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1
				complete_sipmsg
#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then					# ignore BAD msg since it does not start with "01"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg			
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			emptyline=0
			insidesip=1
#			sip_partnum
			get_sip_datetime
			if [[ $((sipsplit)) == 0 ]]; then
				sip_direction
		        if [[ $((dirdefined)) != 0 ]]; then
#			  		if [[ $foundipddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#						reset_sipmsg
#						continue
#			  		else
						insidesip=2															
#				    fi
				fi
			fi
		fi
 # VDIC-beg
	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
		if [[ $((sipsplit)) == 0 ]]; then
			complete_sipmsg
		elif [[ $partnum == $maxpart ]]; then
			complete_sipmsg
		fi
 # VDIC-end
	elif [[ $((insidesip)) == 1 ]]; then
		sip_direction
        if [[ $((dirdefined)) != 0 ]]; then
#		  if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#			reset_sipmsg
#			continue
#		  else
#			sipmsg_header
			insidesip=2															
#		  fi
		fi

	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line == "RX "* ]] || [[ $line == "TX "* ]]; then
			line=$(echo "$line" | awk -F "TX |RX " '{print $2}')
				## echo -e "{\n[$sipstream] $firstline\x0d" >> "$newfile"
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
				reset_sipmsg;
				continue
			else
				sipmsg_header
				start_sipmsg
                insidesip=3
			fi
		fi
	elif [[ $((sipstart)) != 0 ]]; then
#		if [[ $line =~ \<16[3-7]\> ]] || 
		if [[ $line =~ ^[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
		    dummy=0
#			complete_sipmsg
		elif [[ ${#line} != 0 ]]; then
			sipline=$(echo "$line" | egrep -c "<16[3-7]>")
			if [[ $((sipline)) -gt 0 ]]; then					
				line=$(echo "$line" | awk -F "<16[3-7]>" '{print $1}')
				if [[ ${#line} != 0 ]]; then
					echo -e "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
				echo -e "$line" >> "$newfile.b64"
			else
				echo -e "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi
		fi
	fi
done <<< "$conv"
} # convert_syslog_tftpd64

function convert_syslog_mega () {
while IFS= read -r line
do
	##linelength=$(echo $line | wc -c)
		linelength=${#line}
		nlines=$((nlines+1))

	if [[ $line == *"SIPMESSAGE:"* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		fi

		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
			elif [[ $line =~ Part\  ]]; then
#				echo "$line" | awk -F "[MTWFS][orehau][neduitn] [JFMASOND][[:lower:]][[:lower:]] " '{print $1}' >> "$newfile"
#				elif [[ $line =~ [MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then				
#				line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
				if [[ $partnum == $maxpart ]]; then
					complete_sipmsg
				fi
			else
				complete_sipmsg				
			fi

		fi
		if [[ $line =~ \<16[3-7]\> ]]; then
			line=$(echo "$line" | awk -F"<16[3-7]>" '{print $2}')
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then
			badmsg=1
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1					
				complete_sipmsg

#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then				# ignore BAD msg since it does not start with "01"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg			
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			emptyline=0
			insidesip=1
#			sip_partnum
			get_sip_datetime
			if [[ $((sipsplit)) == 0 ]]; then
				sip_direction
		        if [[ $((dirdefined)) != 0 ]]; then
#			  		if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#						reset_sipmsg
#						continue
#			  		else
						insidesip=2															
#				    fi
				fi
			fi
		fi
 	elif [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
		if [[ $((sipstart)) == 0 ]]; then
			continue
		elif [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
			complete_sipmsg
		fi

	elif [[ $((insidesip)) == 1 ]]; then
		sip_direction
        if [[ $((dirdefined)) != 0 ]]; then
#		  if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#			reset_sipmsg
#			continue
#		  else
#			sipmsg_header
			insidesip=2															
#		  fi
		fi
	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line =~ RX\ |TX\  ]]; then
			line=$(echo "$line" | awk -F "RX |TX " '{print $2}')
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
				reset_sipmsg;
				continue
			else
				sipmsg_header
				start_sipmsg
                insidesip=3
			fi
		fi
	elif [[ $((sipstart)) != 0 ]]; then
		if [[ $((vsyslog)) == 7 ]]; then
			line=$(echo "$line" | awk '{print substr($0,46)}')
		fi
		if [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
			complete_sipmsg			
		elif [[ $line =~ ^\<16[3-7]\> ]] || [[ $line =~ [JFMASOND][[:lower:]][[:lower:]]\ [0-9]{1,2}\  ]]; then
			complete_sipmsg
		elif [[ ${#line} != 0 ]]; then
			sipline=$(echo "$line" | egrep -c "<16[3-7]>")
			if [[ $((sipline)) -gt 0 ]]; then					
				line=$(echo "$line" | awk -F "<16[3-7]>" '{print $1}')
				if [[ ${#line} != 0 ]]; then
					echo "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
				echo "$line" >> "$newfile.b64"
			else
				echo -e "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi
		fi
	fi
done <<< "$conv"
} # convert_syslog_mega

function convert_syslog_visual () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *"SIPMESSAGE:"* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		fi

		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
			elif [[ $line =~ Part\  ]]; then
				if [[ $partnum == $maxpart ]]; then
					complete_sipmsg
				fi
			else
				complete_sipmsg				
			fi
		fi

#		if [[ $line =~ \<16[3-7]\> ]]; then
#			line=$(echo "$line" | awk -F"<16[3-7]>" '{print $2}')
#		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then												# ???
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1					
				complete_sipmsg

#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then					# ignore BAD msg since it does not start with "01"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg			
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			emptyline=0
			insidesip=1
#			sip_partnum
			get_sip_datetime
			if [[ $((sipsplit)) == 0 ]]; then
				sip_direction
		        if [[ $((dirdefined)) != 0 ]]; then
#			  		if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#						reset_sipmsg
#						continue
#			  		else
						insidesip=2															
#				    fi
				fi
			fi
		fi
 
	elif [[ $((insidesip)) == 1 ]]; then
		sip_direction
        if [[ $((dirdefined)) != 0 ]]; then
#		  if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#			reset_sipmsg
#			continue
#		  else
#			sipmsg_header
			insidesip=2															
#		  fi
		fi

	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line =~ ^RX\ |^TX\  ]]; then
			line=$(echo "$line" | awk -F "^RX |^TX " '{print $2}')
				## echo -e "{\n[$sipstream] $firstline\x0d" >>$newfile
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
				reset_sipmsg;
				continue
			else
				sipmsg_header
				start_sipmsg
                insidesip=3
			fi
		fi
	elif [[ $((sipstart)) != 0 ]]; then
#		if [[ $line =~ \<16[34567]\> ]] || [[ $line =~ [JFMASOND][[:lower:]][[:lower:]]\ [0-9]{1,2}\  ]]; then
		if [[ $line =~ ^INFO|^DEBUG|^NOTICE ]]; then
			complete_sipmsg
		elif [[ ${#line} != 0 ]]; then
			sipline=$(echo "$line" | egrep -c "<16[3-7]>")
			if [[ $((sipline)) -gt 0 ]]; then					
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(echo "$line" | awk -F "<16[3-7]>" '{print $1}')
				if [[ ${#line} != 0 ]]; then
					echo "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
				echo "$line" >> "$newfile.b64"
			else
				echo -e "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi
		fi
	fi
done <<< "$conv"
} # convert_syslog_visual


function convert_syslog_interactive () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *"SIPMESSAGE:"* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		fi

		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
			elif [[ $line =~ Part\  ]]; then
#				echo "$line" | awk -F "[MTWFS][orehau][neduitn] [JFMASOND][[:lower:]][[:lower:]] " '{print $1}' >> "$newfile"
#				elif [[ $line =~ [MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then				
#				line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
				if [[ $partnum == $maxpart ]]; then
					complete_sipmsg
				fi
			else
				complete_sipmsg				
			fi

		fi
#		if [[ $line =~ \<16[3-7]\> ]]; then
#			line=$(echo "$line" | awk -F"<16[3-7]>" '{print $2}')
#		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then													# ???
			badmsg=1
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1					
				complete_sipmsg

			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then						# ignore BAD msg since it does not start with "01"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			emptyline=0
			insidesip=1
#			sip_partnum
			get_sip_datetime
			if [[ $((sipsplit)) == 0 ]]; then
				sip_direction
		        if [[ $((dirdefined)) != 0 ]]; then
#			  		if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#						reset_sipmsg
#						continue
#			  		else
						insidesip=2															
#				    fi
				fi
			fi
		fi

	elif [[ $((insidesip)) == 1 ]]; then
		sip_direction
        if [[ $((dirdefined)) != 0 ]]; then
#		  if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#			reset_sipmsg
#			continue
#		  else
#			sipmsg_header
			insidesip=2															
#		  fi
		fi

	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line =~ ^RX\ |^TX\  ]]; then
			line=$(echo "$line" | awk -F "^RX |^TX " '{print $2}')
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
				reset_sipmsg;
				continue
			else
				sipmsg_header
				start_sipmsg
                insidesip=3
			fi
		fi
	elif [[ $((sipstart)) != 0 ]]; then

		if [[ $line =~ ^INFO|^DEBUG|^NOTICE ]]; then
			complete_sipmsg
		elif [[ ${#line} != 0 ]]; then
			sipline=$(echo "$line" | egrep -c "<16[34567]>")
			if [[ $((sipline)) -gt 0 ]]; then					
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(echo "$line" | awk -F "<16[34567]>" '{print $1}')
				if [[ ${#line} != 0 ]]; then
					echo "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
				echo "$line" >> "$newfile.b64"
			else
				echo -e "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi
		fi
	fi
done <<< "$conv"
} # convert_syslog_interactive

function convert_EndpointLog () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *"SIPMESSAGE:"* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		fi

		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
#			elif [[ $line =~ [MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			elif [[ $line =~ Part\  ]]; then
			    if [[ $line =~ ^\<16[3-7]\> ]] || [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				    dummy=0															# dummy statement
				elif [[ $line =~ .*\<16[3-7]\> ]]; then
					echo "$line" | awk -F"<16[3-7]>" '{print $1}' >> "$newfile"					
					line=$(echo "$line" | awk -F"<16[3-7]>" '{print $2}')
				    siplines=$((siplines+1))					
				elif [[ $line =~ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
					echo "$line" | awk -F "[JFMASOND][[:lower:]][[:lower:]] " '{print $1}' >> "$newfile"
					line=$(echo "$line" | awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $2}')					
					siplines=$((siplines+1))
				fi
#				line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
				if [[ $partnum == $maxpart ]]; then
					complete_sipmsg
				fi
			else
				complete_sipmsg				
			fi
		fi

		if [[ $line =~ \<16[3-7]\> ]]; then
			line=$(echo "$line" | awk -F"<16[3-7]>" '{print $NF}')
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then											# ???
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1
				complete_sipmsg

#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue

#			elif [[ $partnum != "01" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then				# # ignore BAD msg since it does not start with "01"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			emptyline=0
			insidesip=1
#			sip_partnum
			get_sip_datetime
			if [[ $((sipsplit)) == 0 ]]; then					# ALERT: split messages may write in/Outbound message into next line !!!
				sip_direction
		        if [[ $((dirdefined)) != 0 ]]; then
#			  		if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#						reset_sipmsg
#						continue
#			  		else
						insidesip=2															
#				    fi
				fi
			fi
		fi
 
# VDIC-beg
	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^\<16[3-7]\> ]]; then
		if [[ $((sipsplit)) == 0 ]]; then
			complete_sipmsg
		elif [[ $partnum == $maxpart ]]; then
			complete_sipmsg
		fi
	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
		if [[ $((sipsplit)) == 0 ]]; then
			complete_sipmsg
		elif [[ $partnum == $maxpart ]]; then
			complete_sipmsg
		fi
	elif [[ $((vsyslog)) == 20 ]] && [[ $((sipstart)) != 0 ]] && [[ $line =~ Local[04] ]]; then
		if [[ $((sipsplit)) == 0 ]]; then
			complete_sipmsg
		elif [[ $partnum == $maxpart ]]; then
			complete_sipmsg
		fi
# VDIC-end
	elif [[ $((insidesip)) == 1 ]]; then
		sip_direction
        if [[ $((dirdefined)) != 0 ]]; then
#		  if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#			reset_sipmsg
#			continue
#		  else
#			sipmsg_header
			insidesip=2															
#		  fi
		fi

	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line == "RX "* ]] || [[ $line == "TX "* ]]; then
			line=$(echo "$line" | awk -F "TX |RX " '{print $2}')
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
				reset_sipmsg;
				continue
			else
				sipmsg_header
				start_sipmsg
                insidesip=3
			fi
		fi
	elif [[ $((sipstart)) != 0 ]]; then

# VDICcut		if [[ $line =~ \<16[34567]\> ]] || [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
# VDICcut			complete_sipmsg
		if [[ ${#line} != 0 ]]; then
			sipline=$(echo "$line" | egrep -c "<16[3-7]>")
			if [[ $((sipline)) -gt 0 ]]; then					
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(echo "$line" | awk -F "<16[37]>" '{print $1}')
				if [[ ${#line} != 0 ]]; then
					echo -e "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi
# VDIC-beg
				if [[ $((sipsplit)) == 0 ]]; then
					complete_sipmsg
				fi
# VDIC-end
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
				echo "$line" >> "$newfile.b64"
			else
				echo -e "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi
		fi
	fi
done <<< "$conv"
} # convert_EndpointLog

function convert_ANB () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			emptyline=0
			insidesip=1
			get_sip_datetime
		fi
	elif [[ $((insidesip)) == 1 ]] && [[ $((dirdefined)) == 0 ]]; then
		sip_direction
	elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
			reset_sipmsg
			continue
		else
			sipmsg_header
			start_sipmsg
		fi						
	elif [[ $((sipstart)) != 0 ]]; then
		if [[ $line == "-------------"* ]]; then 
			complete_sipmsg
		elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
			base64found=1
			echo "# Base64 dump found" >> "$newfile"
			if [[ -f "$newfile.b64" ]]; then
				rm "$newfile.b64"
			fi
		elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
			echo "$line" >> "$newfile.b64"
		else
			echo "$line" >> "$newfile"
			siplines=$((siplines+1))
			get_useragent
		fi
	fi
done <<< "$conv"
} # convert_ANB

function convert_siplog () {
	lastfoundip=""
	useragent=""
	nlines=0
	sipyear=0
	sipmonth=0
	sipday=0
	siphour=0
	sipmin=0
	sipmsec=0
	siptime=""
	siptimeprev=""
	sipmsg=0
	sipbadmsg=0
	sipbadmsgnum=""
	sipbadtime=0
	sipbadtimemsg=""
	sipwordlist=""	
	siptotalmsg=0
	sipmaxlines=0
	sipmaxpart=0
	sipmaxpartmsg=0
	sipmaxsplit=0
	longestmsg=0
	sipin=0
	sipout=0
	splitin=0
	splitout=0
	splitparts=0	
	error=0
	rec=0
	n=0

	reset_sipmsg	

#	sample=$(egrep -m 1 ".*SIPMESSAGE:.*Part .*" "$file")
	sample=$(egrep -m 1 "SIPMESSAGE:" "$file")						
	rec=$(egrep -c "SIPMESSAGE:" "$file")

	if [[ $rec == 0 ]];	then
		rec=$(egrep -c -e "CSeq:" "$file")
	fi				
	if [[ $rec == 0 ]];	then			
	 	error=2
		echo "error: No SIP messages have been found in $var."
		echo "Perhaps $var is not a logfile from 96x1SIP, J1xxSIP, H175 or SparkEmulator. Or, debug loglevel was not enabled with SIPMESSAGE logcategory."
		echo ''; return
#	elif [[ $sample != "" ]] && [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
	elif [[ $sample != "" ]]; then

	 	if [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then	# EndpointLog or 96x1/J1xx syslog from wireshark/Follow UDP stream
#			vsyslog=2													

			sed 's/^<1[0-9][0-9]>//g' "$file" > "$file.sip"
			file="$file.sip"
			vsyslog=2
		elif [[ $sample =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]] && [[ $sample =~ ANB\[ ]]; then # Murray Gibb created this avaya_phone.log conversion
			vsyslog=10
			tmpfile=1
			input2="$file"
			file="$file.sipmessages"		
			echo "-------------" > "$file"
			sipyear=$(echo $today  | cut -d'/' -f3)		
			egrep SIPMESSAGE "$input2" | sed 's/^.*<16[567]>\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\)\(.*\)/MaRk\1 \2/' | sed 's/^\(MaRk[A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\)  \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* [0-9]\{4\} \([0-9]\{3\}\) \(.*$\)/\1.\3 \2 \4/' | sed 's/^MaRk\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* CNetworkInputManager::ProcessInput.* = \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* [RT]X \(.*$\)/\1 <- \2 \3/' | sed 's/^MaRk\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* CSIPServer::SendToNetwork.* to \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\):.* [RT]X \(.*$\)/\1 -> \2 \3/' | sed 's/^MaRk\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .*TEL | 0 \(.*$\)/CoNtInUe \2/' | sed ':a;N;$!ba;s/\nCoNtInUe //g' | sed 's/^\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\}\) \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\} [-<][->] [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) \(.*$\)/\1\r\n\2\r\n\3-------------\r\n/' | sed 's/\^M /\r\n/g' | sed 's/\^M/\r\n/g' >> "$file"
#			input2="$file"
	 	elif [[ $sample =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]] && [[ $sample =~ SIPMESSAGE ]]; then	# pcap syslog r7.1.14
		 	vsyslog=2
		elif [[ $sample =~ ^[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]] && [[ $sample =~ \;\ \<16[34567]\> ]]; then	# tftd64 syslog
			vsyslog=8
		elif [[ $sample =~ ^INFO ]] && [[ $sample =~ LOCAL4 ]]; then							# interacive syslog viewer
			vsyslog=9
		elif [[ $sample =~ ^DEBUG ]] && [[ $sample =~ LOCAL4 ]]; then							# visual syslog
			vsyslog=6

		elif [[ $sample =~ Local4.Debug|Local4.Info ]] && [[ $sample =~ \<010\> ]]; then					# KIWI syslog
#			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
#			sample=$(echo $sample | awk '{print $6}')
			vsyslog=20
			tmpfile=1
			input2="$file"
			sed 's/<013><010>/\n/g' "$file" | sed 's/<010>/\n/g' | sed 's/<013>/\n/g' > "$file.kiwi"
			file="$file.kiwi"
#			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")									

		elif [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			sample=$(echo $sample | awk '{print $5}')						# cut -d' ' -f5)
			if [[ $sample == "SIPMESSAGE:" ]]; then
				vsyslog=1
			else
				error=3
			fi
		elif [[ $sample =~ ^[12][0-9]{3}-[0-9]{2}-[0-9]{2}\ [0-9]{2}\: ]]; then		# MEGA syslog
			vsyslog=7
		else
			error=3		
		fi
		if [[ $error == 3 ]]; then
			echo "error: unknown log format. Verify source and content of "$var
			echo ''; return
		fi
	fi

	if [[ $((vsyslog)) == 10 ]]; then
		rec=$(egrep -c "^-------------" "$file")
	else
		rec=$(egrep -c "SIPMESSAGE:" "$file")
	fi

	if [[ $rec == 0 ]]; then
		echo "error: $var file is empty."
		error=1			
		rec=$(egrep -c -e "^CSeq:*" "$file")
		if [[ $rec == 0 ]]; then 
			rec=$(egrep -c -e "CSeq:" "$file")
		fi
		if [[ $rec == 0 ]]; then
			error=2		
			echo 'In fact, no sign of any "CSeq:" lines in '$file
			echo ''; return
		else
			rec=0
			error=2
			echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages in '$file
			echo "Verify source and content of $file"
			echo ''; return
		fi
#	else
#		rec=$(egrep -c -e "^CSeq:*" "$file")
	fi

	if [[ $((vsyslog)) != 0 ]]; then
		if [[ $((rec)) -gt 500 ]]; then
			echo "Warning: about to convert a logfile with $rec SIP messages"
			echo "This could take a while... you may want to execute this script on a more powerful PC or server."
			echo ''
		fi
			##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
		if [[ $((vsyslog)) == 10 ]]; then
#			conv=$(awk -e '/-------------/{flag=1} flag; /}/{flag=0}' "$file")
			conv=$(awk -W source='/-------------/{flag=1} flag; /}/{flag=0}' "$file")				
		else
#    		conv=$(awk -e '/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file")
    		conv=$(awk -W source='/SIPMESSAGE:/{flag=1} flag; /}/{flag=0}' "$file")				
		fi

		check=$(egrep -c -e "<1[36][34567]>" "$file")
		if [[ $((vsyslog)) -lt 9 ]] && [[ $((check)) == 1 ]]; then			# == 0 if not stripping of leading <167>, see orig vsyslog=2
			error=3		
			echo "ALERT: expecting SYSLOG extracted from Wireshark but could not find any lines with <16x> pattern."
			echo "Could $var be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			echo ''; return
		elif [[ $((vsyslog)) == 20 ]] && [[ $((check)) != 0 ]]; then
			error=3		
			echo "ALERT: expecting SYSLOG collected by KIWI or other tools but found some lines with <16x> pattern."
			echo "Could $var be a SYSLOG extracted from Wireshark instead of remote SYSLOG via KIWI or other tools?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			echo ''; return
		fi

		if [[ $file == *"/"* ]]; then 
			basefile=$(echo "${file##*/}")
		else
			basefile=$file
		fi
		if [[ $basefile == *"."* ]]; then
			basefile=$(echo "${basefile%.*}")
		fi

		if [[ $var == *"."* ]]; then
			xfile=$(echo "${var%%.*}")
			if [[ $var == $basefile ]]; then
				output=$var
			elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
				output="$xfile-$basefile"
			else
				output=$var
			fi
		else
			output=$basefile
		fi

		if [[ $output != "" ]]; then
			newfile="$output.asm.tmp"
		elif [[ $file != "" ]]; then
			newfile="$file.asm.tmp"
		fi

		if [ -f "$newfile" ]; then
			rm "$newfile"
		fi
		echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

		if [[ $var != $file ]]; then
			if [[ $input2 != "" ]] && [[ $file != "" ]] && [[ $file != $input2 ]]; then
				echo -e "# Input/output file: $var -> $input2 -> $file -> $output.asm\n" >> "$newfile"
			elif [[ $file != "" ]] && [[ $file != $output ]]; then
				echo -e "# Input/output file: $var -> $file -> $output.asm\n" >> "$newfile"
			fi
		else 
			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"
		fi

		case $((vsyslog)) in
 		1|2|3) 	convert_EndpointLog;;
	 	6) 		convert_syslog_visual;;
 		7|20)	convert_syslog_mega;;
	 	8)		convert_syslog_tftpd64;;
 		9)		convert_syslog_interactive;;
	 	10)		convert_ANB;;
		esac

#		if [[ $((vsyslog)) == 2 ]]; then
#			convert_EndpointLog
#		elif [[ $((vsyslog)) == 6 ]]; then						# by default, VisualSyslog ExportAll saves SIP messages in reverse order !!!
#			convert_syslog_visual				
#		elif [[ $((vsyslog)) == 7 ]] || [[ $((vsyslog)) == 20 ]]; then						# KIWI transformed into MEGA
#			convert_syslog_mega
#		elif [[ $((vsyslog)) == 8 ]]; then
#			convert_syslog_tftpd64
#		elif [[ $((vsyslog)) == 9 ]]; then						# by default, Interactive Syslog ExportAll saves SIP messages in reverse order !!!
#			convert_syslog_interactive
#		elif [[ $((vsyslog)) == 10 ]]; then
#			convert_ANB
#		else

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi

        if [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm file"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $var file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    has been converted for addr=$endptaddr into $output.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				echo -e "$NL\tUser-Agent: $useragent"
				if [[ $lastfoundip != "" ]] && [[ $lastfoundip != "0.0.0.0" ]]; then
					echo -e "\t\tusing ipaddr = $lastfoundip"
				fi
			fi

			echo -e "\tTotal #lines digested:\t\t\t $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
#				echo -e "\tSIP messages in/out:\t\t\t\t $sipin/$sipout"
				if [[ $((sipmaxsplit)) != 0 ]]; then
					echo -e "\tSplit SIP messages (RX/TX):\t\t\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts"
					echo -e "# Split SIP messages (RX/TX):\t\t\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts" >> "$newfile"
					echo -e "\tLargest split SIP message:\t\t\t $sipmaxpart parts at msg #$sipmaxpartmsg"
					echo -e "# Largest split SIP message:\t\t\t $sipmaxpart parts at msg #$sipmaxpartmsg" >> "$newfile"
				fi
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg #$longestmsg"
				echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg #$longestmsg" >> "$newfile"
				if [[ $((sipbadmsg)) != 0 ]]; then
					echo -e "\tBad SIP messages (eg \"Part\" starts with \"02\"):\t $sipbadmsg at msg #$sipbadmsgnum"
					echo -e "# Bad SIP messages (eg \"Part\" starts with \"02\"): $sipbadmsg at msg #$sipbadmsgnum" >> "$newfile"
				fi
				if [[ $((sipbadtime)) != 0 ]]; then
					echo -e "\tBad SIP messages (timestamps out of order):\t $sipbadtime at msg #$sipbadtimemsg"
					echo -e "# Bad SIP messages (timestamps out of order):\t $sipbadtime at msg #$sipbadtimemsg" >> "$newfile"
				fi

				if [[ $((base64decode)) != 0 ]] && [[ $((base64msg)) != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
				fi
			fi		
		fi

		echo '' >> "$newfile"
		if [[ $sipwordlist != "" ]]; then
			echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
		fi
		echo ''
		echo "Task started: $currtime - completed: $(date +%R:%S)"
		echo ''
		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd; ls -l "$output.asm"			

		if [[ $tmpfile == 1 ]] && [[ $file != $var ]]; then
			rm $file
		fi
		echo ''
	fi
} # convert_siplog

################################# MAIN Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":ae:i:hk:bf:sv:IA" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
	I)
		noINFO=1;;		
	s)
		sipstat=0;;
	a)	
		conv2asm=1;;		
	b)
		base64decode=0;;
	e)
		endptaddr=${OPTARG};;
	i)
		smaddr=${OPTARG};;
	k)
		enckey=${OPTARG};;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 20 ]]; then
			vsyslog=1
		fi;;
    :)
		echo "Error: -${OPTARG} requires an argument."
		usage
		exit 0;;
	*)
		echo "Error: -${OPTARG} is an unknown option."
		usage
		exit 0;;
	esac
  done
fi

skipper=0

if [[ $((base64decode)) != 0 ]]; then
   base64 --version >/dev/null
   if [[ $? != 0 ]]; then
	  base64decode=0
   fi
fi

for var in "$@"
	do

	if [[ $var == "-"* ]]; then
  		if [[ $var ==   "-f"* ]]; then
			skipper=1
		elif [[ $var == "-e"* ]]; then
			skipper=2
		elif [[ $var == "-i"* ]]; then
			skipper=3
		elif [[ $var == "-v"* ]]; then
			skipper=4
		elif [[ $var == "-k"* ]]; then
			skipper=5
		else
			skipper=0
		fi
		continue
	elif [[ $skipper != 0 ]]; then
		if [[ $((skipper)) == 1 ]]; then	
			voutput=$var
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
				voutput=1
			fi
		elif [[ $((skipper)) == 2 ]]; then
			endptaddr=$var
		elif [[ $((skipper)) == 3 ]]; then
			smaddr=$var
		elif [[ $((skipper)) == 4 ]]; then
			vsyslog=${OPTARG}
			if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 20 ]]; then
				vsyslog=0
			fi
		elif [[ $((skipper)) == 5 ]]; then
			enckey=$var
		fi
		skipper=0			
		continue
	fi

	file=$var
	currtime=$(date +%R:%S)
	currdir=$PWD
	error=0
	
	if [ -f "$file" ]; then
		echo -en "Exploring content in $var... stand by\r"

		sample=""	
		sample2=""	
		filelist=""
		basefile=""
	    tmpfile=0		
		input=""
		input2=""
		output=""

		filecontent="Emulator"
		filetype=$(file -b "$file")

		if [[ $filetype == *"compressed data"* ]] || [[ $filetype == "data" ]]; then # is this an H175 debugreport? VDIC logreport does not support encryption (yet)
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
			if [[ $filecontent == *"ANDROID:"* ]]; then	# sometimes "file vantage.log" reports data (false), could be the case for other "txt" files?
				filecontent="ANDROID"
			elif [[ $enckey != "" ]]; then
				openssl version >/dev/null
				if [[ $? != 0 ]]; then
					if [[ $file == *"."* ]]; then
						input=$(echo "${file%.*}")
					else
						input="$file"
					fi

					openssl aes-128-cbc -d -salt -k $enckey -in "$file" -out "$input-decrypted.tgz"
					if [[ $? == 0 ]]; then
						error=6
						echo "error: Could not decode $file using \"openssl\" - verify encryption key with provider"
						echo ''; continue
					else
						file="$input-decrypted.tgz"
						filecontent="H175"
						filetype=$(file -b "$file")						
					fi
				else
					error=5
					echo 'error: "openssl" was not found, required for decrypting '$var
					echo ''; exit $error
				fi
			fi				
		fi

		if [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "Emulator" ]]; then
			if [[ $file == *"."* ]]; then
				input=$(echo "${file%.*}")
			else
				input="$file"
			fi
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp"
				if [[ $? != 0 ]]; then
					error=100; echo ''
					echo "error: could not delete $input.tmp folder. Check if any subfolders or files are open."
					exit $error
				fi
			fi
			mkdir "$input.tmp"
			if [[ $? != 0 ]]; then
				error=100; echo ''
				echo "error: could not create $input.tmp folder at $PWD. Check if this folder is open."
				exit $error
			fi

			cd "$input.tmp"			
			unzip -qq -v >/dev/null
			if [[ $? == 0 ]]; then
				unzip -qq "../$file"
				if [[ $? -gt 1 ]]; then
					tar --version >/dev/null
					if [[ $? == 0 ]]; then
						tar xf "../$file"
						if [[ $? != 0 ]]; then
							error=8; cd ..
							echo "error: unable to uncompress $var, using \"tar\" utility."
							echo ''; exit $error
						fi
					else
						error=8; cd ..
						echo "error: could not uncompress $var, using \"unzip\".  Suggest to deploy \"unzip\" package"
					    echo "in Ubuntu, you can install it by typing: sudo apt install unzip"						
						echo ''; exit $error
					fi
				fi
			else
				error=8; cd ..
				echo "error: could not uncompress $var, using \"unzip\".  Suggest to deploy \"unzip\" package"
				echo ''; exit $error
#				tar --version >/dev/null
#				if [[ $? == 0 ]]; then
#					tar xf "../$file"
#					if [[ $? != 0 ]]; then
#						error=8
#						echo "error: could not uncompress $var, using \"tar\" utility"
#						echo ''; cd ..; exit $error
#					fi
#				fi
			fi

			file=""; filelist=""; tmpdir=""
			targetfiles="EndpointLog.txt EndpointLog_bak.txt EndpointLog_prev.txt"
			if [ -d "Avaya Endpoint" ]; then
				tmpdir="Avaya Endpoint/"
			fi
			for xfile in $targetfiles
			do
				if [ -d "Avaya Endpoint" ]; then		
					if [ -d "Avaya Endpoint/LogFiles" ]; then
						if [ -f "Avaya Endpoint/LogFiles/$xfile" ]; then
							if [[ $file == "" ]]; then				
								file="$input.tmp/Avaya Endpoint/LogFiles/$xfile"
							fi
							filelist="$filelist=$input.tmp/Avaya Endpoint/LogFiles/$xfile"
						fi
					elif [ -f "AvayaEndpoint/$xfile" ]; then
						if [[ $file == "" ]]; then								
							file="$input.tmp/Avaya Endpoint/$xfile"
						fi
						filelist="$filelist=$input.tmp/Avaya Endpoint/$xfile"
					fi
				elif [ -d "LogFiles" ]; then
					if [ -f "LogFiles/$xfile" ]; then
						if [[ $file == "" ]]; then				
							file="$input.tmp/LogFiles/$xfile"
						fi
						filelist="$filelist=$input.tmp/LogFiles/$xfile"
					fi
				elif [ -f "$xfile" ]; then
					if [[ $file == "" ]]; then								
						file="$input.tmp/$xfile"
					fi
					filelist="$filelist=$input.tmp/$xfile"
				fi
			done

			cd ..

			if [[ $file == "" ]]; then
				error=9
				echo "error: extracted $var does not include any EndpointLog.txt files"
				echo ''; continue
			else
				filetype=$(file -b "$file")
				filecontent="EndpointLog"
			fi

		elif [[ $filetype == *"compressed data"* ]]; then
			filetype=$(file -bZ "$file")
			if [[ $filetype == *"ASCII text"* ]]; then
				if [[ $file == *"."* ]]; then
					input=$(echo "${file%.*}")
				else
					input="$file"
				fi
				gunzip --version >/dev/null
				if [[ $? == 0 ]]; then
					gunzip -q "$file"
					file=$input
				else
					error=8
					echo "error: unable to uncompress $var, using \"gunzip\" utility."
					echo ''; exit $error
				fi
			elif [[ $filetype == *"tar"* ]]; then
				if [[ $file == *"."* ]]; then
					input=$(echo "${file%%.*}")
				else
					input="$file"
				fi
				if [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp"
					if [[ $? != 0 ]]; then
						error=100; echo ''
						echo "error: could not delete $input.tmp folder. Check if any subfolders or files are open."
						echo ''; exit $error
					fi
				fi
				mkdir "$input.tmp"
				if [[ $? != 0 ]]; then
					error=100; echo ''
					echo "error: could not create $input.tmp folder at $PWD. Check if this folder is open."
					echo ''; exit $error
				fi
				cd "$input.tmp"
				tmpfile=1

				tar --version >/dev/null
				if [[ $? == 0 ]]; then
					tar zxf "../$file"
					if [[ $? != 0 ]]; then
						error=8; cd ..
						echo "error: unable to uncompress $file, using \"tar\" utility."
						echo ''; exit $error
					fi
				else
					gunzip --version >/dev/null
					if [[ $? == 0 ]]; then
						gunzip -q "../$file" 2>/dev/null	# TODO: can gunzip untar or only uncompress .tgz into .tar?
						if [[ $? != 0 ]]; then
							error=8; cd ..;
							echo "error: could not uncompress $file, using \"gunzip\" utility."
							echo ''; exit $error
						fi
					fi
				fi

                n=$?
				if [[ $filecontent == "" ]] && [ -d "var/log" ]; then
					filecontent="H175"
				fi

#				file=""				
#				if [[ $? == 0 ]]; then
				if [[ $n == 0 ]] && [[ $filecontent != "H175" ]]; then
				    if [[ -f REPORT.txt ]]; then
                           ncore=$(egrep -c "\.core" REPORT.txt)
						if [[ $((ncore)) != 0 ]]; then
                              echo "ALERT: found coredump files in $file -> REPORT.txt"
						   egrep "\.core" REPORT.txt
						   echo ''
						fi
					fi
				    file=""
					targetfiles="EndpointLog.txt EndpointLog_bak.txt EndpointLog_prev.txt"
#					filelist=""
					for xfile in $targetfiles
						do
						if [ -f "AvayaDir/SIP/application/LogFiles/$xfile" ]; then
							if [[ $file == "" ]]; then					
								file="$input.tmp/AvayaDir/SIP/application/LogFiles/$xfile"
							fi
							filelist="$filelist=$input.tmp/AvayaDir/SIP/application/LogFiles/$xfile"
						fi
					done

					if [[ $file == "" ]]; then
						for xfile in $targetfiles
						do
							if [ -f "AvayaDir/application/LogFiles/$xfile" ]; then
								if [[ $file == "" ]]; then						
									file="$input.tmp/AvayaDir/application/LogFiles/$xfile"
								fi
								filelist="$filelist=$input.tmp/AvayaDir/application/LogFiles/$xfile"
							fi
						done
					fi

					if [[ $file == "" ]]; then
						if [ -f "AvayaDir/var/log/avaya_phone.log" ]; then
							if [[ $file == "" ]]; then						
								file="$input.tmp/AvayaDir/var/log/avaya_phone.log"
							fi
							filelist="$filelist=$input.tmp/AvayaDir/var/log/avaya_phone.log"
						elif [ -f "var/volatile/tmp/logs/avaya_phone.log" ]; then
							if [[ $file == "" ]]; then						
								file="$input.tmp/var/volatile/tmp/logs/avaya_phone.log"
							fi
							filelist="$filelist=$input.tmp/var/volatile/tmp/logs/avaya_phone.log"
						elif [ -f "var/log/avaya_phone.log" ]; then
							if [[ $file == "" ]]; then												
								file="$input.tmp/var/log/avaya_phone.log"
							fi
							filelist="$filelist=$input.tmp/var/log/avaya_phone.log"
						fi

						if [[ $alllogs != 0 ]]; then
							for i in {1..7}
							do
								if [ -f "AvayaDir/var/log/avaya_phone.log.$i.gz" ]; then
									if [[ $file == "" ]]; then
										file="$input.tmp/AvayaDir/var/log/avaya_phone.log.$i"
									fi
									gunzip --version >/dev/null
									if [[ $? == 0 ]]; then
										gunzip -q "AvayaDir/var/log/avaya_phone.log.$i.gz"
										filelist="$filelist=$input.tmp/AvayaDir/var/log/avaya_phone.log.$i"
									else
										error=8
										echo "error: unable to uncompress $var -> $file, using \"gunzip\" utility."
										echo ''; cd ..; exit $error
									fi

								elif [ -f "var/log/avaya_phone.log.$i.gz" ]; then
									if [[ $file == "" ]]; then								
										file="$input.tmp/var/log/avaya_phone.log.$i"
									fi
									gunzip --version >/dev/null
									if [[ $? == 0 ]]; then
										gunzip -q "var/log/avaya_phone.log.$i.gz"
										filelist="$filelist=$input.tmp/var/log/avaya_phone.log.$i"
									else
										error=8
										echo "error: unable to uncompress $var -> $file, using \"gunzip\" utility."
										echo ''; cd ..; exit $error
									fi
								elif [ -f "var/log/avaya_phone.log.$i" ]; then
									if [[ $file == "" ]]; then														
										file="$input.tmp/var/log/avaya_phone.log.$i"								
									fi
									filelist="$filelist=$input.tmp/var/log/avaya_phone.log.$i"
								elif [ -f "/avaya_phone.log.$i" ]; then
									if [[ $file == "" ]]; then														
										file="$input.tmp/avaya_phone.log.$i"								
									fi
									filelist="$filelist=$input.tmp/avaya_phone.log.$i"
								fi
							done
						fi
					fi									

				elif [[ $filecontent == "H175" ]]; then
					if [[ $filelist == "" ]] && [[ $filecontent == "H175" ]]; then
						if [ -d "var/log" ]; then
							tmpfile=2
							if [ -f "var/log/EndpointLog_B+sig+CPS.txt" ]; then
								file="$input.tmp/var/log/EndpointLog_B+sig+CPS.txt"
								if [[ $alllogs != 0 ]]; then
									filelist=$(ls -t1 $input.tmp/var/log/EndpointLog_B+sig+CPS.txt*)
								fi
							fi
						elif [ -f "EndpointLog_B+sig+CPS.txt" ]; then
							tmpfile=2
							file="$input.tmp/EndpointLog_B+sig+CPS.txt"
							if [[ $alllogs != 0 ]]; then
								filelist=$(ls -t1 $input.tmp/EndpointLog_B+sig+CPS.txt*)
							fi
						fi
					fi
				else
					echo "error: could not uncompress $file at $PWD"
					error=8; cd ..					
					echo ''; exit $error
				fi
				if [[ $file == "" ]]; then
					error=9; cd ..				
					echo "error: extracted $var does not include EndpointLog.txt, avaya_phone.log or EndpointLog_B+sig+CPS.txt file"
					echo ''; continue
				else
				    cd ..				
				fi
			fi		
		elif [[ $filetype == *"capture"* ]]; then
			if [[ $filetype == *"tcpdump"* ]] || [[ $filetype == *"pcap"* ]]; then
		  		line=$(whereis tshark)

				if [[ ${#line} -gt 10 ]]; then
					if [[ $endptaddr != "" ]]; then
		    			tshark -r "$file" -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else						
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi

					n=$(egrep -m 1 -c "\n[RT]X\ " "$file.syslog2")
					if [[ $((n)) != 0 ]]; then
#						sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
						sed 's/\\r\\n\ /\'$'\n''/g' < "$file.syslog2" | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
						file="$file.syslog"
					else
						file="$file.syslog2"
					fi
					tmpfile=1
					vsyslog=11
		      	else
					error=10					  
		     		echo "error: unable to locate 'tshark' command"
					echo "'tshark' is required to extract syslog messages from $var into text file"
					echo "in Ubuntu, you can install it by typing: sudo apt install tshark"
					echo ''; error=10; exit $error
				fi
	  		fi
		fi

	nfiles=0
	if [[ $((alllogs)) != 0 ]] && [[ $filelist != "" ]]; then
		if [[ $filelist =~ ^= ]]; then
			filelist=${filelist:1}
		fi
		origIFS=$IFS; IFS="="
		nfiles=$(echo $filelist | awk -F"=" '{print NF}')

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x EndpointLog.txt or avaya_phone.log) found in $var"
			echo "This could take a while... you may want to execute this script on a more powerful PC or server."
			echo ''
			for file in $filelist;
			do

			if [[ $file != "" ]]; then
				IFS=$origIFS
				z=$(egrep -c "CSeq:" "$file")
				if [[ $z != 0 ]]; then
					convert_siplog
				fi
				IFS="="
			fi				
			done
		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			IFS=$origIFS
			convert_siplog				
		fi
		IFS=origIFS
	elif [[ $file != "" ]]; then
		convert_siplog	
	fi

else
	echo "error: file $var was not found."
	error=3
fi
done