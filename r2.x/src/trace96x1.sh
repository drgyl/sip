#!/bin/bash
version="2.0.0.1"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
AWKSRCFLAG="-W source="
today=$(date +%m/%d/%Y)
year=$(date +%Y)
sipstat=1
enckey=""
alllogs=0
noINFO=0
bCAT=0
bDelTemp=1
bReverse=0
findANI=""
fixVSYSLOG=0
adjusthour=0
localtime=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
extractppm=0
udp=0
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
    echo "trace96xx.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: trace96xx.sh [<LOG_FILE> | <phone report> | <folder>, ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis avaya_phone.log, EndpointLog.txt or phonereport taken from either"
	echo -e "\t\t\t96x1/J1xxSIP, SparkEmulator, 1XAgent or H175 (EndpointLog_B+sig_CPS)"
	echo -e "\t\t\tor, it can also be a syslog stream sent by these clients captured"
	echo -e "\t\t\teither via a remote SYSLOG server (eg. Kiwi) or via wireshark tool."
	echo -e "\t\t\tSyslog can be also extracted manually from pcap using \"Follow UDP stream\"."
	echo -e "\t<folder>\tincludes either of the above files, or it could be even a local directory"
	echo -e "\t\t\teg. \"Avaya\", \"Avaya\\Avaya Endpoint\", \"Log Files\", \"var/log\" or \"logs\""
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: \"a.b.c.d\""
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all log files found in logreport (eg. avaya_phone.log.X)"	
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converted multiple logfiles)"	
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"	
#	echo -e "\t-P:\t\textract PPM messages from syslog or http stream (into .ppm514/.ppm80 file)"		
#	echo -e "\t-i ipaddr:\tconvert syslog/http messages only sent by SM IP addr: a.b.c.d"	
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	partnum="00"; maxpart="99";	currpartnum="555"
	base64found=0
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	dirdefined=0	
	emptyline=0
	badmsg=0
	foundipaddr="";	siptime="";	sipdate="";	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then
	sipstart=1; 	siplines=$((siplines+1))
	case $voutput in
	1) 	echo -en "{$NL[$sipstream] $line$NL" >> "$newfile";;
	2)	echo -en "$NL$line$NL" >> "$newfile";;
	3)	echo -en "$line$NL" >> "$newfile";;
	esac

	sipword=$(cut -d' ' -f1 <<< "$line" | sed -e 's/[[:space:]]*$//')
	if [[ $sipword == "SIP/2.0" ]]; then
	   sipword=$(awk -F"SIP/2.0 " '{print $2}' <<< "$line" | sed -e 's/[[:space:]]*$//' | tr -d "\r")
	fi
	if [[ $sipwordlist != *$sipword* ]]; then
		sipwordlist="$sipwordlist | $sipword"
	fi
fi	
} # start_sipmsg()

function complete_sipmsg () {
if [[ $((sipstart)) != 0 ]]; then
	sipmsg=$((sipmsg+1))

	lastmsg="$sipword"
	timelast="$sipdate $siptime"
	if [[ $((sipmsg)) == 1 ]]; then
		firstmsg=$lastmsg
		timefirst=$timelast
	fi

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
		if [[ $maxpart == "99" ]] || [[ $partnum == "00" ]]; then
			echo -e "error: SIP msg was split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime line#$nlines"
			echo -e "# error: SIP msg was split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime line#$nlines" >> "$newfile"
		elif [[ $maxpart != "99" ]]; then
			splitparts=$((splitparts+10#$maxpart-1))

			if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
				sipmaxpart=${maxpart#0}
				sipmaxpartmsg=$sipmsg
				sipmaxpartsipword=$sipword				
			fi

			if [[ $partnum != $maxpart ]]; then
				badmsg=1; sipbadmsg=$((sipbadmsg+1))
				if [[ $sipbadmsgnum == "" ]]; then
					sipbadmsgnum="$siptotalmsg $siptime"
				fi
			fi
		else
			splitparts=$((splitparts+10#$partnum-1))				# this will increase number of parts, but we do not know exactly how many parts were actually seen in this sip msg
		fi
#		partnum="00"
#		maxpart="99"
	elif [[ $partnum != "00" ]]; then
		echo -e "error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime"
		echo -e "# error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime" >> "$newfile"		
		echo "nlines=$nlines vsyslog=$vsyslog"
		echo -e "Contact developer.\n"
	fi

	if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then	
		sipmaxlines=$siplines
		longestmsg=$sipmsg
		if [[ $((dirdefined)) == 1 ]]; then 
			longestsipword="RX $sipword"
		elif [[ $((dirdefined)) == 2 ]]; then
			longestsipword="TX $sipword"
		fi
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

	case $voutput in
	1)	echo -e "[$sipstream] }\x0d$NL" >> "$newfile";;
	2)	echo -e "$NL}$NL" >> "$newfile";;
	3)	echo -e "--------------------" >> "$newfile";;
	esac

	if [[ $((badmsg)) != 0 ]]; then
		echo -e "# This is a BAD message\n" >> "$newfile"
		badmsg=1;	sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadmsgnum == "" ]]; then
			sipbadmsgnum="$siptotalmsg $siptime"
		fi
	fi

	lastfoundip=$foundipaddr
	reset_sipmsg
else										# cannot complete a SIP message if it did not start properly
	badmsg=1; 	sipbadmsg=$((sipbadmsg+1))
	if [[ $sipbadmsgnum == "" ]]; then
		sipbadmsgnum="$siptotalmsg $siptime"
	fi
fi	
} # complete_sipmsg()

function sipmsg_header () {
if [[ $((dirdefined)) != 0 ]]; then	
	if [[ $foundipddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
		reset_sipmsg
	elif [[ $sipdate == "" ]] || [[ $siptime == "" ]] || [[ $ip == "" ]]; then
		echo -e "\nerror: failed to grab message header items at msg# $((n+1)) at line# $nlines of $basefile"
		echo "sipdate=$sipdate siptime=$siptime ip=$ip dirdefined=$dirdefined dirstring=$dirstring1 vsyslog=$vsyslog"
		echo "line=$line"; echo "Contact developer."; exit 1
	else	
		sipstart=0; 		n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted            \r"
			else
				echo -en "$var => $n/$rec Msgs converted            \r"
			fi
		fi

		if [[ $((sipsplit)) != 0 ]]; then
			echo -e "# msgno: $((sipmsg+1)) (split)" >> "$newfile"
		else
			echo -e "# msgno: $((sipmsg+1))" >> "$newfile"
		fi

		case $voutput in
		1)	echo -e "[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
		2)	echo -e "[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi	
} # sipmsg_header()

function sip_partnum () {
	if [[ $line =~ \[Part\  ]]; then
		currpartnum=$partnum	
		partline=$(awk -F "Part " '{print $2}' <<< "$line")
		partnum=$(cut -d' ' -f1 <<< "$partline")
		if [[ $partnum == "01" ]]; then
#		if [[ $partnum == "01" ]] && [[ $((sipsplit)) == 0 ]]; then
#			if [[ $((sipsplit)) != 0 ]]; then			# existing split SIP msg, but it starts with 01 - could be BAD
#				currpartnum="661"
#			fi
			maxpart=$(awk '{printf "%02i",$3}' <<< "$partline")
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
	if [[ $line == *"Inbound SIP"* ]] || [[ $line == *" <- "* ]] || [[ $line =~ ^RX\  ]]; then
		sipstream=5f70; 			dirdefined=1

		case $voutput in
		1)	dirstring1="RECEIVED";	dirstring2="from";;
		2)	dirstring1="RECEIVED";	dirstring2="from";;
		3)	dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line == *"Outbound SIP"* ]] || [[ $line == *" -> "* ]] || [[ $line =~ ^TX\  ]]; then
		sipstream=1474;				dirdefined=2

		case $voutput in
		1)	dirstring1="SENT"; 	  	dirstring2="to";;
		2)	dirstring1="SENDING"; 	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	fi

	if [[ $line =~ ^RX|^TX ]]; then								# 1xAgent special case
		ip="6.6.6.6:6666"

	elif [[ $((dirdefined)) != 0 ]]; then
		if [[ $foundipaddr == "" ]]; then
			case $vsyslog in
			9)	foundipaddr=$(cut -d' ' -f6 <<< "$line");;
			10)	foundipaddr=$(cut -d' ' -f1 <<< "$line");;
			11)	foundipaddr=$(awk '{print $8}' <<< "$line");;
			*)	foundipaddr=$(awk '{print $4}' <<< "$line");;
			esac
			localip="$foundipaddr:1111"
		fi

		if [[ $((vsyslog)) == 1 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f3 <<< "$ip")
				ip2=$(awk '{printf "%i",$5}' <<< "$ip")
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 2 ]] || [[ $((vsyslog)) == 3 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$line")				# cut -d' ' -f3  | tr -d "\n")
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")	#cut -d':' -f2  | tr -d "\n")
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 6 ]]; then
# DEBUG	LOCAL4	2/11/2022 4:28:37 PM	135.105.129.244		SIPMESSAGE: +01:00 2022 065 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 10.134.117.194 port: 5061
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")			# cut -d' ' -f3 | tr -d "\n")
			else 
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 7 ]]; then
# 2022-02-11 16:48:54	20	7	1	135.105.129.244				Feb 11 16:48:52 135.105.129.244 SIPMESSAGE: +01:00 2022 695 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 10.134.117.194 port: 5061				
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")			# cut -d' ' -f3 | tr -d "\n")
			else 
				ip=$(awk '{print $(NF-1)}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 8 ]]; then
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061		
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")
			else 
#				ip=$(echo "$line" | awk '{print $NF}' | tr -d "\n")		 # TODO: strip off ^M from the end (if any)				
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 9 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f3 <<< "$ip")
				ip2=$(awk '{printf "%i,$5}' <<< "$ip")
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 10 ]]; then
			ip1=$(awk '{print $3}' <<< "$line" | tr -d "\r")			# cut -d' ' -f3 | tr -d "\r")	# TODO: ANB missing port
			ip="$ip1:5061"

		elif [[ $((vsyslog)) == 11 ]]; then	# ANB incorrectly converted due to "Nov  3"
# Nov  3 12:00:48 ANB[1265 eventQueueProc]:<167>Nov  3 13:00:48 172.101.1.222 SIPMESSAGE: +02:00 2022 795 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 172.101.1.15 port: 5061 RX NOTIFY sip:83476@172.101.1.222:38283;transport=tls SIP/2.0		
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")			# cut -d' ' -f3 | tr -d "\n")
			else 
				ip=$(awk -F"SIP message to " '{print $2}' <<< "$line" | cut -d' ' -f1)
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(cut -d':' -f2 <<< "$ip")					# awk -F":" '{printf "%i",$2}')
			fi
			ip=$ip1:$ip2
		elif [[ $((vsyslog)) == 20 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")			#cut -d' ' -f3 | tr -d "\n")
				ip=$ip1:$ip2
			elif [[ $line == *"bound SIP message "* ]]; then
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2
			else
				ip=""
				echo -e "\nerror: could not determine IP address in sip_direction() for msg#$n at $siptime"
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
	if [[ $sipmonth == "666" ]]; then
		echo -e "\nerror: found non-english MONTH: $month - contact developer.\n"
		echo $line; echo ''; exit 1
	fi
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line =~ User-Agent: ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
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
			foundipaddr=$(awk '{print $4}' <<< "$line")
			sipyear=$(awk '{print $7}' <<< "$line")
			sipday=$(awk '{printf "%02i",$2}' <<< "$line")
			if [[ $line =~ ^\<1[0-9][0-9] ]]; then
				month=$(awk -F"<16[34567]>" '{print $2}' <<< "$line" | cut -d' ' -f1)
#				month=$(echo "$line"       | cut -d'>' -f2 | cut -d' ' -f1)				
			else
				month=$(cut -d' ' -f1 <<< "$line")
			fi
			get_sipmonth
#		fi

		siphour=$(awk '{print $3}' <<< "$line")	
		sipmin=$(cut -d':' -f2 <<< "$siphour")	# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour")	# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour")	# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $8}' <<< "$line")
		siptmp=$(awk '{print $6}' <<< "$line")

	elif [[ $((vsyslog)) == 6 ]]; then 								 ## visual syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

		foundipaddr=$(awk '{print $6}' <<< "$line")
#		if [[ $((n)) == 0 ]]; then	
			sipyear=$(awk '{print $3}' <<< "$line")		# cut -d' ' -f1)
			sipday=$(awk -F"/" '{printf "%02i", $1}' <<< "$sipyear")
			sipmonth=$(awk -F"/" '{printf "%02i", $2}' <<< "$sipyear")
			sipyear=$(cut -d'/' -f3 <<< "$sipyear")
#		fi

		siphour=$(awk '{print $4}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour")	# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour")	# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour")	# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $10}' <<< "$line")
		siptmp=$(awk '{print $8}' <<< "$line")
		pm=$(awk '{print $5}' <<< "$line")
		if [[ $pm == "PM" ]]; then
			siphour=$(($((siphour))+12))
			if [[ $((siphour)) -gt 23 ]]; then
				echo -e "\nerror: found invalid HOUR in $file at line #$nlines: hour=$siphour pm=$PM"
				echo $line; echo -e "\nContact developer.\n"; exit 1
			fi
		fi

	elif [[ $((vsyslog)) == 7 ]]; then 								 ## mega syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

		foundipaddr=$(awk '{print $6}' <<< "$line")
#		if [[ $((n)) == 0 ]]; then	
			sipyear=$(awk '{print $1}' <<< "$line")		# cut -d' ' -f1)
			sipday=$(cut -d'-' -f3 <<< "$sipyear")
			sipmonth=$(cut -d'-' -f2 <<< "$sipyear")
			sipyear=$(cut -d'-' -f1 <<< "$sipyear")
#		fi

		siphour=$(awk '{print $2}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour")	# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour")	# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour")	# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $14}' <<< "$line")
		siptmp=$(awk '{print $12}' <<< "$line")

	elif [[ $((vsyslog)) == 8 ]]; then 								 ## tftpd64 syslog
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]

		foundipaddr=$(awk '{print $4}' <<< "$line")
#		if [[ $((n)) == 0 ]]; then	
			sipyear=$(awk '{print $7}' <<< "$line") 			# cut -d' ' -f7)
			sipday=$(awk '{printf "%02i",$2}' <<< "$line")		# cut -d' ' -f2)
			month=$(cut -d' ' -f1 <<< "$line")
			get_sipmonth
#		fi

		siphour=$(awk '{print $3}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour")	# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour")	# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour")	# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $8}' <<< "$line")
		siptmp=$(awk '{print $6}' <<< "$line")

	elif [[ $((vsyslog)) == 9 ]]; then 								 ## interactive syslog viewer
# INFO	LOCAL4	1/25/2022 4:32:48 PM	192.168.7.113		SIPMESSAGE: +01:00 2022 622 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061
		foundipaddr=$(awk '{print $6}' <<< "$line")
#		if [[ $((n)) == 0 ]]; then
			sipyear=$(awk '{print $3}' <<< "$line")
			sipday=$(awk -F"/" '{printf "%02i",$2}' <<< "$sipyear")
			sipmonth=$(awk -F"/" '{printf "%02i",$1}' <<< "$sipyear")
			sipyear=$(cut -d'/' -f3 <<< "$sipyear")
#		fi

		sipmsec=$(awk '{print $10}' <<< "$line")
		siphour=$(awk '{print $4}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour")	# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour")	# awk -F ':' '{print $3}')
		siphour=$(awk -F":" '{printf "%02i",$1}' <<< "$siphour")

		pm=$(awk '{print $5}' <<< "$line")
		if [[ $pm == "PM" ]]; then
			siphour=$(($((siphour))+12))
			if [[ $((siphour)) -gt 23 ]]; then
				echo -e "\nerror: found invalid HOUR in $file at line #$nlines: hour=$siphour pm=$PM"
				echo $line; echo -e "\nContact developer.\n"; exit 1
			fi
		fi

		siptmp=$(awk '{print $8}' <<< "$line")

	elif [[ $((vsyslog)) == 10 ]]; then 								 ## avaya_phone.log ANB
# Jul 29 06:39:11 ANB[779 MSM]:<167>Jul 29 08:38:57 10.11.10.90 SIPMESSAGE: +02:00 2022 319 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 10.11.10.205:5061 TX REGISTER sips:sip.intranet.geiger.de 
# Jul 29 08:38:57.319
#		foundipaddr=$(echo "$line" | awk '{print $8}')
		sipyear=$(cut -d',' -f1 <<< "$line")
		sipday=$(awk '{printf "%02i",$3}' <<< "$line")
		month=$(cut -d' ' -f2 <<< "$line")
		get_sipmonth

		sipmsec=$(awk '{print $4}' <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")						# awk -F ':' '{print $1}')		
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")						# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")						# awk -F ':' '{print $3}')
		sipmsec=$(awk -F'.' '{printf "%03i",$2}' <<< "$sipsec")		# cut -d'.' -f2)
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")		

	elif [[ $((vsyslog)) == 11 ]]; then 									# ANB incorrectly parsed
# Nov  3 12:00:48 ANB[1265 eventQueueProc]:<167>Nov  3 13:00:48 172.101.1.222 SIPMESSAGE: +02:00 2022 800 1 .TEL | 0 CSIPServer::SendToNetwork(): Outbound SIP message to 172.101.1.15:5061 TX SIP/2.0 200 OK	
		foundipaddr=$(awk '{print $8}' <<< "$line")
		sipyear=$(awk '{print $11}' <<< "$line")
		sipday=$(awk '{printf "%02i",$6}' <<< "$line")
		month=$(cut -d' ' -f1 <<< "$line")
		get_sipmonth

		sipmsec=$(awk '{print $7}' <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")						# awk -F ':' '{print $1}')		
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")						# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")						# awk -F ':' '{print $3}')
		sipmsec=$(awk '{printf "%03i",$12}' <<< "$line")		# cut -d'.' -f2)

	elif [[ $((vsyslog)) == 20 ]]; then 								 ## KIWI syslog aka SyslogCatchAll
# 2022-02-11 17:33:11	Local4.Debug	135.105.129.244	Feb 11 16:33:09 135.105.129.244 SIPMESSAGE: +01:00 2022 653 1 .TEL | 0 [Part 01 of 02]<010>CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061<010>TX 
# TODO: date format can depend on Windows / KIWI server locale
		foundipaddr=$(awk '{print $4}' <<< "$line")
#		if [[ $((n)) == 0 ]]; then
			sipyear=$(cut -d' ' -f1 <<< "$line")					#| cut -d'-' -f1)	# awk -F'-' '{print $1}')
			sipmonth=$(cut -d'-' -f2 <<< "$sipyear")						# awk -F'-' '{print $2}')			
			sipday=$(cut -d'-' -f3 <<< "$sipyear")						# awk -F'-' '{print $3}')			
			sipyear=$(cut -d'-' -f1 <<< "$sipyear")			
#		fi

		if [[ $localtime == 1 ]]; then
			siphour=$(awk '{print $2}' <<< "$line")
		else
			siphour=$(awk '{print $7}' <<< "$line")
		fi

		sipmin=$(cut -d':' -f2 <<< "$siphour") 				# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour") 				# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour") 			# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $12}' <<< "$line")
		siptmp=$(awk '{print $10}' <<< "$line")
	fi

	if [[ $((adjusthour)) == 1 ]] && [[ $siptmp != "" ]]; then
		tzhour=$(cut -d':' -f1 <<< "$siptmp")		# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
		tzmin=$(cut -d':' -f2 <<< "$siptmp")		# awk -F ':' '{print $2}')
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24))            # TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60))              # TODO need to print 2 digits
		fi
	fi

	case $voutput in
	1)	sipdate="$sipmonth/$sipday/$sipyear"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	2)	sipdate="$sipyear/$sipmonth/$sipday"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	3)	sipdate="$sipday/$sipmonth/$sipyear"
		siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
	esac
} # get_sip_datetime()

function extract_PPMfromHTTP () { # from pcap file
echo Under construction

} # extract_PPMfromHTTP()

function extract_PPMfromSYSLOG () { # pcap file + remote syslog
echo Under construction

} # extract_PPMfromSYSLOG()

function reverse_logfile () {			# to revert order of SIPMESSAGE in Interactive and Visual SYSLOG
	block=$(awk -W source='/SIPMESSAGE/{flag=1} flag; /}/{flag=0}' "$file")
	line=""
	insidesip=0
	emptyline=0
	firstmsg=1
	tmpfile1="$file.tmp1"
	tmpfile2="$file.tmp2"
	filerev="$file.rev"

	while IFS= read -r line
	do
    	if [[ $line =~ SIPMESSAGE ]]; then
        	if [[ $((insidesip)) != 0 ]]; then
            	if [[ $((firstmsg)) != 0 ]]; then
                	cat $tmpfile1 > $filerev
	                firstmsg=0
    	        else
	                cat "$tmpfile1" "$filerev" > "$tmpfile2"
    	            mv "$tmpfile2" "$filerev"
        	    fi
	        fi
    	    insidesip=1
        	emptyline=0
	        echo "$line" > "$tmpfile1"
    	elif [[ $((insidesip)) == 1 ]]; then
        	if [[ ${#line} -le 2 ]]; then 
            	emptyline+=1
	            echo "$line" >> "$tmpfile1"
    	        if [[ $((emptyline)) == 2 ]]; then
        	        insidesip=2
            	fi
	        elif [[ $line =~ \.TEL\ \|\ 0 ]]; then
    	        insidesip=2
        	else
            	echo "$line" >> "$tmpfile1"
	        fi
    	elif [[ $((insidesip)) == 2 ]]; then
        	insidesip=0
	        if [[ $((firstmsg)) != 0 ]]; then
    	        cat "$tmpfile1" > "$filerev"
        	    firstmsg=0
	        else
	            cat "$tmpfile1" "$filerev" > "$tmpfile2"
    	        mv "$tmpfile2" "$filerev"
        	fi
	        continue    
    	fi
	done <<< "$block"

	insidesip=0
	emptyline=0
	block=""
	file="$filerev"
	if [ -f "$tmpfile1" ]; then
		rm "$tmpfile1"
	fi
} # reverse_logfile ()

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
			line=$(awk -F"<16[3-7]>" '{print $2}' <<< "$line")
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then												# ???
			badmsg=1; sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1; sipbadmsg=$((sipbadmsg+1))
				complete_sipmsg
#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then					# ignore BAD msg since it does not start with "01"
			badmsg=1; sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg			
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
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
	elif [[ $((insidesip)) == 0 ]]; then
		continue
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
			line=$(awk -F "TX |RX " '{print $2}' <<< "$line")
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
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
			sipline=$(egrep -c "<16[3-7]>" <<< "$line")
			if [[ $((sipline)) -gt 0 ]]; then					
				line=$(awk -F "<16[3-7]>" '{print $1}' <<< "$line")
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
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *"SIPMESSAGE:"* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		fi

		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
			elif [[ $line =~ \[Part\  ]]; then
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
			line=$(awk -F"<16[3-7]>" '{print $2}' <<< "$line")
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then
			badmsg=1;			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
				complete_sipmsg

#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then				# ignore BAD msg since it does not start with "01"
			badmsg=1;	sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg			
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
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

	elif [[ $((insidesip)) == 0 ]]; then
		continue

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
			line=$(awk -F "RX |TX " '{print $2}' <<< "$line")
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
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
			line=$(awk '{print substr($0,46)}' <<< "$line")
		fi
		if [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
			complete_sipmsg			
		elif [[ $line =~ ^\<16[3-7]\> ]] || [[ $line =~ [JFMASOND][[:lower:]][[:lower:]]\ [0-9]{1,2}\  ]]; then
			complete_sipmsg
		elif [[ ${#line} != 0 ]]; then
			sipline=$(egrep -c "<16[3-7]>" <<< "$line")
			if [[ $((sipline)) -gt 0 ]]; then					
				line=$(awk -F "<16[3-7]>" '{print $1}' <<< "$line")
				if [[ ${#line} != 0 ]]; then
					echo "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi

#				if [[ $((sipsplit)) == 0 ]]; then
#					complete_sipmsg
#				fi

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
			badmsg=1;	sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
				complete_sipmsg

#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then					# ignore BAD msg since it does not start with "01"
			badmsg=1;	sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg			
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
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
 
 	elif [[ $((insidesip)) == 0 ]]; then
		continue

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
			line=$(awk -F "^RX |^TX " '{print $2}' <<< "$line")
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
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
			sipline=$(egrep -c "<16[3-7]>" <<< "$line")
			if [[ $((sipline)) -gt 0 ]]; then					
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(awk -F "<16[3-7]>" '{print $1}' <<< "$line")
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
			badmsg=1;			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
				complete_sipmsg
			fi

		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then						# ignore BAD msg since it does not start with "01"
			badmsg=1;	sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
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

	elif [[ $((insidesip)) == 0 ]]; then
		continue

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
			line=$(awk -F "^RX |^TX " '{print $2}' <<< "$line")
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
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
		else
			if [[ ${#line} != 0 ]]; then
				sipline=$(egrep -c "<16[34567]>" <<< "$line")
				if [[ $((sipline)) -gt 0 ]]; then					
					##if [[ $line == *" SIPMESSAGE: "* ]]; then
					line=$(awk -F "<16[34567]>" '{print $1}' <<< "$line")
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
		elif [[ $line == *" End of "* ]] && [[ $((sipstart)) != 0 ]]; then		# 1xAgent special line
			complete_sipmsg
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
					line=$(awk -F"<16[3-7]>" '{print $2}' <<< "$line")
				    siplines=$((siplines+1))					
				elif [[ $line =~ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
					awk -F "[JFMASOND][[:lower:]][[:lower:]] " '{print $1}' <<< "$line" >> "$newfile"
					line=$(awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $2}' <<< "$line")
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
			line=$(awk -F"<16[3-7]>" '{print $NF}' <<< "$line")
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then											# ???
			badmsg=1;	sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
				complete_sipmsg

#			elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
#				complete_sipmsg				
#				continue

#			elif [[ $partnum != "01" ]] && [[ $((sipsplit)) == 0 ]]; then
#				badmsg=1;	sipbadmsg=$((sipbadmsg+1))
#				complete_sipmsg				
#				continue
			fi
		elif [[ $((sipsplit)) != 0 ]] && [[ $partnum != "01" ]]; then				# ignore BAD msg since it does not start with "01"
			badmsg=1;	sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
			reset_sipmsg
			continue
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
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
 
 	elif [[ $((insidesip)) == 0 ]]; then
		continue

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
			if [[ $line =~ RX\ |TX\  ]]; then						# 1xAgent special scenario
				line=$(awk -F "TX |RX " '{print $2}' <<< "$line")
				if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
					nINFO=$((nINFO+1))
					reset_sipmsg;
					continue
				else
					sipmsg_header
					start_sipmsg
	                insidesip=3
				fi
			fi
#		  fi
		fi

	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line =~ RX\ |TX\  ]]; then
			line=$(awk -F "TX |RX " '{print $2}' <<< "$line")
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
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
			sipline=$(egrep -c "<16[3-7]>" <<< "$line")
			if [[ $((sipline)) -gt 0 ]]; then					
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(awk -F "<16[37]>" '{print $1}' <<< "$line")
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

	if [[ $((vsyslog)) == 11 ]] && [[ $line =~ SIPMESSAGE: ]]; then
		if [[ $((sipstart)) != 0 ]] && [[ $line =~ RX|TX ]]; then
			complete_sipmsg
		fi

		if [[ $((insidesip)) == 0 ]] && [[ $line =~ RX|TX ]]; then
#			emptyline=0
			insidesip=1
			get_sip_datetime
			sip_direction
			if [[ $line =~ RX\ $|TX\ $ ]]; then
				badmsg=1;			sipbadmsg=$((sipbadmsg+1))
				if [[ $sipbadmsgnum == "" ]]; then
					sipbadmsgnum="$siptotalmsg $siptime"
				fi
				reset_sipmsg
				continue
			elif [[ $((dirdefined)) == 1 ]]; then
				line=$(awk -F" RX " '{print $2}' <<< "$line")
			elif [[ $((dirdefined)) == 2 ]]; then
				line=$(awk -F" TX " '{print $2}' <<< "$line")
			fi
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
				reset_sipmsg
				continue
			else
				siptotalmsg=$((siptotalmsg+1))			
				sipmsg_header
				start_sipmsg
			fi						

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				sipsplit=1
			fi
			splitparts=$((splitparts+1))
			line=$(awk -F" 0 " '{print $2}' <<< "$line")
			echo "$line" >> "$newfile"			
		fi

	elif [[ $line =~ ^[0-9]{4},\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
# TODO: modify to single if sipstart != 0 then	
		if [[ $((vsyslog)) == 11 ]] && [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		elif [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi

		if [[ $((insidesip)) == 0 ]]; then
			siptotalmsg=$((siptotalmsg+1))
			insidesip=1
			get_sip_datetime
		fi
	elif [[ $((insidesip)) == 1 ]] && [[ $((dirdefined)) == 0 ]]; then
		sip_direction
	
	elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
			nINFO=$((nINFO+1))
			reset_sipmsg
			continue
		else
			sipmsg_header
			start_sipmsg
		fi						
	
	elif [[ $((sipstart)) != 0 ]]; then
		if [[ $line == "-------------"* ]]; then 
#		if [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then		
			complete_sipmsg
		else		
			if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
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
	fi
done <<< "$conv"
} # convert_ANB

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "

	logsec=$SECONDS
	ppmfile=""
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
	longestsipword=""
	sipmaxpartsipword=""
	base64msg=0
	firstmsg=""
	lastmsg=""
	timefirst=""
	timelast=""
	callID=""
	calltime=""
	callDIR=0

	sipin=0
	sipout=0
	splitin=0
	splitout=0
	splitparts=0	
	nINFO=0
	error=0; rec=0; rec3=0; 	n=0

	reset_sipmsg	

#	sample=$(egrep -m 1 ".*SIPMESSAGE:.*Part .*" "$file" 2>/dev/null)
	sample=$(egrep -m 1 "SIPMESSAGE:" "$file" 2>/dev/null)
	rec=$(egrep -c "SIPMESSAGE:" "$file" 2>/dev/null)
	rec3=$(egrep -c -e "^[0-9]{4}, [JFMASOND][a-z][a-z][ ]{1,2}[0-9]{1,2}" "$file" 2>/dev/null)		# ANB file after converted into .sipmessages	

	if [[ $((rec)) == 0 ]] && [[ $((rec3)) == 0 ]];	then
		echo -e "\nerror: No SIP messages have been found in $basefile in the expected format."
		echo "This file may not be a logfile from 96x1SIP, J1xxSIP, VDIC, H175 or SparkEmulator."
		echo "Or, debug loglevel was not enabled with SIPMESSAGE logcategory."
		echo "Or, in case of 96x1SIP/J1xxSIP (thanks to new logging enhancements), logbuffer may have become congested."
		echo "If that is the case, review the logging configuration (and/or try to reduce amount of log categories)."
		echo "Otherwise, verify source and content of $bvar."

		rec=$(egrep -c -e "CSeq:" "$file" 2>/dev/null)

		if [[ $rec == 0 ]];	then
			echo -e "In fact, no sign of any "CSeq:" lines within $basefile\n"
		else
			echo -e "Though, found $rec lines with \"CSeq:\" - so there might be some SIP messages within this file."
			footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				if [[ $footprint == 1 ]]; then
					echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			elif [[ $var != $file ]]; then
				echo -e "Verify source and content of $bvar -> $basefile.\n"
				error=2; return
			else
				echo -e "Verify source and content of $bvar.\n"
				error=2; return
			fi
		fi

		if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
			echo "Verifying logging configuration:"
 			if [ -d "$input.tmp/AvayaDir/application" ] && [ -f "$input.tmp/AvayaDir/application/configcache.xml" ]; then
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG" "$input.tmp/AvayaDir/application/configcache.xml" 2>/dev/null
			elif [ -d "$input.tmp/Avaya Endpoint" ] && [ -f "$input.tmp/Avaya Endpoint/configcache.xml" ]; then
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG" "$input.tmp/Avaya Endpoint/configcache.xml" 2>/dev/null
			elif [ -f "$input.tmp/configcache.xml" ]; then
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG" "$input.tmp/configcache.xml" 2>/dev/null
			fi
			if [ -d "$input.tmp/AvayaDir/application" ] && [ -f "$input.tmp/AvayaDir/application/ConfigStatus_Web_Debugging.xml" ]; then
				echo -e "\nJ100 webUI Debugging includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG" "$input.tmp/AvayaDir/application/ConfigStatus_Web_Debugging.xml" 2>/dev/null
			fi
		fi
		rec=0; error=2; echo ''; return
#	elif [[ $sample != "" ]] && [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
	elif [[ $sample != "" ]] && [[ $((vsyslog)) == 0 ]]; then
	 	if [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then	# EndpointLog or 96x1/J1xx syslog from wireshark/Follow UDP stream
			sed 's/^<1[0-9][0-9]>//g' "$file" > "$file.sip"
			file="$file.sip"; tmpfile=2
			vsyslog=2

		elif [[ $sample =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]] && [[ $sample =~ ANB\[ ]]; then # Murray Gibb created this cool avaya_phone.log conversion script
			if [[ $sample =~ \r\  ]]; then
				vsyslog=11
			else
				vsyslog=10			
				input2="$file"
				file="$file.sipmessages"; tmpfile=2
				echo "# Converted from $input2 on $today $currtime" > "$file"
				echo "-------------" >> "$file"
#				sipyear=$(echo $today  | cut -d'/' -f3)		
#				egrep SIPMESSAGE "$input2" | sed 's/^.*<16[567]>\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\)\(.*\)/MaRk\1 \2/' | sed 's/^\(MaRk[A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\)  \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* [0-9]\{4\} \([0-9]\{3\}\) \(.*$\)/\1.\3 \2 \4/' | sed 's/^MaRk\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* CNetworkInputManager::ProcessInput.* = \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* [RT]X \(.*$\)/\1 <- \2 \3/' | sed 's/^MaRk\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* CSIPServer::SendToNetwork.* to \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\):.* [RT]X \(.*$\)/\1 -> \2 \3/' | sed 's/^MaRk\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .*TEL | 0 \(.*$\)/CoNtInUe \2/' | sed ':a;N;$!ba;s/\nCoNtInUe //g' | sed 's/^\([A-Z][a-z]\{2\} [0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\}\) \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\} [-<][->] [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) \(.*$\)/\1\r\n\2\r\n\3-------------\r\n/' | sed 's/\^M /\r\n/g' | sed 's/\^M/\r\n/g' >> "$file"
				egrep SIPMESSAGE "$input2" | sed 's/^.*<16[567]>\([A-Z][a-z]\{2\}[ ]\{1,2\}[0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\)\(.*\)/MaRk\1 \2/' | sed 's/^\(MaRk[A-Z][a-z]\{2\}[ ]\{1,2\}[0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}\)  \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* \([0-9]\{4\}\) \([0-9]\{3\}\) \(.*$\)/\3\1.\4 \2 \5/' | sed 's/^\([0-9]\{4\}\)MaRk\(.*$\)/MaRk\1\2/' | sed 's/^MaRk\([0-9]\{4\}[A-Z][a-z]\{2\}[ ]\{1,2\}[0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* CNetworkInputManager::ProcessInput.* = \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* [RT]X \(.*$\)/\1 <- \2 \3/' | sed 's/^MaRk\([0-9]\{4\}[A-Z][a-z]\{2\}[ ]\{1,2\}[0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .* CSIPServer::SendToNetwork.* to \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\):.* [RT]X \(.*$\)/\1 -> \2 \3/' | sed 's/^MaRk\([0-9]\{4\}[A-Z][a-z]\{2\}[ ]\{1,2\}[0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\} [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) .*TEL | 0 \(.*$\)/CoNtInUe \2/' | sed ':a;N;$!ba;s/\nCoNtInUe //g' | sed 's/^\([0-9]\{4\}\)\([A-Z][a-z]\{2\}[ ]\{1,2\}[0-9]\{1,2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\}.[0-9]\{3\}\) \([0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\} [-<][->] [0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}.[0-9]\{1,3\}\) \(.*$\)/\1, \2\r\n\3\r\n\4\r\n-------------\r\n/' | sed 's/\^M /\r\n/g' | sed 's/\^M/\r\n/g' >> "$file"
				dummy=$(egrep -m 1 -c "SIPMESSAGE:" "$file" 2>/dev/null)
				if [[ $? == 0 ]]; then
					vsyslog=11
				fi
			fi
#			input2="$file"
	 	elif [[ $sample =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]] && [[ $sample =~ SIPMESSAGE ]]; then	# pcap syslog r7.1.14
		 	vsyslog=2
		elif [[ $sample =~ ^[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]] && [[ $sample =~ \;\ \<16[34567]\> ]]; then	# tftpd64 syslog
			vsyslog=8
		elif [[ $sample =~ ^INFO ]] && [[ $sample =~ LOCAL4 ]]; then									# interactive syslog viewer
			vsyslog=9
			# if [[ $file is reversed ]]; then
			if [[ $((bReverse)) != 0 ]]; then
				reverse_logfile
			fi

		elif [[ $sample =~ ^DEBUG ]] && [[ $sample =~ LOCAL4 ]]; then									# visual syslog
			vsyslog=6
			# if [[ $file is reversed ]]; then
			if [[ $((bReverse)) != 0 ]]; then			
				reverse_logfile
			fi

		elif [[ $sample =~ Local4.Debug|Local4.Info ]] && [[ $sample =~ \<010\> ]]; then				# KIWI syslog
#			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
#			sample=$(echo $sample | awk '{print $6}')
			vsyslog=20
			input2="$file"
			sed 's/<013><010>/\n/g' "$file" | sed 's/<010>/\n/g' | sed 's/<013>/\n/g' > "$file.kiwi"
			file="$file.kiwi"; tmpfile=2
#			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")									

		elif [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			sample=$(awk '{print $5}' <<< "$sample")						# cut -d' ' -f5)
			if [[ $sample =~ SIPMESSAGE: ]]; then
				vsyslog=1
			else
				error=3
			fi

		elif [[ $sample =~ ^[12][0-9]{3}-[0-9]{2}-[0-9]{2}\ [0-9]{2}\: ]]; then							# MEGA syslog
			vsyslog=7

		elif [[ $sample =~ :\ INFO ]]; then
			sample2=$(awk -F": INFO    : " '{print $2}' <<< $sample)
			if [[ $sample2 =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				egrep "SIPMESSAGE" < "$file" 2>/dev/null | awk -F": INFO    : " '{print $2}' > "$file.syslog"		# H175/log35.txt
				if [[ $? == 0 ]] && [ -s "$file.syslog" ]; then
					file="$file.syslog"; tmpfile=2
					if [[ ${#sample} -lt 160 ]]; then
						vsyslog=175
					else																				# log35.txt SIPMESSAGE no linebreaks
						echo -e "\nALERT: input file includes SIPMESSAGEs in unrecognized format (no linebreaks?).  Contact developer."
						error=3
					fi
				else
					echo -e "error: could not extract SIPMESSAGEs from $basefile"
					error=3
				fi
			fi
		else
			error=3
		fi

	elif [[ $(($rec3)) -gt 0 ]]; then																	# ANB file after converted into .sipmessages
			vsyslog=10
#	elif [[ $footprint == 1 ]]; then			
	elif [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
		footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
		if [[ $footprint == 1 ]]; then
			echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
		fi
	elif [[ $var != $file ]] && [[ $((vsyslog)) == 0 ]]; then
		echo -e "\nerror: Unknown log format. Verify source and content of $bvar -> $basefile.\n"
		error=2; return
	elif [[ $((vsyslog)) == 0 ]]; then
		echo -e "\nerror: Unknown log format. Verify source and content of $bvar.\n"
		error=2; return

#		else
# if match to Jan 17 15:04:46 135.64.97.139 SIPMESSAGE: +02:00 2023 264 1 .TEL | 0 [Part 01 of 02]      # SYSLOG from PCAP		
# then it is good
# else
#			error=3
	fi

	if [[ $((vsyslog)) == 0 ]] || [[ $error == 3 ]] && [[ $((vsyslog)) != 2 ]]; then
		echo -e "\nerror: $basefile has unknown log format."
		echo -e "Verify source and content of $bvar\n"
		return
	fi

#	if [[ $((vsyslog)) == 10 ]]; then
#		rec=$(egrep -c "^CSeq:" "$file" 2>/dev/null)
#	else
# 		rec=$(egrep -c "SIPMESSAGE:" "$file" 2>/dewv/null)
#	fi

	if [[ $((vsyslog)) != 0 ]]; then

		if [[ $((rec)) == 0 ]] && [[ $((rec3)) != 0 ]]; then
			rec=$rec3
		fi
		if [[ $((rec)) -gt 500 ]]; then
			echo "Warning: about to convert a logfile with $rec SIP messages"
			echo -e "This could take a while... you may want to execute the script on a more powerful PC or server.\n"
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
			echo -e "\nALERT: expecting SYSLOG extracted from Wireshark but could not find any lines with <16x> pattern."
			echo "Could $var be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
			echo -e "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing...\n"
			error=3; return
		elif [[ $((vsyslog)) == 20 ]] && [[ $((check)) != 0 ]]; then
			echo -e "\nALERT: expecting SYSLOG collected by KIWI or other tools but found some lines with <16x> pattern."
			echo "Could $var be a SYSLOG extracted from Wireshark instead of remote SYSLOG via KIWI or other tools?"
			echo -e "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing...\n"
			error=3; return
		fi

		bakfile=""; output=""; 	bfile=""

		if [[ $basefile != "" ]] && [[ $basefile == *"."* ]]; then
			bfile=${basefile%.*}
		fi

		if [[ $var != $basefile ]] && [[ $basefile != $file ]]; then
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
			bakfile=$output
		elif [[ $file != "" ]]; then
			newfile="$file.asm.tmp"
			bakfile="$file"
		fi

		if [ -f "$newfile" ]; then
			mv "$newfile" "$bakfile.asm.bak"
		fi

		echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
		echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
		echo "# Command line: $args" >> "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
		echo "# Input: $var" >> "$newfile"		

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $output.asm\n" >> "$newfile"
		fi

#	if [[ $var != $file ]]; then
#			if [[ $input2 != "" ]] && [[ $file != "" ]] && [[ $var != $input2 ]]; then
#				echo -e "# Input/output file: $var -> $input2 -> $file -> $output.asm\n" >> "$newfile"
#			elif [[ $file != "" ]] && [[ $file != $output ]]; then
#				echo -e "# Input/output file: $var -> $file -> $output.asm\n" >> "$newfile"
#			fi
#		else 
#			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"
#		fi

		case $((vsyslog)) in
 		1|2|3)	 	convert_EndpointLog;;
	 	6) 			convert_syslog_visual;;						# by default, VisualSyslog ExportAll saves SIP messages in reverse order !!!
 		7|20)		convert_syslog_mega;;						# KIWI has been transformed into MEGA
	 	8)			convert_syslog_tftpd64;;
 		9)			convert_syslog_interactive;;				# by default, Interactive Syslog ExportAll saves SIP messages in reverse order !!!
	 	10|11)		convert_ANB;;								# 11 exist only due to bug in extract_sipmessages sed converter in (10)
		esac

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi
		
		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error\n\n"

        elif [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm file"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $var file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    have been converted for addr=$endptaddr into $output.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				server=""; server=$(egrep -m 1 "^Server:" "$newfile" 2>/dev/null)
				if [[ $foundipaddr != "" ]] && [[ $foundipaddr != "0.0.0.0" ]]; then
					if [[ ${#useragent} -lt 19 ]]; then
						echo -e "\n\tUser-Agent: $useragent\t\t\t\t ipaddr = $foundipaddr"
					elif [[ ${#useragent} -lt 27 ]]; then
						echo -e "\n\tUser-Agent: $useragent\t\t\t ipaddr = $foundipaddr"
					else
						echo -e "\n\tUser-Agent: $useragent\t ipaddr = $foundipaddr"
					fi
				else
					echo -e "\n\tUser-Agent: $useragent"
				fi

				if [[ $server != "" ]]; then
					if [[ $input != "" ]] && [[ ${#server} -lt 68 ]]; then
						echo -e "\t\t$server"
					else
						echo -e "\t$server"
					fi
				fi
			fi

			echo -e "\tTotal # of lines digested:\t\t\t $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
#				if [[ $((sipmaxsplit)) != 0 ]]; then
#					echo -e "\tSplit SIP messages (RX/TX):\t\t\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts"
#					echo -e "# Split SIP messages (RX/TX):\t\t\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts" >> "$newfile"
#					echo -e "\tLargest split SIP message:\t\t\t $sipmaxpart parts at msg #$sipmaxpartmsg ($sipmaxpartsipword)"
#					echo -e "# Largest split SIP message:\t\t\t $sipmaxpart parts at msg #$sipmaxpartmsg ($sipmaxpartsipword)" >> "$newfile"
#				fi
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg #$longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg #$longestmsg ($longestsipword)" >> "$newfile"
				if [[ $((nINFO)) != 0 ]]; then
					echo -e "\tINFO messages ignored:\t\t\t\t $nINFO"
				fi
				if [[ $((sipbadmsg)) != 0 ]]; then
					echo -e "\tBad SIP messages (eg \"Part\" starts with \"02\"):\t $sipbadmsg at msg #$sipbadmsgnum"
					echo -e "# Bad SIP messages (eg \"Part\" starts with \"02\"): $sipbadmsg at msg #$sipbadmsgnum" >> "$newfile"
				fi
				if [[ $((sipbadtime)) != 0 ]]; then
					echo -e "\tBad SIP messages (timestamps out of order):\t $sipbadtime at msg #$sipbadtimemsg"
					echo -e "# Bad SIP messages (timestamps out of order):\t $sipbadtime at msg #$sipbadtimemsg" >> "$newfile"
				fi
				if [[ $((sipmaxsplit)) != 0 ]]; then			# .log.sipmessages are already re-constructed - do not expect split stat
					echo -e "\tSplit SIP messages (with 2 or more parts):\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts maxpart: $sipmaxpart msg# $sipmaxpartmsg $sipmaxpartsipword"
					echo -e "\tSplit SIP messages (with 2 or more parts):\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts maxpart: $sipmaxpart msg# $sipmaxpartmsg $sipmaxpartsipword" >> "$newfile"
				fi
				if [[ $((base64decode)) != 0 ]] && [[ $((base64msg)) != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
				fi
				let length1=${#firstmsg}
				let length2=${#lastmsg}
				length1=$((length1+${#timefirst}))
				length2=$((length2+${#timelast}))
				if [[ $length1 -lt 35 ]] && [[ $length2 -lt 35 ]]; then
					if [[ $length1 -lt 29 ]]; then
						echo -e "\tFirst msg: $firstmsg $timefirst\t\t Last msg: $lastmsg $timelast"
					else
						echo -e "\tFirst msg: $firstmsg $timefirst\t Last msg: $lastmsg $timelast"
					fi
				else
					if [[ ${#firstmsg} -lt 8 ]]; then
						echo -e "\tFirst msg:\t$firstmsg\t\t\t\t $timefirst"
					elif [[ ${#firstmsg} -lt 17 ]]; then
						echo -e "\tFirst msg:\t$firstmsg\t\t\t $timefirst"
					else
						echo -e "\tFirst msg:\t$firstmsg\t $timefirst"
					fi
					if [[ ${#lastmsg} -lt 8 ]]; then				
						echo -e "\tLast  msg:\t$lastmsg\t\t\t\t $timelast"
					elif [[ ${#lastmsg} -lt 17 ]]; then
						echo -e "\tLast  msg:\t$lastmsg\t\t\t $timelast"
					else
						echo -e "\tLast  msg:\t$lastmsg\t $timelast"
					fi
				fi

				if [[ $findANI != "" ]] && [[ $callID != "" ]] && [[ $calltime != "" ]]; then
					if [[ $callDIR == 1 ]]; then
						echo -e "\tIncoming call from $findANI at $calltime\t\t $callID"
					elif [[ $callDIR == 2 ]]; then
						echo -e "\tOutgoing call to $findANI at $calltime\t\t $callID"
					fi
				fi
				if [[ $((extractppm)) != 0 ]] && [[ $ppmfile != "" ]]; then
					echo -e "\tPPM messages have been extracted into $ppmfile"
					ppmfile=""
				fi			
			fi		
		fi

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
		else
			echo "conversion ended with error code: $error n=$n sipwords=$sipwordlist"
		fi

		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.2f "$(($((n)) * 100 / $tmpsec))e-2")
			echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: $avgmsg\t Time spent: $SECONDS sec\n"
		else
			echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t Time spent: $SECONDS sec\n"
		fi
		currtime=$(date +%R:%S)	

		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd; ls -l "$output.asm"			
		echo ''

		if [[ $((error)) == 0 ]] && [[ $((bCAT)) != 0 ]] && [[ $((n)) != 0 ]]; then
			echo -e "\n# ///////////////////////////////////////////////////////////////////////////////////////" >> "$ctarget"
			echo -e "# CAT $basefile into $ctarget" >> "$ctarget"
			echo -e "# ///////////////////////////////////////////////////////////////////////////////////////\n" >> "$ctarget"			
			cat "$output.asm" >> "$ctarget"
			echo "Converted $basefile into $output.asm, and concatenated it into $ctarget."
			echo ''; ls -l "$ctarget"				
			echo ''
		fi
	fi

elif [[ $file != "" ]]; then
		echo -e "\nerror: $file was not found in the current folder: $PWD\n"
		error=9
else
	echo -e "\nerror: convert_siplog() received null string for input. Contact developer.\n"
	error=6
fi
} # convert_siplog()

function explore_logfolder () {								# explore the potential log files found in current folder
if [[ $destdir != "" ]]; then
	targetfiles=""; targetX=""; xfile=""
#	targetX=""; targetX=$(ls -r -t1 avaya_phone.log.[1-7] 2>/dev/null)
	targetX=""; targetX=$(ls avaya_phone.log.[1-7] 2>/dev/null)	
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetX != "" ]]; then
		targetfiles="$targetX"
	fi

#	targetX=""; targetX=$(ls -r -t1 avaya_phone.log.[1-7].gz 2>/dev/null)
	targetX=""; targetX=$(ls avaya_phone.log.[1-7].gz 2>/dev/null)	
	if [[ $? == 0 ]]; then
		for xfile in $targetX
		do
			xtype=$(file -b "$xfile")
			bxfile=$(basename "$xfile" .gz)
#			xtype2=$(file -bZ "$xfile")
			if [[ $bUnzip != 0 ]] && [[ $xtype =~ compressed ]]; then
				gunzip -q "$xfile" 2>/dev/null
				if [[ $? != 0 ]]; then
					echo -e "\nerror: unable to uncompress $bvar -> $xfile, using \"gunzip\" utility.\n"
				elif [[ $targetfiles != "" ]]; then
					targetfiles="$targetfiles $bxfile"
				else
					targetfiles="$bxfile"
				fi
			fi
		done
	fi

#	targetX=""; targetX=$(ls -r -t1 EndpointLog_B+sig+CPS.txt.[1-9] 2>/dev/null)
	targetX=""; targetX=$(ls EndpointLog_B+sig+CPS.txt.[1-9] 2>/dev/null)	
	if [[ $? == 0 ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 EndpointLog_B+sig+CPS.txt 2>/dev/null)
	if [[ $? == 0 ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; xtargetfiles="EndpointLog_bak.txt EndpointLog_prev.txt EndpointLog.txt avaya_phone.log.before_reboot avaya_phone.log"		# TODO: verify chronological order
	for xfile in $xtargetfiles
	do
		targetX=$(ls -t1 "$xfile" 2>/dev/null)
		if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
			if [[ $targetfiles != "" ]]; then
				targetfiles="$targetX $targetfiles"
			else
				targetfiles="$targetX"
			fi
		fi
	done

	file=""; filelist=""; xfile=""
	if [[ $((alllogs)) == 0 ]] && [[ $targetfiles != "" ]]; then
		xfile=$(head -1 <<< $targetfiles)
		filelist=""
	elif [[ $targetfiles != "" ]]; then
		for xfile in $targetfiles
		do
			if [ -s "$xfile" ]; then
				if [[ $file == "" ]]; then					
					file="$destdir/$xfile"
				fi
				if [[ $((alllogs)) != 0 ]]; then
					if [[ $filelist == "" ]]; then
						filelist="=$destdir/$xfile"
					else
						filelist="$filelist=$destdir/$xfile"
					fi
				fi
			fi
		done
	else
		xfile=""
	fi
	if [[ $xfile != "" ]] && [ -s "$xfile" ]; then
		file="$destdir/$xfile"
	fi
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
	fi

	let bAvayaDir=0
	origdestdir="$destdir"	

	if [ -d "Avaya" ]; then									# typical usecase: %APPDATA% roaming folder
		destdir="$destdir/Avaya"
		cd "Avaya"

		if [ -d "Avaya Endpoint" ]; then
			destdir="$destdir/Avaya Endpoint"
			cd "Avaya Endpoint"
			if [ -d "LogFiles" ]; then
				destdir="$destdir/LogFiles"
				target="$target-AvayaEndpointLogFiles"
				cd "LogFiles"
			elif [ -d "Log Files" ]; then
				destdir="$destdir/Log Files"
				target="$target-AvayaEndpointLogFiles"
				cd "Log Files"
			else
				target="$target-AvayaEndpoint"
			fi
		else
			target="$target-Avaya"
		fi

	elif [ -d "Avaya Endpoint" ]; then
		destdir="$destdir/Avaya Endpoint"
		cd "Avaya Endpoint"
		if [ -d "LogFiles" ]; then
			destdir="$destdir/LogFiles"
			target="$target-AvayaEndpointLogFiles"
			cd "LogFiles"
		elif [ -d "Log Files" ]; then
			destdir="$destdir/Log Files"
			target="$target-AvayaEndpointLogFiles"
			cd "Log Files"
		else
			target="$target-AvayaEndpoint"
		fi

	elif [ -d "Avaya VDI Communicator" ]; then
		if [ -d "Avaya VDI Communicator/logs" ]; then
			destdir="$destdir/Avaya VDI Communicator/logs"
			cd "Avaya VDI Communicator/logs"
		else
			destdir="$destdir/Avaya VDI Communicator"
			cd "Avaya VDI Communicator"
		fi

	elif [ -d "Avaya Equinox VDI" ]; then
		if [ -d "Avaya Equinox VDI/logs" ]; then
			destdir="$destdir/Avaya Equinox VDI/logs"
			cd "Avaya Equinox VDI/logs"
		else
			destdir="$destdir/Avaya Equinox VDI"
			cd "Avaya Equinox VDI"
		fi

	elif [ -d "Avaya Workplace VDI" ]; then
		if [ -d "Avaya Workplace VDI/logs" ]; then
			destdir="$destdir/Avaya Workplace VDI/logs"
			cd "Avaya Workplace VDI/logs"
		else
			destdir="$destdir/Avaya Workplace VDI"
			cd "Avaya Workplace VDI"
		fi

	elif [ -d "setup/eLux/.workplace-vdi/logs" ]; then									# TODO: what was the folder name on eLux for Equinox VDI or VDI-C?
		destdir="$destdir/setup/eLux/.workplace-vdi/logs"
		cd "setup/eLux/.workplace-vdi/logs"

	elif [ -d "setup/eLux/.equinox-vdi/logs" ]; then
		destdir="$destdir/setup/eLux/.equinox-vdi/logs"
		cd "setup/eLux/.equinox-vdi/logs"

	elif [ -d "setup/eLux/.vdi-communicator/logs" ]; then
		destdir="$destdir/setup/eLux/.vdi-communicator/logs"
		cd "setup/eLux/.vdi-communicator/logs"

	elif [ -d "home/eLux/.workplace-vdi/logs" ]; then
		destdir="$destdir/home/eLux/.workplace-vdi/logs"
		cd "home/eLux/.workplace-vdi/logs"

	elif [ -d "home/eLux/.equinox-vdi/logs" ]; then
		destdir="$destdir/home/eLux/.equinox-vdi/logs"
		cd "home/eLux/.equinox-vdi/logs"

	elif [ -d "home/eLux/.vdi-communicator/logs" ]; then
		destdir="$destdir/home/eLux/.vdi-communicator/logs"
		cd "home/eLux/.vdi-communicator/logs"

	elif [ -d "eLux/.workplace-vdi/logs" ]; then
		destdir="$destdir/eLux/.workplace-vdi/logs"
		cd "eLux/.workplace-vdi/logs"

	elif [ -d "eLux/.equinox-vdi/logs" ]; then
		destdir="$destdir/eLux/.equinox-vdi/logs"
		cd "eLux/.equinox-vdi/logs"

	elif [ -d "eLux/.vdi-communicator/logs" ]; then
		destdir="$destdir/eLux/.vdi-communicator/logs"
		cd "eLux/.vdi-communicator/logs"

	elif [ -d ".workplace-vdi/logs" ]; then
		destdir="$destdir/.workplace-vdi/logs"
		cd ".workplace-vdi/logs"
		
	elif [ -d ".equinox-vdi/logs" ]; then
		destdir="$destdir/.equinox-vdi/logs"
		cd ".equinox-vdi/logs"

	elif [ -d ".vdi-communicator/logs" ]; then
		destdir="$destdir/.vdi-communicator/logs"
		cd ".vdi-communicator/logs"

	elif [ -d "LogFiles" ]; then
		destdir="$destdir/LogFiles"
		target="$target-LogFiles"
		cd "LogFiles"

	elif [ -d "Log Files" ]; then
		destdir="$destdir/Log Files"
		target="$target-LogFiles"
		cd "Log Files"

	elif [ -d "AvayaDir" ]; then
		if [ -d "AvayaDir/var/log" ]; then
			destdir="$destdir/AvayaDir/var/log"
			target="$target-AvayaDir"
			cd "AvayaDir/var/log"
		fi
		if [ -d "AvayaDir/SIP/application/LogFiles" ]; then
			bAvayaDir=1
		elif [ -d "AvayaDir/application/LogFiles" ]; then
			bAvayaDir=1
		fi

	elif [ -d "var/log" ]; then																	# for H175
		destdir="$destdir/var/log"
		cd "var/log"

	elif [ -d "log" ] || [ -d "logs" ]; then
		if [ -d "log" ]; then
			destdir="$destdir/log"
			target="$target-log"
			cd "log"
		elif [ -d "logs" ]; then
			target="$target-logs"
			if [ -d "logs/log" ]; then
				destdir="$destdir/logs/log"
				cd "logs/log"
			else
				destdir="$destdir/logs"
				cd "logs"
			fi
		fi
	fi

	explore_logfolder

	cd "$origdestdir"; destdir="$origdestdir"

    if [ -f "REPORT.txt" ]; then
        ncore=$(egrep -c "\.core" "REPORT.txt" 2>/dev/null)
		if [[ $((ncore)) != 0 ]]; then
           	echo "ALERT: found coredump files in $folder -> REPORT.txt"
			egrep "\.core" REPORT.txt 2>/dev/null
			echo ''
		fi
	fi

	if [[ $bAvayaDir != 0 ]]; then
		if [ -d "AvayaDir/application/LogFiles" ]; then
			destdir="$destdir/AvayaDir/application/LogFiles"
			target="$target-AvayaDir"
			cd "AvayaDir/application/LogFiles"
		elif [ -d "AvayaDir/SIP/application/LogFiles" ]; then
			destdir="$destdir/AvayaDir/SIP/application/LogFiles"
			target="$target-AvayaDir"
			cd "AvayaDir/SIP/application/LogFiles"
		fi

		if [ -s "EndpointLog_bak.txt" ]; then
			if [[ $filelist != "" ]]; then
				filelist="=$destdir/EndpointLog_bak.txt$filelist"					
			fi
			file="$destdir/EndpointLog_bak.txt"
		fi
		if [ -s "EndpointLog_prev.txt" ]; then
			if [[ $filelist != "" ]]; then
				filelist="=$destdir/EndpointLog_prev.txt$filelist"					
			fi
			file="$destdir/EndpointLog_prev.txt"
		fi
		if [ -s "EndpointLog.txt" ]; then
			if [[ $filelist != "" ]]; then
				filelist="=$destdir/EndpointLog.txt$filelist"					
			fi
			file="$destdir/EndpointLog.txt"
		fi
	fi
	
	cd "$origdestdir"; destdir="$origdestdir"
	if [ -d "var/volatile/tmp/logs" ]; then
		destdir="$destdir/var/volatile/tmp/logs"
		cd "var/volatile/tmp/logs"
		if [ -f "avaya_phone.log" ]; then
			if [[ $filelist != "" ]]; then
				filelist="=$destdir/avaya_phone.log$filelist"					
			fi
			file="$destdir/avaya_phone.log"
		fi
	fi

	if [[ $file == "" ]]; then
		error=1
		echo "error: could not find any 96x1SIP/J1xxSIP/H175/VDIC related logs in $folder"		
	fi
	cd "$currdir"
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

################################# MAIN Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts "e:i:hk:bdf:rsu:v:ICAPN:" options; do
	case "${options}" in
	h)
		usage; exit 0;;
	A)
		alllogs=1;;
	C)
		bCAT=1;;
	I)
		noINFO=1;;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	P)
		extractppm=1;;			
	r)	
		bReverse=1;;		
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;
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
	u)	udp=${OPTARG};;
	v)  vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 20 ]]; then
			vsyslog=1
		else
			fixVSYSLOG=1
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
bUnzip=0
bGunzip=0
ctarget=""
origctarget=""

file --help >/dev/null 2>&1
if [[ $? != 0 ]]; then
	echo -e "\nerror: unable to find "file" utility.  You may want to install it with "apt install file" command."
	echo -e "This tool relies heavily upon "file" command. Cannot continue execution. Aborting...\n"
	exit 1
fi

if [[ $((base64decode)) != 0 ]]; then
   base64 --version >/dev/null
   if [[ $? != 0 ]]; then
	  base64decode=0
   fi
fi
cmdtest=$(unzip -qq -v >/dev/null 2>&1)
if [[ $? == 0 ]]; then
	bUnzip=1
fi
gunzip --version >/dev/null 2>&1
if [[ $? -le 1 ]]; then
	bGunzip=1
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
		elif [[ $var == "-N"* ]]; then
			skipper=6
		elif [[ $var == "-u"* ]]; then
			skipper=7	
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
		elif [[ $((skipper)) == 6 ]]; then
			findANI=$findANI		# findANI=$var
		elif [[ $((skipper)) == 7 ]]; then
			udp=$var
		fi
		skipper=0; continue
	fi

	n=0; 		error=0;	tmpfile=0
	bdir="";	bvar=""; 	folder=""
	target=""; 	destdir="";	input=""; input2=""	
	file=""; 	filelist="";basefile=""
	currtime=$(date +%R:%S);currdir=$PWD	

	if [[ $((fixVSYSLOG)) == 0 ]]; then
		vsyslog=0
	fi
	
	bSinglefile=0	
	filecontent="96x1"	
	filetype=$(file -b "$var")
	filetype2=$(file -bZ "$var")
	bdir=$(dirname "$var")
	bvar=$(basename "$var")
	if [[ $var == $bvar ]]; then
		bvar=$(basename "$var" .tar)
		if [[ $var == $bvar ]]; then
			bvar=$(basename "$var" .tgz)
			if [[ $var == $bvar ]]; then
				bvar=$(basename "$var" .gz)
			else
				bvar=$(basename "$var" .zip)
			fi
		fi
		target="$bvar"
		bvar=$(basename "$var")
	elif [[ $var == "." ]]; then
		target="96x1"
	else
		target=$bvar		
	fi

#	target=${target%%.*}										# TODO: what about ../folder or ../filename - note the leading ".."	
	if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
		target=${target%.*}
		if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
			target=${target%.*}
		fi
	fi

	if [ -d "$var" ]; then
		echo -en "\nExploring content in \"$var\" folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders

	elif [ -s "$var" ];then
		echo -en "\nExploring content in $var... stand by\r"
		file="$var"; basefile="$bvar"
		sample=""; sample2=""	
		filecontent="Emulator"

		if [[ $filetype == "7-zip archive"* ]]; then
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."
			error=99; continue

		elif [[ $filetype == "RAR archive"* ]]; then
			echo -e "\nerror: unfortunately, thist script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."
			error=99; continue

		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "Emulator" ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")			
			fi

			if [[ $bvar == *"."* ]]; then
				input=${bvar%.*}
			else
				input="$bvar"
			fi
			if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then										
					echo -e "\nerror: could not delete existing $input.tmp folder."
					echo -e "Check if any subfolders or files currently open (in other shell sessions)."
					echo -e "Unable to unzip $bfile into a temp folder. Skipping this file...\n"
					error=7; cd $currdir; input=""; continue
				fi
			fi

#			target=$(basename "$input")
#			target=${target%%.*}
			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bfile into a temp folder. Skipping this file...\n"
				input=""; error=7; cd $currdir; continue
			fi

			if [[ $bUnzip != 0 ]] && [ -d "$input.tmp" ]; then
				cd "$input.tmp"
				echo -e "\nUncompressing $basefile into $input.tmp ...                              "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress $bfile, using \"unzip\" utility. Skipping this file..."
					echo -e "Suggesting to validate \"unzip -qq $bfile\" command manually.\n"
					cd "$currdir"; input=""; error=8; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
					cd $currdir
				fi
			fi
		fi

		if [[ $filetype =~ data ]] && [[ ! $filetype =~ Zip|compressed ]] && [[ $filetype2 != *"tar"* ]]; then		# is this an H175 debugreport?  VDIC logreport does not support encryption (yet)
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file" 2>/dev/null)
			recX=$(egrep -a -c -m 1 "CSeq:" "$file" 2>/dev/null)
			if [[ $filecontent =~ ANDROID ]]; then								# sometimes "file vantage.log" reports data instead of ASCII text
				filecontent="ANDROID"
			elif [[ $filetype2 =~ ASCII ]] && [[ $enckey != "" ]]; then
				openssl version >/dev/null 2>&1
				if [[ $? == 0 ]]; then
					if [[ $bvar == *"."* ]]; then
						input=${bvar%.*}
					else
						input="$bvar"
					fi

#					outfile=$outfile"-decrypted.tgz"
					openssl aes-128-cbc -d -salt -k $enckey -in "$var" -out "$input-decrypted.tgz"
					if [[ $? != 0 ]] || [[ $(file -b "$input-decrypted.tgz") == "data" ]]; then
						echo -e "error: Could not decode $file using openssl - verify encryption key with provider of $bvar\n"
						filecontent="error"; error=6; continue
					else
						file="$input-decrypted.tgz"; tmpfile=2
						basefile=$(basename "$file")
						filetype=$(file -b "$file")
						filecontent="H175"
						echo "Decoded $bvar into $basefile successfully using \"openssl\"."						
					fi
				else
					echo -e "error: \"openssl\" was not found, required for decoding $bvar - need to decode this file manually.\n"
					error=5; exit $error
				fi
			elif [[ $((recX)) == 0 ]]; then
				echo "error: $bvar appears to be an H175 encrypted debugreport."
				echo -e "Please provide the encryption key with -e option.\n"
				error=7; exit $error
			fi				
		fi

		if [[ $filetype == *"compressed data"* ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				zfile="$file"
				bfile=$(basename "$file")
				filetype2=$(file -bZ "$file")
			else
				zfile="$var"
				bfile=$(basename "$var")
				filetype2=$(file -bZ "$var")
			fi

			if [[ $filetype =~ compressed ]] && [[ $filetype2 =~ ASCII|text|data|capture|tar ]]; then
				if [[ $bfile == *"."* ]]; then
					input2=${bfile%.*}
				else
					input2="$bfile"
				fi

				if [[ $bGunzip != 0 ]]; then
					echo "Uncompressing $zfile into $input2 ...                                     "
					gunzip -q -c "$zfile" > "$input2" 2>/dev/null

					if [[ $? -le 1 ]]; then
						file="$input2"; tmpfile=2
						basefile=$(basename "$file")
						filetype=$(file -b "$file")
					else
						echo -e "\nerror: failed to uncompress $bfile, using \"gunzip\" utility.\n"
						error=8; continue
					fi
				else
					echo -e "\nerror: unable to uncompress $bfile, \"gunzip\" utility not found.\n"
					error=8; continue
				fi
			fi
		fi

		if [[ $filetype =~ tar ]] || [[ $filetype2 =~ tar ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")			
			fi

			tar --version >/dev/null 2>&1
			if [[ $? == 0 ]]; then
				if [[ $bfile == *"."* ]]; then
					input=${bfile%.*}					
				else
					input="$bfile"
				fi

				if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp" 2>/dev/null
					if [[ $? != 0 ]]; then						
						echo -e "\nerror: could not delete existing temp folder: $input.tmp"
						echo "Check if any subfolders or files are open (in other shell sessions).\n"
						error=7; cd $currdir; input=""; continue
					fi
				fi

				mkdir "$input.tmp"
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd $currdir; input=""; continue
				fi

				cd "$input.tmp"
				echo "Extracting $bfile ...                                                                              "

				if [[ $filetype =~ compressed ]] && [[ $filetype2 =~ tar ]]; then
					tar zxf "../$file" 2>/dev/null
				elif [[ $filetype =~ tar ]]; then
					tar xf "../$file" 2>/dev/null				
				fi

				if [[ $? != 0 ]]; then
					if [[ $bGunzip != 0 ]]; then
						gunzip -q "../$file" 2>/dev/null
						if [[ $? != 0 ]]; then
							echo -e "error: could not uncompress $bfile, using neither \"tar\" nor \"gunzip\" utilities.\n"
							error=8; cd $currdir; input=""; continue
						else
							tar xf $input 2>/dev/null										# TODO verify the exact new filename after gunzip
							if [[ $? != 0 ]]; then
								cd ..; rm -rf "$input.tmp"						
								echo -e "\nerror: failed to uncompress $bfile, using \"tar\" utility.\n"
								error=8; cd $currdir; input=""; continue
							else
								destdir="$PWD"; tmpfile=1
								folder="$input"
								explore_folders
							fi
						fi
					else 
						cd ..; rm -rf "$input.tmp"						
						echo -e "error: failed to uncompress $bfile, using \"tar\" utility.\n"
						error=8; cd $currdir; input=""; continue
					fi
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"					
					explore_folders
				fi
				cd $currdir				
			else
				echo -e "\nerror: unable to uncompress $bvar, \"tar\" utility not found.\n"
				error=1; continue
			fi

		elif [[ $filetype =~ capture ]]; then
			if [[ $filetype =~ tcpdump|pcap ]]; then
		  		line=$(whereis tshark)
				tshark --version 2>&1 >/dev/null
				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
		     		echo -e "\nerror: unable to locate 'tshark' command"
					echo "'tshark' is required to extract syslog messages from $bvar into text file"
					echo -e "in Ubuntu, you can install it by typing: \"sudo apt install tshark\".\n"
					error=10; exit $error
				else																					# TODO: -u UDPPORT (if using non-defaul 514 port)
					origfile=$file
					if [[ $endptaddr != "" ]]; then
		    			tshark -r "$file" -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else						
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi

					if [[ $? == 0 ]] && [ -s "$file.syslog2" ]; then
						n=$(egrep -m 1 -c "\n[RT]X\ " "$file.syslog2" 2>/dev/null)
						if [[ $((n)) != 0 ]]; then
							echo -e "\nExtracting syslog out of $file ..."
#							sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
#							sed 's/\\r\\n\ /\'$'\n''/g' < "$file.syslog2" | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
#							egrep "SIPMESSAGE:" "$file.syslog2" | sed 's/\\r\\n\ /\'$'\n''/g' | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
							egrep "SIPMESSAGE:" "$file.syslog2" | sed 's/\\r\\n\ /\'$'\n''/g' | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' | sed 's/&lt;/\</g' | sed 's/&gt;/\>/g' > "$file.syslog"
							file="$file.syslog"; tmpfile=2
							vsyslog=2							
						else
							file="$file.syslog2"; tmpfile=2
							vsyslog=2
						fi					
#						vsyslog=11

						if [[ $((extractppm)) != 0 ]]; then		# extract from either SYSLOG or HTTP
							ppm=0; ppm=$(egrep -c "PPMMESSAGE:" "$file" 2>/dev/null)
							if [[ $((ppm)) != 0 ]]; then
								ppmfile="$file.ppm.tmp"	
								echo "Extracting PPM messages from $file..."
								egrep "PPMMESSAGE:" "$file" > "$ppmfile"
								splitppm=0
								while IFS= read -r line
								do
									if [[ $line =~ PPMMESSAGE: ]]; then
										if [[ $((splitppm)) == 0 ]]; then
											get_sip_datetime
											if [[ $line =~ \[Part\ 01 ]]; then
												splitppm=1
											fi
										else
											line=$(echo "$line" | awk -F"\]\\n")  # !!!!!!!!!! imcomplete AWK - this is BUG
										fi
									fi
								done < "$ppmfile"
								mv $ppmfile "$file.ppm"
							fi

							echo "Checking HTTP for unsecured PPM traffic in $file..."
							if [[ $endptaddr != "" ]]; then
				    			tshark -r "$origfile" -S=== -2Y "ip.addr==$endptaddr && http" -t ad -T fields -E separator="#" > "$origfile.http1"
							else						
#		    					tshark -r "$file" -S=== -2Y "http" -t ad -T fields -E separator="#"  > "$file.http1"
		    					tshark -r "$origfile" -S=== -2Y "http"   > "$origfile.http1"
								echo "Created $origfile.http1 file"
							fi
							echo "Under construction..."; exit 999							
						fi

					else
						echo -e "\nerror: either could not execute tshark or extract SYSLOG packets out from $file\n"
						error=11; exit $error
					fi
				fi
	  		fi

		elif [[ $filetype =~ text ]] || [[ $filetype == "data" ]]; then
			filelist=""
			filecontent="ASCII"
			bSinglefile=1

		elif [[ $file == "" ]] && [[ $error == 0 ]]; then
			echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
			error=4
		fi

	elif [[ $filetype =~ cannot|open ]]; then
		echo -e "\nerror: $bvar was not found. Verify path and filename."
		error=3

	elif [[ $file == "" ]] && [[ $error == 0 ]]; then
		echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
		error=4

	elif [ -f "$var" ]; then
		echo -e "\nerror: $bvar is an empty file."
		ls -l "$var"; error=3
	fi

	if [[ $((error)) != 0 ]]; then
		continue
	fi

	if [[ "$filelist" != "" ]] && [[ $file != $filelist ]]; then
		bSinglefile=0
	else
		bSinglefile=1					
	fi

	if [[ $((bCAT)) != 0 ]] && [[ $bSinglefile != 0 ]]; then
		if [[ $origctarget == "" ]]; then
			ctarget="$target.casm"
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
#			echo -e "\nConcatenating for $var into $ctarget\n"
			echo -e "# Concatenating for $var\n" > "$ctarget"
			origctarget=$ctarget
		else
			ctarget=$origctarget
		fi
	elif [[ $((bCAT)) != 0 ]]; then
		ctarget="$target.casm"
		if  [ -f "$ctarget" ]; then
			mv "$ctarget" "$ctarget.bak"
		fi
#		echo -e "\nConcatenating for $var into $ctarget\n"
		echo -e "# Concatenating for $var\n" > "$ctarget"
	fi

	nfiles=0; origIFS=$IFS
	if [[ $((alllogs)) != 0 ]] && [[ "$filelist" != "" ]]; then
#		nfiles=$(wc -w <<< "$filelist")
		if [[ $filelist =~ ^= ]]; then
			nfiles=$(awk -F"=" '{print NF}' <<< "$filelist")		
			filelist=${filelist:1}
			nfiles=$((nfiles-1))
		fi
		if [[ $((bCAT)) != 0 ]]; then
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
		fi
		IFS="="

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x avaya_phone.log/EndpointLog*.txt)."
			echo "This may take a while... You may want to execute the script on a more powerful PC or server."

			let z=0; file=""
			for file in $filelist;
			do
				if [[ $file != "" ]] && [ -s "$file" ]; then
					IFS=$origIFS				
					z=$(egrep -m 1 -c -e "CSeq:" "$file" 2>/dev/null)
					if [[ $((z)) != 0 ]]; then
						convert_siplog
					else
						bfile=$(basename "$file")					
						echo "Skipping $bfile - no SIP messages have been found."
					fi
					z=0; error=0
				fi
				IFS="="; currtime=$(date +%R:%S)
			done

			if [[ $((bCAT)) != 0 ]] && [ -f "$ctarget" ]; then
				echo -e "All converted files found in $bvar have been concatenated into $ctarget\n"
				ls -l "$ctarget"; echo ''
			fi

		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			IFS=$origIFS
			convert_siplog
		fi
		IFS=$origIFS

	elif [[ "$filelist" != "" ]]; then
		file=$(awk '{print $1}' <<< "$filelist")		# head -1)
#		file="$input.tmp/$file"
		convert_siplog
	elif [[ $file != "" ]]; then
		convert_siplog	
	fi

	if [[ $bDelTemp != 0 ]]; then
		if [[ $input2 != "" ]] && [ -d "$input2.tmp" ]; then
			rm -rf "$input2.tmp" 2>/dev/null
		fi
		if [[ $input != "" ]]; then 
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp" 2>/dev/null
			fi
			if [ -f "$input" ]; then
				rm "$input" 2>/dev/null
			fi
		fi
		if [[ $tmpfile == 2 ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
		fi
	fi
done

if [[ $((converted)) != 0 ]] && [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0