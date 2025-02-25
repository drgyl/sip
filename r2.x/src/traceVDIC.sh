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
bCAT=0
alllogs=0
bDelTemp=1
converted=0
noINFO=0
findANI=""
adjusthour=0
localtime=1
base64decode=1
bIgnoreMonth=0
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
# targetfiles="EndpointLog_bak.txt EndpointLog_prev.txt EndpointLog.txt"			# TODO: verify chronological order
targetfiles="EndpointLog.txt EndpointLog_bak.txt EndpointLog_prev.txt"

voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

# TODO: get VDI logs from IGEL

## 1) from wireshark SYSLOG UDP stream - see ade_vdic_syslog1.txt
## <166>Jan 12 16:43:54 135.105.160.122 SIPMESSAGE: +01:00 2022 562 1 .TEL | 0 [Part 01 of 02]
## <166>Nov 17 11:50:57 135.105.160.122 SIPMESSAGE: +01:00 2020 946 1 .TEL | 0 Inbound SIP message from 198.152.84.100:5061
## 2) created by KIWI Syslog r8.x, default ISO log file format - see EqVDI2-SyslogCatchAll.txt
## 2022-02-08 17:22:43	Local4.Info	135.123.66.134	Feb  8 17:22:43 135.123.66.134 SIPMESSAGE: +01:00 2022 338 1 .TEL | 0 [Part 02 of 02]<010>-id=1<013><010>Content-Length:     0<013>
## challenges: <013><010> } Length is bogus (666), Month is bogus (12)

## H175: 2021-01-29 12:22:32	Local4.Info	10.8.232.36	Jan 29 12:25:09 10.8.232.36 SIPMESSAGE: +01:00 2021 034 1 .TEL | 0 Outbound SIP message to 10.8.12.6:5061<010>TX INVITE sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook SIP/2.0<013><010>From: <sip:2470@smn.rosneft.ru>;tag=6013b855715502b6693p7t1r1q3l5f196nmh5h1k6j6l3o32_F247010.8.232.36<013><010>To: <sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook><013><010>Call-ID: 217_6013b855-7fb11eab4692x5j163b5x70316n6p8336jx5m2c32_I247010.8.232.36<013><010>CSeq: 535 INVITE<013><010>Max-Forwards: 70<013><010>Via: SIP/2.0/TLS 10.8.232.36:1026;branch=z9hG4bK217_6013b8559dc2a981w724ais5q1n3k5x385pw2t4z76442_I247010.8.232.36<013><010>Supported: 100rel,eventlist,feature-ref,replaces,tdialog<013><010>Allow: INVITE,ACK,BYE,CANCEL,SUBSCRIBE,NOTIFY,MESSAGE,REFER,INFO,PRACK,PUBLISH,UPDATE<013><010>User-Agent: Avaya H175 Collaboration Station H1xx_SIP-R1_0_2_3_3050.tar<013><010>Contact: <sip:2470@10.8.232.36:1026;transport=tls>;+avaya-cm-line=1<013><010>Accept-Language: ru<013><010>Expires: 30<013><010>Content-Length:     0<013>

function usage ()  {
    echo "traceVDIC.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceVDIC.sh [<LOG_FILE>, <folder> ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either an EndpointLog.txt from VDIC, 1XA or SparkEmulator,"
	echo -e "\t\t\tEquinox/Workplace for VDI logreport (ZIP file) from Windows, iGEL, eLux platforms"
	echo -e "\t\t\ta syslog stream sent by a VDIC client, captured either via a remote SYSLOG server"
	echo -e "\t\t\tor captured via wireshark (pcap), or extracted using \"Follow UDP stream\" function"
	echo -e "\t  or, a debugreport (encrypted or decrypted), EndpointLog_B_sig_CPS.txt or syslog from a H175 phone"
	echo -e "\t<folder>\ta folder or path including above files eg. \"logs\", \"Avaya Workplace VDI/logs\""	
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-k \t\tset decryption key for debugreport decoding"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: \"a.b.c.d\""			
#	echo -e "\t-i \t\tconvert syslog messages only sent by SM IP addr: a.b.c.d"						
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport where SIP message found"	
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converted multiple logfiles)"
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"		
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"	
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
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
	base64found=0
	emptyline=0
	badmsg=0
	foundipaddr=""
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then	
	sipstart=1; siplines=$((siplines+1))
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
			badmsg=1
			if [[ $sipbadtimemsg == "" ]]; then
				sipbadtimemsg="$sipmsg $siptimeprev $siptime"
			fi
		fi
	fi
	siptimeprev=$siptime

	if [[ $((sipsplit)) != 0 ]]; then
		sipmaxsplit=$((sipmaxsplit+1))
		if [[ $maxpart == "99" ]] || [[ $partnum == "00" ]]; then
			echo -e "\nerror: SIP msg was split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime"
			echo "nlines=$nlines vsyslog=$vsyslog"
			echo -e "Contact developer.\n"

		elif [[ $maxpart != "99" ]]; then

			splitparts=$((splitparts+10#$maxpart-1))
			if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
				sipmaxpart=${maxpart#0}
				sipmaxpartmsg=$sipmsg
				sipmaxpartsipword=$sipword
			fi
			if [[ $partnum != $maxpart ]]; then
				badmsg=1
			fi
		else
			splitparts=$((splitparts+1))				# this will increase number of parts, but we do not know how many parts were actually seen in this sip msg		
		fi
	elif [[ $partnum != "00" ]]; then
		echo -e "error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime"
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
		sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadmsgnum == "" ]]; then
			sipbadmsgnum="$siptotalmsg $siptime"
		fi
	fi

	lastfoundip=$foundipaddr
	reset_sipmsg

else												# cannot complete a SIP message if it did not start properly
	badmsg=1; sipbadmsg=$((sipbadmsg+1))
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
		echo -e "\nerror: failed to grab message header items at msg# $((n+1)) at line# $nlines"
		echo "sipdate=$sipdate siptime=$siptime ip=$ip dirstring=$dirstring1 vsyslog=$vsyslog"
		echo "$line"; exit 1
	else	
		sipstart=0; n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted             \r"
			else
				echo -en "$var => $n/$rec Msgs converted             \r"
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
#		if [[ $partnum == "01" ]] && [[ $((sipsplit)) == 0 ]]; then
		if [[ $partnum == "01" ]]; then
#			if [[ $((sipsplit)) != 0 ]]; then								# existing split SIP msg, but it starts with 01 - could be BAD
#				currpartnum="661"
#			fi
			maxpart=$(awk '{printf "%02i",$3}' <<< "$partline")
		elif [[ $currpartnum == "00" ]]; then								# new SIP msg split, but does not start with 01 - BAD
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
}

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line == *"Inbound SIP"* ]] || [[ $line =~ ^RX\  ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED"; dirstring2="from";;
		3)	dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line == *"Outbound SIP"* ]] || [[ $line =~ ^TX\  ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	fi

	if [[ $line =~ ^RX|^TX ]]; then
		ip="6.6.6.6:6666"

	elif [[ $((dirdefined)) != 0 ]]; then
		if [[ $foundipaddr == "" ]]; then
			if [[ $((vsyslog)) == 10 ]]; then
				foundipaddr=$(cut -d' ' -f1 <<< "$line")
				localip="$foundipaddr:1111"
			elif [[ $((vsyslog)) == 9 ]]; then
				foundipaddr=$(cut -d' ' -f6 <<< "$line")
				localip="$foundipaddr:1111"				
			else
				foundipaddr=$(awk '{print $4}' <<< "$line")
				localip="$foundipaddr:1111"
			fi
		fi

		if [[ $((vsyslog)) == 1 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")
				ip=$ip1:$ip2
			elif [[ $line == *"bound SIP message "* ]]; then
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2
			fi
		
		elif [[ $((vsyslog)) == 2 ]] || [[ $((vsyslog)) == 3 ]]; then
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")				# cut -d' ' -f3  | tr -d "\n")
				ip=$ip1:$ip2
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")	#cut -d':' -f2  | tr -d "\n")
				ip=$ip1:$ip2					
			fi
		elif [[ $((vsyslog)) == 6 ]]; then
# DEBUG	LOCAL4	2/11/2022 4:28:37 PM	135.105.129.244		SIPMESSAGE: +01:00 2022 065 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 10.134.117.194 port: 5061
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")			# cut -d' ' -f3 | tr -d "\n")
				ip=$ip1:$ip2					
			else 
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2
			fi

		elif [[ $((vsyslog)) == 7 ]]; then
# 2022-02-11 16:48:54	20	7	1	135.105.129.244				Feb 11 16:48:52 135.105.129.244 SIPMESSAGE: +01:00 2022 695 1 .TEL | 0 CNetworkInputManager::ProcessInput(): Inbound SIP message from ip = 10.134.117.194 port: 5061				
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")			# cut -d' ' -f3 | tr -d "\n")
				ip=$ip1:$ip2
			else 
				ip=$(awk '{print $(NF-1)}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2					
			fi

		elif [[ $((vsyslog)) == 8 ]]; then
# Fri Feb 11 17:40:45 2022;135.105.129.244; <167>Feb 11 16:40:43 135.105.129.244 SIPMESSAGE: +01:00 2022 483 1 .TEL | 0 [Part 01 of 02]
# CSIPServer::SendToNetwork(): Outbound SIP message to 135.64.253.72:5061		
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")
				ip=$ip1:$ip2					
			else 
#				ip=$(echo "$line" | awk '{print $NF}' | tr -d "\n")		 # TODO: strip off ^M from the end (if any)				
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2					
			fi

		elif [[ $((vsyslog)) == 9 ]]; then
			if [[ $line == *"port:"* ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f3 <<< "$ip")
				ip2=$(awk '{printf "%i,$5}' <<< "$ip")
				ip=$ip1:$ip2
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2
			fi
		elif [[ $((vsyslog)) == 10 ]]; then
			ip1=$(awk '{printf "%i",$3}' <<< "$line")			# cut -d' ' -f3 | tr -d "\r")	# TODO: ANB missing port
			ip2="5061"
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
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 1 ]]; then 								# syslog UDP stream from wireshark
#		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(awk '{print $4}' <<< "$line")
			sipyear=$(awk '{print $7}' <<< "$line")
			sipday=$(awk '{printf "%02i",$2}' <<< "$line")
			if [[ $bIgnoreMonth == 0 ]]; then 
				if [[ $line =~ ^\<1[0-9][0-9] ]]; then
					month=$(awk -F"<16[34567]>" '{print $2}' <<< "$line" | cut -d' ' -f1)
#					month=$(cut -d'>' -f2 <<< "$line" | cut -d' ' -f1)
				else
					month=$(cut -d' ' -f1 <<< "$line")
				fi
				if [[ ${#month} != 3 ]]; then
					sipmonth=${today:0:2}
				else
					get_sipmonth
				fi
			fi
#		fi

		siphour=$(awk '{print $3}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour")			# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour")			# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour")			# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $8}' <<< "$line")
		siptmp=$(awk '{print $6}' <<< "$line")
		
	elif [[ $((vsyslog)) == 20 ]]; then 								 ## KIWI syslog aka SyslogCatchAll
#		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(awk '{print $4}' <<< "$line")
			sipyear=$(cut -d' ' -f1 <<< "$line")						#| cut -d'-' -f1)	# awk -F'-' '{print $1}')
			if [[ $bIgnoreMonth == 0 ]]; then
				sipmonth=$(cut -d'-' -f2 <<< "$sipyear")					# awk -F'-' '{print $2}')
			fi
			sipday=$(cut -d'-' -f3 <<< "$sipyear")						# awk -F'-' '{print $3}')			
			sipyear=$(cut -d'-' -f1 <<< "$sipyear")
#		fi

		siphour=$(awk '{print $7}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour") 					# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour") 					# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour") 				# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $12}' <<< "$line")
		siptmp=$(awk '{print $10}' <<< "$line")
	fi

	if [[ $((adjusthour)) == 1 ]]; then
		tzhour=$(cut -d':' -f1 <<< "$siptmp")		# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
		tzmin=$(cut -d':' -f2 <<< "$siptmp")		# awk -F ':' '{print $2}')
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) 			# TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) 				# TODO need to print 2 digits
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

function convert_EndpointLog () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *" SIPMESSAGE: "* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		elif [[ $line == *" End of "* ]] && [[ $((sipstart)) != 0 ]]; then			# 1xAgent special line	
			complete_sipmsg
		fi

#		if [[ $((vsyslog)) == 1 ]] && [[ $((sipstart)) != 0 ]]; then
		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				complete_sipmsg
#			elif [[ $line =~ [MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			elif [[ $line =~ Part\  ]]; then
				if [[ $line =~ ^\<16[3-7]\> ]]; then
					dummy=0															# dummy statement
				elif [[ $((vsyslog)) == 1 ]] && [[ $line =~ .*\<16[3-7]\> ]]; then
					echo "$line" | awk -F"<16[3-7]>" '{print $1}' >> "$newfile"
					line=$(awk -F"<16[3-7]>" '{print $2}' <<< "$line")					
					siplines=$((siplines+1))
				elif [[ $((vsyslog)) == 1 ]] && [[ $line =~ \ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
					echo "$line" | awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $1}' >> "$newfile"
					line=$(awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $2}' <<< "$line")
					siplines=$((siplines+1))
#				elif [[ $((vsyslog)) == 1 ]] && [[ $line =~ \ [JFMASOND]..?[cglnprtyv]\  ]]; then
#					echo "$line" | awk -F " [JFMASOND]..?[cglnprtyv] " '{print $1}' >> "$newfile"
#					line=$(awk -F " [JFMASOND]..?[cglnprtyv] " '{print $2}' <<< "$line")
#					siplines=$((siplines+1))
				fi
#				line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
				if [[ $partnum == $maxpart ]]; then
					complete_sipmsg
				fi
			else
				complete_sipmsg				
			fi
		fi

		if [[ $line =~ ^\<16[3-7]\> ]]; then
			line=$(awk -F"<16[3-7]>" '{print $NF}' <<< "$line")
		fi

		sip_partnum

		if [[ $currpartnum =~ "66" ]]; then											# ???
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $partnum == "01" ]] || [[ ${partnum#0} -le ${currpartnum#0} ]]; then
				badmsg=1; 				
				complete_sipmsg
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
			insidesip=1
			get_sip_datetime

			if [[ $((sipsplit)) == 0 ]]; then										# ALERT: split messages may write in/Outbound message into next line !!!
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
	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^\<16[3-7]\> ]]; then
		if [[ $((sipsplit)) == 0 ]]; then
			complete_sipmsg
		elif [[ $partnum == $maxpart ]]; then
			complete_sipmsg
		fi
	elif [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[0-9] ]]; then
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
			if [[ $line =~ RX\ |TX\  ]]; then										# 1xAgent special scenario			
#			if [[ $line == "RX "* ]] || [[ $line == "TX "* ]]; then						# 1xAgent special scenario
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
		if [[ ${#line} != 0 ]]; then
			sipline=$(egrep -c "<16[3-7]>" <<< "$line")
			if [[ $((sipline)) -gt 0 ]]; then
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(awk -F "<16[3-7]>" '{print $1}' <<< "$line")
				if [[ ${#line} != 0 ]]; then
					echo -e "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
					if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
						if [[ $calltime == "" ]] && [[ $line =~ From:|To: ]] && [[ $line =~ $findANI ]]; then
							calltime=$siptime
						elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ Call-ID: ]]; then
							callID=$(awk -F"Call-ID: " '{print $2}' <<< "$line" | cut -d' ' -f1)
							callID="Call-ID: $callID"; callDIR=$dirdefined
						fi
					fi
				fi
				if [[ $((sipsplit)) == 0 ]]; then
					complete_sipmsg
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
				if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
					if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
						calltime=$siptime
					elif [[ $calltime != "" ]] && [[ $line =~ ^Call-ID: ]]; then
						callID=$line; callDIR=$dirdefined
					fi
				fi
			fi
		fi
	fi
done <<< "$conv"
} # convert_EndpointLog()

function explore_logfolder () {
	targetfiles=""

	targetX=""; targetX=$(ls -r -t1 EndpointLog_B+sig+CPS.txt.[1-9] 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetX != "" ]]; then
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -t1 EndpointLog_B+sig+CPS.txt 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 EndpointLog_prev.txt 2>/dev/null)							# TODO eLux has strange character in EndpointLog_prev.txt filename
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 EndpointLog_bak.txt 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 EndpointLog.txt 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	if [[ $((alllogs)) == 0 ]]; then
		if [[ "$targetfiles" != "" ]]; then
			targetfiles=$(tail -1 <<< $targetfiles)
		else
			targetfiles=$targetX
		fi
	fi

	xfile=""; file=""; filelist=""
	for xfile in $targetfiles
	do
		if [ -s "$xfile" ]; then
			if [[ $file == "" ]]; then					
				file="$destdir/$xfile"
			fi
			if [[ $((alllogs)) != 0 ]]; then
				if [[ "$filelist" == "" ]]; then
					filelist="=$destdir/$xfile"
				else
					filelist="$filelist=$destdir/$xfile"
				fi
			fi
		fi
	done
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
	fi

	if [[ -d "Avaya" ]]; then
		destdir="$destdir/Avaya"
		cd "Avaya"
	fi

	if [ -d "Avaya VDI Communicator" ]; then
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

	elif [ -d "one-X Agent" ]; then
		if [ -d "one-X Agent/2.5/Log Files" ]; then
			destdir="$destdir/one-X Agent/2.5/Log Files"
			cd "one-X Agent/2.5/Log Files"
		elif [ -d "one-X Agent/Log Files" ]; then
			destdir="$destdir/one-X Agent/Log Files"
			cd "one-X Agent/Log Files"
		else
			destdir="$destdir/one-X Agent"
			cd "one-X Agent"
		fi

	elif [ -d "Log Files" ]; then																# for 1XA
		destdir="$destdir/Log Files"
		cd "Log Files"

	elif [ -d "LogFiles" ]; then																# for SparkEmulator
		destdir="$destdir/LogFiles"
		cd "LogFiles"

	elif [ -d "Avaya Endpoint/LogFiles" ]; then
		destdir="$destdir/Avaya Endpoint/LogFiles"
		cd "Avaya Endpoint/LogFiles"

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

	elif [ -d "target" ] && [ -d "igel" ]; then
		echo -e "\nwarning: $var appears to be a compressed file collected from iGEL platform"
		echo -e "You would have to manually extract content of \"target\" folder and re-run script on the \"logs\" folder.\n"
		ls -l "target";	cd $currdir; return

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

	elif [ -d "var/log" ]; then																	# for H175
		destdir="$destdir/var/log"
		cd "var/log"
	fi

	explore_logfolder

	if [[ $file == "" ]]; then
		error=1
		echo -e "\nerror: could not find any VDI-C/1XA/H175/SparkEmulator related logs in $folder"
	fi
elif [[ $destdir == "" ]]; then
	error=2
	echo -e "\nerror: explore_logfolders() was called with empty \$destdir - contact developer.\n"
else
	error=2
	echo -e "\nerror: explore_logfolders() was called with empty \$folder - contact developer.\n"
fi
} # explore_folders()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "

	rec=0; sample=""
#	rec=$(egrep -c -e "CSeq:" "$file")
	rec=$(egrep -ac "SIPMESSAGE:" "$file")		
	sample=$(egrep -a -m 1 "SIPMESSAGE:" "$file")

	if [[ $rec == 0 ]];	then
		rec=$(egrep -c -e "CSeq:" "$file")		
	fi				
	if [[ $rec == 0 ]];	then
		echo -e "\nerror: No SIP messages have been found in $basefile in the expected format."
		echo "In fact, no sign of any "CSeq:" lines in $basefile"
		echo "Perhaps this file is not a logfile from VDIC client...(or 1XA client or H175 phone)."
		echo -e "Or, debug (INFO) loglevel was not enabled - Verify source and content of $basefile\n"
		error=2; egrep -m 2 "Logging level" "$file"; echo ''

	elif [[ $sample != "" ]] && [[ $((vsyslog)) == 0 ]]; then
#		if [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
#		if [[ $sample =~ ^\<16[34567]\>[JFMASOND]*[cglnprtyv]\  ]]; then
		if [[ $sample =~ ^\<16[34567]\>[JFMASOND] ]]; then
			month=$(cut -d' ' -f1 <<< "$sample" | cut -d'>' -f2)
			if [[ ${#month} != 3 ]]; then
				echo $sample
				od -cx <<< "$month"
				echo -e "\nALERT: $file shows unusual \"month\" string: $month"
				echo "Expecting to find either of Jan, Feb, Mar, Apr, May, Jun, Jul, Aug, Sep, Oct, Nov or Dec strings."
				echo "Typically, this could happen when log is collected from eLUX or IGEL platform, using non-english locale."
				echo "Therefore during this conversion, month will be taken from current date: $today."
				echo -e "Yet, strongly recommend to edit this file by replacing all occurances of month string with a valid value.\n" # TODO: manage non-english month
				bIgnoreMonth=1; sipmonth=$(cut -d'/' -f1 <<< $today)
			fi
			
			sample2=$(echo $sample | cut -d' ' -f5)
#			sample2=$(cut -d' ' -f5 <<< "$sample")						# why does this result in field #4 instead of #5 ???
			if [[ $sample2 == "SIPMESSAGE:" ]]; then
				vsyslog=1
			elif [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
				if [[ $footprint == 1 ]]; then
					echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			elif [[ $var != $file ]]; then
				error=2; echo -e "\nerror: Unknown log format. Verify source and content of $bvar -> $basefile.\n"
			else
				error=2; echo -e "\nerror: Unknown log format. Verify source and content of $bvar.\n"
			fi

		elif [[ $sample =~ Local4.Info|Local4.Debug ]] && [[ $sample =~ \<010\> ]]; then		# KIWI syslog
#			sample=$(echo $sample | awk '{print $6}')
			vsyslog=20
			input2="$file"
			sed 's/<013><010>/\n/g' "$file" | sed 's/<010>/\n/g' | sed 's/<013>/\n/g' > "$file.kiwi"
			file="$file.kiwi"; tmpfile=2
			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")

		elif [[ $sample =~ :\ INFO ]]; then
			sample2=$(awk -F": INFO    : " '{print $2}' <<< $sample)
			if [[ $sample2 =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				egrep "SIPMESSAGE" < "$file" | awk -F": INFO    : " '{print $2}' > "$file.syslog"			# H175/log35.txt
				file="$file.syslog"; tmpfile=2
				if [[ ${#sample} -lt 160 ]]; then
					vsyslog=175															# TODO find a logfile which meets this scenario
				else																	# log35.txt SIPMESSAGE no linebreaks
					vsyslog=0
					echo -e "\nALERT: input file includes SIPMESSAGES in unrecognized format (no linebreaks?).  Contact developer.\n"
				fi
			fi

		elif [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
			footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
			if [[ $footprint == 1 ]]; then
				echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
			fi
		elif [[ $var != $file ]]; then
			error=2; echo -e "\nerror: Unknown log format. Verify source and content of $bvar -> $basefile.\n"
		else
			error=2; echo -e "\nerror: Unknown log format. Verify source and content of $bvar.\n"
		fi
	fi

	if [[ $rec != 0 ]] && [[ $((vsyslog)) != 0 ]]; then
		logsec=$SECONDS	
		base64msg=0
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
		longestsipword=""	
		sipmaxpartsipword=""		
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
		sipmaxpartmsg=0
		sipmaxsplit=0
		longestmsg=0
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
		n=0

		reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then
			echo "Warning: about to convert a logfile with $rec SIP messages"
			echo -e "This could take a while... you may want to execute this script on a more powerful PC or server.\n"
		fi
	
		##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
#       conv=$(awk -e '/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file")
        conv=$(awk -W source='/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file")

		check=$(egrep -c -e "<1[36][34567]>" "$file")
		if [[ $((vsyslog)) == 1 ]] && [[ $((check)) == 0 ]]; then
			echo "ALERT: expecting SYSLOG extracted from Wireshark but did not find any lines with <166> pattern."
			echo "Could $var be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			exit 0
		elif [[ $((vsyslog)) != 1 ]] && [[ $((check)) != 0 ]]; then
			echo "ALERT: expecting SYSLOG collected by KIWI or other tools but found some lines with <166> pattern."
			echo "Could $var be a SYSLOG extracted from Wireshark instead of remote SYSLOG via KIWI or other tools?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			exit 0
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

# if [ -f oisjdfoisjdf ]; then
		case $((vsyslog)) in
 		1|20) 	convert_EndpointLog;;
# 		20)		convert_syslog_mega;;					# KIWI syslog?
		esac
# fi

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
				if [[ $useragent =~ "Avaya Workplace VDI"* ]]; then
					xagent=$(egrep -m 1 "avaya.firmware=" "$file" | awk -F"avaya.firmware=" '{print $2}' | cut -d'"' -f2)
					if [[ ${#xagent} == 0 ]]; then
						xagent=$(egrep -m 1 "avaya.firmware\"> " "$file" | awk -F'avaya.firmware"> ' '{print $2}' | cut -d'"' -f2)
						if [[ ${#xagent} != 0 ]]; then
							useragent=$xagent
						fi
					else
						useragent=$xagent
					fi
				fi

				server=""; server=$(egrep -m 1 "^Server:" "$newfile")
				if [[ $lastfoundip != "" ]] && [[ $lastfoundip != "0.0.0.0" ]]; then
					if [[ ${#useragent} -lt 19 ]]; then
						echo -e "\n\tUser-Agent: $useragent\t\t ipaddr = $lastfoundip"
					elif [[ ${#useragent} -lt 27 ]]; then
						echo -e "\n\tUser-Agent: $useragent\t ipaddr = $lastfoundipr"
					else
						echo -e "\n\tUser-Agent: $useragent   ipaddr = $lastfoundip"
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
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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
					elif [[ ${#firstmsg} -lt 14 ]]; then
						echo -e "\tFirst msg:\t$firstmsg\t\t\t $timefirst"
					elif [[ ${#firstmsg} -lt 17 ]]; then
						echo -e "\tFirst msg:\t$firstmsg\t\t $timefirst"
					else
						echo -e "\tFirst msg:\t$firstmsg\t $timefirst"
					fi
					if [[ ${#lastmsg} -lt 8 ]]; then				
						echo -e "\tLast  msg:\t$lastmsg\t\t\t\t $timelast"
					elif [[ ${#lastmsg} -lt 14 ]]; then
						echo -e "\tLast  msg:\t$lastmsg\t\t\t $timelast"
					elif [[ ${#lastmsg} -lt 17 ]]; then
						echo -e "\tLast  msg:\t$lastmsg\t\t $timelast"
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
			fi		
		fi

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
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
} # convert_siplog

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":ae:i:hk:bdf:sv:ICAN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
    I)
		noINFO=1;;
	C)
		bCAT=1;;	
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	s)
		sipstat=0;;
	a)	
		conv2asm=1;;		
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
	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 10 ]]; then
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
			vsyslog=${OPTARG}												# TODO: vsyslog=INTEGER($var)
			if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 10 ]]; then
				vsyslog=0
			fi
		elif [[ $((skipper)) == 5 ]]; then
			enckey=$var
		elif [[ $((skipper)) == 6 ]]; then
			findANI=$findANI
		fi
		skipper=0			
		continue
	fi

	n=0; 		error=0;	vsyslog=0
	bdir="";	bvar="";	folder=""
	target=""; 	destdir="";	input=""; input2=""
	file=""; 	filelist="";basefile=""
	currtime=$(date +%R:%S);currdir=$PWD	
	bSinglefile=0;			tmpfile=0
	filetype2=""; filecontent="VDIC"
	
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
	elif [[ $bvar == "Avaya VDI Communicator" ]]; then
		target="AvayaVDICommunicator"
	elif [[ $bvar == "Avaya Equinox VDI" ]]; then
		target="AvayaEquinoxVDI"
	elif [[ $bvar == "Avaya Workplace VDI" ]]; then
		target="AvayaWorkplaceVDI"
	elif [[ $var == "." ]]; then
		target="VDIC"
	else
		target=$bvar	
#		target=${target%%.*}												# TODO: what about ../folder or ../filename - note the leading ".."			
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
# folder names:  Windows %appdata%\Roaming\Avaya: Avaya Equinox VDI\logs		Avaya Workplace VDI/logs	Avaya VDI Communicator/logs
# .zip with all above
		explore_folders

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"
		file="$var"

		if [[ $filetype == "7-zip archive"* ]]; then
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."
			error=99; continue
		elif [[ $filetype == "RAR archive"* ]]; then
			echo -e "\nerror: unfortunately, thist script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."
			error=99; continue

		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "VDIC" ]]; then
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
					echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"
					error=7; cd $currdir; input=""; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"
				input=""; error=7; cd $currdir; continue
			fi

			if [[ $bUnzip != 0 ]] && [ -d "$input.tmp" ]; then
				cd "$input.tmp"
				echo -e "\nUncompressing $bvar into $input.tmp ...                                                  "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress $bvar, using \"unzip\" utility. Skipping this file..."
					echo -e "Suggesting to validate \"unzip -qq $bvar\" command manually.\n"
					cd "$currdir"; input=""; error=8; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"			
					explore_folders
				fi

			elif [[ $bUnzip == 0 ]]; then
				cd ..; rm -rf "$input.tmp" 2>/dev/null
				echo -e "\nWarning: \"unzip\" package was not found."
				echo -e "If using Ubuntu, execute \"sudo apt-get unzip install\" to deploy and re-try.\n"
				cd $currdir; input=""; error=8; continue
			fi
			cd "$currdir"
		fi

		if [[ $filetype =~ data ]] && [[ ! $filetype =~ Zip|compressed ]] && [[ $filetype2 != *"tar"* ]]; then		# is this an H175 debugreport?  VDIC logreport does not support encryption (yet)
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file" 2>/dev/null)
			recX=0; recX=$(egrep -a -c -m 1 "CSeq:" "$file" 2>/dev/null)
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
						echo -e "error: Could not decode $bvar using openssl - verify encryption key with provider.\n"
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
				echo -e "\nerror: $bvar appears to be an H175 encrypted debugreport."
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
					echo "Uncompressing $zfile into $input2 ...                                                               "
					gunzip -q -c "$zfile" > "$input2" 2>/dev/null

					if [[ $? -le 1 ]]; then
						file="$input2"; tmpfile=2
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
				echo "Extracting $bfile ...                                                                          "

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
				tshark --version >/dev/null 2>&1

				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
					filecontent="error"
					echo -e "\nerror: unable to locate 'tshark' command."
					echo "'tshark' is required to extract syslog messages from $bvar into text file"
					echo -e "in Ubuntu, you can install it by typing: \"sudo apt install tshark\"\n"
					error=10; exit $error
				else
#					origfile=$file				
					if [[ $endptaddr != "" ]]; then
		    			tshark -r "$file" -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					else				
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi

					n=$(egrep -m 1 -c "\n[RT]X\ " "$file.syslog2" 2>/dev/null)

					if [[ $((n)) != 0 ]]; then
#						sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
#						sed 's/\\r\\n\ /\'$'\n''/g' < "$file.syslog2" | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
						egrep "SIPMESSAGE:" "$file.syslog2" | sed 's/\\r\\n\ /\'$'\n''/g' | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' | sed 's/&lt;/\</g' | sed 's/&gt;/\>/g' > "$file.syslog"
						file="$file.syslog"; tmpfile=2
					else
						file="$file.syslog2"; tmpfile=2
					fi
					vsyslog=11
#					vsyslog=2
#					input="$var"
					filecontent="SYSLOG"
				fi
			else
				echo -e "\nerror: $basefile appears to be a network capture, but format is unknown (expecting tcpdump or pcap)\n"
				error=11
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
			echo "Warning: about to convert multiple files ($nfiles x EndpointLog*.txt)."
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