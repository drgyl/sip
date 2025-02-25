#!/bin/bash
version="1.0.1"
let linelength=0
let siplength=666
let sipmonth=12

let ndebug=22

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

# TODO: get VDI logs from IGEL

## 1) from wireshark SYSLOG UDP stream - see ade_vdic_syslog1.txt
## <166>Jan 12 16:43:54 135.105.160.122 SIPMESSAGE: +01:00 2022 562 1 .TEL | 0 [Part 01 of 02]
## <166>Nov 17 11:50:57 135.105.160.122 SIPMESSAGE: +01:00 2020 946 1 .TEL | 0 Inbound SIP message from 198.152.84.100:5061
## 2) created by KIWI Syslog r8.x, default ISO log file format - see EqVDI2-SyslogCatchAll.txt
## 2022-02-08 17:22:43	Local4.Info	135.123.66.134	Feb  8 17:22:43 135.123.66.134 SIPMESSAGE: +01:00 2022 338 1 .TEL | 0 [Part 02 of 02]<010>-id=1<013><010>Content-Length:     0<013>
## challenges: <013><010> } Length is bogus (666), Month is bogus (12)

## H175: 2021-01-29 12:22:32	Local4.Info	10.8.232.36	Jan 29 12:25:09 10.8.232.36 SIPMESSAGE: +01:00 2021 034 1 .TEL | 0 Outbound SIP message to 10.8.12.6:5061<010>TX INVITE sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook SIP/2.0<013><010>From: <sip:2470@smn.rosneft.ru>;tag=6013b855715502b6693p7t1r1q3l5f196nmh5h1k6j6l3o32_F247010.8.232.36<013><010>To: <sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook><013><010>Call-ID: 217_6013b855-7fb11eab4692x5j163b5x70316n6p8336jx5m2c32_I247010.8.232.36<013><010>CSeq: 535 INVITE<013><010>Max-Forwards: 70<013><010>Via: SIP/2.0/TLS 10.8.232.36:1026;branch=z9hG4bK217_6013b8559dc2a981w724ais5q1n3k5x385pw2t4z76442_I247010.8.232.36<013><010>Supported: 100rel,eventlist,feature-ref,replaces,tdialog<013><010>Allow: INVITE,ACK,BYE,CANCEL,SUBSCRIBE,NOTIFY,MESSAGE,REFER,INFO,PRACK,PUBLISH,UPDATE<013><010>User-Agent: Avaya H175 Collaboration Station H1xx_SIP-R1_0_2_3_3050.tar<013><010>Contact: <sip:2470@10.8.232.36:1026;transport=tls>;+avaya-cm-line=1<013><010>Accept-Language: ru<013><010>Expires: 30<013><010>Content-Length:     0<013>

function usage ()  {
    echo "traceVDIC.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceVDIC.sh [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either an EndpointLog.txt from VDIC or Equinox/Workplace for VDI logreport"
	echo -e "\t\t\tor, the logreport itself"
	echo -e "\t\t\tor, syslog stream sent by a VDIC client, captured either via a remote SYSLOG server"
	echo -e "\t\t\tor, captured via wireshark (pcap), or extracted using \"Follow UDP stream\" function"
	echo -e "\t   or, a debugreport, EndpointLog_B_sig_CPS.txt and syslog from H175 phone can be accepted as well"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-k:\t\tset decryption key for debugreport decoding"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: \"a.b.c.d\""			
#	echo -e "\t-i:\t\tconvert syslog messages only sent by SM IP addr: a.b.c.d"						
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-I:\t\tignore all SIP INFO messages (used in sharedcontrol session)"		
	echo -e "\t-A:\t\tconvert all aditional logs in logreport where SIP message found"	
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
# echo ''; echo reset_sipmsg	
	partnum="00"
	maxpart="99"
	currpartnum="555"
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	dirdefined=0
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
			echo -en "$NL$line" >>$newfile
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
} # start_sipmsg()

function complete_sipmsg () {
# echo COMPLETE_SIPMSG sipstart=$sipstart sipsplit=$sipsplit
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
		if [[ $maxpart == "99" ]] || [[ $partnum == "00" ]]; then
			echo -e "error: SIP msg split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime"
		fi

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
		echo -e "$NL}$NL" >>$ "newfile"
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
#		if [[ $partnum == "01" ]] && [[ $((sipsplit)) == 0 ]]; then
		if [[ $partnum == "01" ]]; then
#			if [[ $((sipsplit)) != 0 ]]; then								# existing split SIP msg, but it starts with 01 - could be BAD
#				currpartnum="661"
#			fi
			maxpart=$(echo "$partline" | awk '{printf "%02i",$3}')
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
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line == *"Inbound SIP"* ]]; then
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

	elif [[ $line == *"Outbound SIP"* ]]; then
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
				ip=$(echo "$line" | awk -F" from ip = " '{print $2}')
				ip1=$(echo "$ip"  | cut -d' ' -f1)
				ip2=$(echo "$ip"  | awk '{printf "%i",$3}')
				ip=$ip1:$ip2
			elif [[ $line == *"bound SIP message "* ]]; then
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
# echo error: BADMONTH: $month
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
	if [[ $((vsyslog)) == 1 ]]; then 								# syslog UDP stream from wireshark
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
		
	elif [[ $((vsyslog)) == 20 ]]; then 								 ## KIWI syslog aka SyslogCatchAll
#		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(echo "$line" | awk '{print $4}')
			sipyear=$(echo "$line"     | cut -d' ' -f1 )					#| cut -d'-' -f1)	# awk -F'-' '{print $1}')
			sipmonth=$(echo "$sipyear" | cut -d'-' -f2)						# awk -F'-' '{print $2}')			
			sipday=$(echo "$sipyear"   | cut -d'-' -f3)						# awk -F'-' '{print $3}')			
			sipyear=$(echo $sipyear    | cut -d'-' -f1)			
#		fi

		siphour=$(echo "$line" | awk '{print $7}')
		sipmin=$(echo $siphour | cut -d':' -f2) 				# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour | cut -d':' -f3) 				# awk -F ':' '{print $3}')
		siphour=$(echo $siphour| cut -d':' -f1) 				# awk -F ':' '{print $1}')
		sipmsec=$(echo "$line" | awk '{print $12}')
		siptmp=$(echo "$line"  | awk '{print $10}')
	fi

	if [[ $((adjusthour)) == 1 ]]; then
		tzhour=$(echo $siptmp | cut -d':' -f1)		# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
		tzmin=$(echo $siptmp  | cut -d':' -f2)		# awk -F ':' '{print $2}')
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) 			# TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) 				# TODO need to print 2 digits
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

function convert_EndpointLog () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

	if [[ $line == *" SIPMESSAGE: "* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
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
					line=$(echo "$line" | awk -F"<16[3-7]>" '{print $2}')					
					siplines=$((siplines+1))
				elif [[ $((vsyslog)) == 1 ]] && [[ $line =~ \ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
					echo "$line" | awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $1}' >> "$newfile"
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

		if [[ $line =~ ^\<16[3-7]\> ]]; then
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
 
	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^\<16[3-7]\> ]]; then
		if [[ $((sipsplit)) == 0 ]]; then
			complete_sipmsg
		elif [[ $partnum == $maxpart ]]; then
			complete_sipmsg
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
		if [[ ${#line} != 0 ]]; then
			sipline=$(echo "$line" | egrep -c "<16[3-7]>")
			if [[ $((sipline)) -gt 0 ]]; then
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
				line=$(echo "$line" | awk -F "<16[3-7]>" '{print $1}')
				if [[ ${#line} != 0 ]]; then
					echo -e "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
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
			fi
		fi
	fi
done <<<"$conv"
} # convert_EndpointLog()

function convert_siplog () {
	if [[ $file == "" ]]; then
		rec=0
	else
#		rec=$(egrep -c -e "CSeq:" "$file")
		rec=$(egrep -c -e "SIPMESSAGE:" "$file")		

		if [[ $rec == 0 ]];	then
			rec=$(egrep -c -e "CSeq:" "$file")
		fi				
		if [[ $rec == 0 ]];	then			
			echo 'error: No SIP messages have been found! In fact, no sign of any "CSeq:" lines in '$var
			echo "Perhaps this file is not a logfile from VDIC client... or, debug (INFO) loglevel was not enabled"
			echo "Verify source and content of "$var
   			echo ''; error=2; return
		else
		    sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
			if [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				sample=$(echo $sample | cut -d' ' -f5)
				if [[ $sample == "SIPMESSAGE:" ]]; then
					vsyslog=1
				else
					echo "error: unknown log format. Verify source and content of "$var
					echo ''; error=2; return
				fi
			elif [[ $sample =~ Local4.Info|Local4.Debug ]] && [[ $sample =~ \<010\> ]]; then		# KIWI syslog
#				sample=$(echo $sample | awk '{print $6}')
				vsyslog=20
				tmpfile=1
				input2="$file"
				sed 's/<013><010>/\n/g' "$file" | sed 's/<010>/\n/g' | sed 's/<013>/\n/g' > "$file.kiwi"
				file="$file.kiwi"
				sample=$(egrep -m 1 "SIPMESSAGE:" "$file")									

			else
				echo "error: unknown log format. Verify source and content of "$var
				echo ''; error=2; return
			fi
		fi
	fi

	if [[ $rec != 0 ]] && [[ $((vsyslog)) != 0 ]]; then
		lastfoundip=""
		useragent=""
#		prevline=""
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
		n=0

		reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then
			echo "Warning: about to convert a logfile with $rec SIP messages"
			echo "This could take a while... you may want to execute this script on a more powerful PC or server."
			echo ''
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
 		1|20) 	convert_EndpointLog;;
# 		20)	convert_syslog_mega;;
		esac

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

		##	done
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

#		if [[ $tmpfile == 1 ]] && [[ $file != $var ]]; then
#			rm $file
#		fi
		echo ''
	fi
} # convert_siplog

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":ae:i:hk:bf:sv:AI" options; do
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
			if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 10 ]]; then
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

		filecontent="VDI"
		filetype=$(file -b "$file")

		if [[ $filetype == *"capture"* ]]; then
			if [[ $filetype == *"tcpdump"* ]] || [[ $filetype == *"pcap"* ]]; then
		  		line=$(whereis tshark)

				if [[ ${#line} -gt 10 ]]; then
					if [[ $endptaddr != "" ]]; then
		    			tshark -r "$file" -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
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
					input="$var"
		      	else
		     		echo "error: unable to locate 'tshark' command."
					echo "'tshark' is required to extract syslog messages from $var into text file"
					echo "in Ubuntu, you can install it by typing: sudo apt install tshark"
					echo ''; error=10; exit $error
				fi
			fi

		elif [[ $filetype == *"data"* ]] && [[ $filetype != *"Zip"* ]]; then			# is this an H175 debugreport?  VDIC logreport does not support encryption (yet)
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
			if [[ $filecontent =~ ANDROID ]]; then								# sometimes "file vantage.log" reports data
				filecontent="ANDROID"
			elif [[ $enckey != "" ]]; then
				openssl version >/dev/null
				if [[ $? != 0 ]]; then
					if [[ $file == *"."* ]]; then
						input=$(echo "${file%.*}")
					else
						input="$var"
					fi
#					outfile=$outfile"-decrypted.tgz"
					openssl aes-128-cbc -d -salt -k $enckey -in "$file" -out "$input-decrypted.tgz"
					if [[ $? == 0 ]]; then
						error=6
						echo "error: Could not decode $file using openssl - verify encryption key with provider"
						echo ''; continue
					else
						file="$input-decrypted.tgz"
						filecontent="H175"
						filetype=$(file -b "$file")						
					fi
				else
					error=5
					echo 'error: "openssl" was not found, required for decoding '$var
					echo ''; exit $error
				fi
			fi				
		fi

		if [[ $filetype == *"compressed data"* ]]; then
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
					input=$(echo "${file%.*}")
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
						echo '';  exit $error
					fi
				else
					gunzip --version >/dev/null
					if [[ $? == 0 ]]; then
						gunzip -q "../$file" 2>/dev/null	# TODO: can gunzip untar or only uncompress .tgz into .tar?
						if [[ $? != 0 ]]; then
							error=8; cd ..
							echo "error: could not uncompress $file, using \"gunzip\" utility."
							echo ''; exit $error
						fi
					fi
				fi

				if [[ $filecontent == "" ]] && [ -d "var/log" ]; then
					filecontent="H175"
				fi

				if [[ $? == 0 ]]; then
					file=""; filelist=""
					if [[ $filecontent == "H175" ]]; then
						if [ -d "var/log" ]; then
							tmpfile=2
							if [ -f "var/log/EndpointLog_B+sig+CPS.txt" ]; then
								file="$input.tmp/var/log/EndpointLog_B+sig+CPS.txt"
								if [[ $alllogs != 0 ]]; then
#									filelist=$(ls -t1 $input.tmp/var/log/EndpointLog_B+sig+CPS.txt*)
									filelist=$(ls -t1 var/log/EndpointLog_B+sig+CPS.txt*)
								fi
							fi
						elif [ -f "EndpointLog_B+sig+CPS.txt" ]; then
							tmpfile=2
							file="$input.tmp/EndpointLog_B+sig+CPS.txt"
							if [[ $alllogs != 0 ]]; then
#								filelist=$(ls -t1 $input.tmp/EndpointLog_B+sig+CPS.txt*)
								filelist=$(ls -t1 EndpointLog_B+sig+CPS.txt*)								
							fi
						fi
					fi

					if [[ $file == "" ]]; then
						echo "error: extracted $var does not include EndpointLog_B+sig+CPS.txt file at $PWD"
						error=9; cd ..
#						exit $error
						continue
					else
						cd ..											
					fi
				else
					error=8; cd ..
					echo "error: could not uncompress $file"
					echo ''; exit $error
				fi
			fi
		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "VDI" ]]; then
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

			unzip -qq -v >/dev/null
			if [[ $? == 0 ]]; then
				unzip -qq "../$file" 2>/dev/null
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
						echo "error: could not uncompress $var, using unzip.  Suggest to deploy \"unzip\" package"
						echo "in Ubuntu, you can install it by typing: sudo apt install unzip"	
						echo ''; exit $error
					fi
				fi
			else
				error=8; cd ..
				echo "error: could not uncompress $var, using \"unzip\".  Suggest to deploy \"unzip\" package"
			    echo "in Ubuntu, you can install it by typing: sudo apt install unzip"						
				echo ''; exit $error
			fi

			file=""
			targetfiles="EndpointLog.txt EndpointLog_bak.txt EndpointLog_prev.txt"
			if [ -d "Avaya VDI Communicator" ]; then
				tmpfile=2
				cd "Avaya VDI Communicator"
			elif [ -d "Avaya Workplace VDI" ]; then
				tmpfile=3
				cd "Avaya Workplace VDI"
			elif [ -d ".vdi-communicator" ]; then
				tmpfile=4
				cd ".vdi-communicator"
			fi

			if [ -d "logs" ]; then
				for xfile in $targetfiles
				do
					if [ -f "logs/$xfile" ]; then
						if [[ $file == "" ]]; then
							if [[ $((tmpfile)) == 2 ]]; then
								file="$input.tmp/Avaya VDI Communicator/logs/$xfile"
							elif [[ $((tmpfile)) == 3 ]]; then
								file="$input.tmp/Avaya Workplace VDI/logs/$xfile"
							elif [[ $((tmpfile)) == 4 ]]; then
								file="$input.tmp/.vdi-communicator/logs/$xfile"

							else
								file="$input.tmp/logs/$xfile"
							fi
						fi
						if [[ $alllogs != 0 ]]; then
							if [[ $((tmpfile)) == 2 ]]; then
								filelist="$filelist=$input.tmp/Avaya VDI Communicator/logs/$xfile"
							elif [[ $((tmpfile)) == 3 ]]; then
								filelist="$filelist=$input.tmp/Avaya Workplace VDI/logs/$xfile"
							elif [[ $((tmpfile)) == 4 ]]; then
								filelist="$filelist=$input.tmp/.vdi-communicator/logs/$xfile"													
							else
								filelist="$filelist=$input.tmp/logs/$xfile"							
							fi
						fi
					fi
				done
			elif [ -d "setup/eLux/.workplace-vdi/logs" ]; then
				for xfile in $targetfiles
				do
					if [ -f "setup/eLux/.workplace-vdi/logs/$xfile" ]; then
						if [[ $file == "" ]]; then					
							file="$input.tmp/setup/eLux/.workplace-vdi/logs/$xfile"
						fi
						if [[ $alllogs != 0 ]]; then
							filelist="$filelist=$input.tmp/setup/eLux/.workplace-vdi/logs/$xfile"
						fi
					fi
				done
			else
				for xfile in $targetfiles
				do
					if [ -f "$xfile" ]; then
						if [[ $file == "" ]]; then					
							file="$input.tmp/$xfile"
						fi
						if [[ $alllogs != 0 ]]; then
							filelist="$filelist=$input.tmp/$xfile"
						fi
					fi
				done
			fi

			if [[ $((tmpfile)) == 2 ]] || [[ $((tmpfile)) == 3 ]] || [[ $((tmpfile)) == 4 ]]; then
				cd ..
			fi

			if [[ $file == "" ]]; then
				echo "error: extracted $var does not include EndpointLog.txt file"
				echo ''; cd ..; error=9
				continue
			fi
			cd ..
		fi

	nfiles=0
	if [[ $((alllogs)) != 0 ]] && [[ $filelist != "" ]]; then
		if [[ $filelist =~ ^= ]]; then
			filelist=${filelist:1}
		fi
		origIFS=$IFS; IFS="="
		nfiles=$(echo $filelist | awk -F"=" '{print NF}')

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x EndpointLogXXX.txt) found in $var"
			echo "This may take a while... you may want to execute this script on a more powerful PC or server."
			echo ''
			for file in $filelist;
			do
				if [[ $file != "" ]]; then
					IFS=$origIFS
					if [[ $input != "" ]]; then
						file="$input.tmp/$file"
					fi
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
			if [[ $input != "" ]]; then
				file="$input.tmp/$file"
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