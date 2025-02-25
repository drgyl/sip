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
findANI=""
sipstat=1
converted=0
adjusthour=0
localtime=0
base64decode=1
bDelTemp=1
bCAT=0
noINFO=0
alllogs=0
localip="1.1.1.1:1111"
protocol="TLS"
enckey=""
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:
targetfiles=""

## 10) vantage.log
## 1) from wireshark SYSLOG UDP stream - see ade_vdic_syslog1.txt
## <166>Jan 12 16:43:54 135.105.160.122 SIPMESSAGE: +01:00 2022 562 1 .TEL | 0 [Part 01 of 02]
## 2) created by KIWI Syslog r8.x, default ISO log file format - see EqVDI2-SyslogCatchAll.txt
## 2022-02-08 17:22:43	Local4.Info	135.123.66.134	Feb  8 17:22:43 135.123.66.134 SIPMESSAGE: +01:00 2022 338 1 .TEL | 0 [Part 02 of 02]<010>-id=1<013><010>Content-Length:     0<013>
## challenges: <013><010> } Length is bogus (666), Month is bogus (12)

## H175: 2021-01-29 12:22:32	Local4.Info	10.8.232.36	Jan 29 12:25:09 10.8.232.36 SIPMESSAGE: +01:00 2021 034 1 .TEL | 0 Outbound SIP message to 10.8.12.6:5061<010>TX INVITE sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook SIP/2.0<013><010>From: <sip:2470@smn.rosneft.ru>;tag=6013b855715502b6693p7t1r1q3l5f196nmh5h1k6j6l3o32_F247010.8.232.36<013><010>To: <sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook><013><010>Call-ID: 217_6013b855-7fb11eab4692x5j163b5x70316n6p8336jx5m2c32_I247010.8.232.36<013><010>CSeq: 535 INVITE<013><010>Max-Forwards: 70<013><010>Via: SIP/2.0/TLS 10.8.232.36:1026;branch=z9hG4bK217_6013b8559dc2a981w724ais5q1n3k5x385pw2t4z76442_I247010.8.232.36<013><010>Supported: 100rel,eventlist,feature-ref,replaces,tdialog<013><010>Allow: INVITE,ACK,BYE,CANCEL,SUBSCRIBE,NOTIFY,MESSAGE,REFER,INFO,PRACK,PUBLISH,UPDATE<013><010>User-Agent: Avaya H175 Collaboration Station H1xx_SIP-R1_0_2_3_3050.tar<013><010>Contact: <sip:2470@10.8.232.36:1026;transport=tls>;+avaya-cm-line=1<013><010>Accept-Language: ru<013><010>Expires: 30<013><010>Content-Length:     0<013>
## 9) Nov 15 10:41:56 localhost 192.168.202.19 ANDROID: +03:00 2021 000 0 | 11-15 13:41:55.866 D/DeskPhoneServiceAdaptor( 2432): [SIP]:RECEIVED 970 bytes from 192.168.70.104:5061 { - see vantage.log

# TODO find/collect pcap for H175 & K1xx

function usage ()  {
    echo "traceK1xx.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceK1xx.sh <options> [<LOG_FILE> | <debugreport> | <folder> ...]'
	echo '  Where:'
	echo -e "    <LOG_FILE>\tcould be either a debugreport file (.tar/.tgz/.zip) - either encrypted or decrypted -"
	echo -e "\t\tand pulled from either an Avaya Vantage (K1xx) device or Avaya H175 Collaboration Station,"
	echo -e "\t\tor a vantage.log file found in a debugreport of a K1xx phone running Basic or Connect app,"	
	echo -e "\t\tor an EndpointLog+sig+CPS.txt found in a debugreport of a H175 device."
	echo -e "\t\tor a pcap/pcapng file including remote syslog packets,"
	echo -e "\t\tor syslog text of \"Follow UDP Stream\" manually extracted from a pcap file using Wireshark,"
	echo -e "\t\tor remote syslog txt file captured by KIWI or other syslog server (refer to doc)."
	echo -e "    <folder>\tincludes one or more of the files extracted from a debugreport (eg. vantage.log.X)"	
#    echo -e "\nWithin debugreport these logfiles are located either in /var/log (r2.x) or in /data/vendor/var/log (r3.x).\n"
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-k \t\tset decryption key for debugreport decoding"	
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"		
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution or result of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	partnum="00"; 	maxpart="99"; 	currpartnum="555"
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	dirdefined=0
	base64found=0
	badmsg=0
	foundipaddr=""; siptime="";	sipdate="";	ip=""
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

	lastmsg="$sipword"; timelast="$sipdate $siptime"
	if [[ $((sipmsg)) == 1 ]]; then
		firstmsg=$lastmsg
		timefirst=$timelast
	fi

	if [[ $((sipsplit)) != 0 ]]; then
		sipmaxsplit=$((sipmaxsplit+1))
		if [[ $maxpart == "99" ]] || [[ $partnum == "00" ]]; then
			echo -e "\nerror: SIP msg was split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime"
			echo "# error: SIP msg was split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime" >> "$newfile"
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
		echo -e "\nerror: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime"
		echo -e "# error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime" >> "$newfile"		
#		echo ''; exit 1
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
		echo -e "# This was a BAD message\n" >> "$newfile"
		sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadmsgnum == "" ]]; then
			sipbadmsgnum="$siptotalmsg $siptime"
		fi
	fi

	lastfoundip=$foundipaddr
	reset_sipmsg
else														# cannot complete a SIP message if it did not start properly
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
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line == *"[SIP]:RECEIVED"* ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac
		##ip=$(echo $line | awk '{print $5}')
	elif [[ $line == *"[SIP]:SENDING"* ]]; then
		## elif [[ $direction == 'Outbound' ]]; then
		sipstream=1474; 			dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--";		dirstring2="egress";;
		esac
		##ip=$(echo $line | awk '{print $5}')
	elif [[ $line == *"Inbound SIP"* ]] || [[ $line == *" <- "* ]] || [[ $line =~ ^RX\  ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1)	dirstring1="RECEIVED"; 	dirstring2="from";;
		2)	dirstring1="RECEIVED"; 	dirstring2="from";;
		3)	dirstring1="-->"; 	 	dirstring2="ingress";;
		esac

	elif [[ $line == *"Outbound SIP"* ]] || [[ $line == *" -> "* ]] || [[ $line =~ ^TX\  ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT"; 	  	dirstring2="to";;
		2)	dirstring1="SENDING"; 	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	fi
	
	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $foundipaddr == "" ]]; then
			case $vsyslog in
			20|175) foundipaddr=$(awk '{print $4}' <<< "$line");;
			esac
		fi

		if [[ $((vsyslog)) == 10 ]]; then
	 		ip=$(cut -d' ' -f20 <<< "$line")
			siplength=$(cut -d' ' -f17 <<< "$line")
		elif [[ $((vsyslog)) == 11 ]]; then
		 	ip=$(cut -d' ' -f16 <<< "$line")
			siplength=$(cut -d' ' -f13 <<< "$line")
		elif [[ $((vsyslog)) == 2 ]] || [[ $((vsyslog)) == 175 ]]; then
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
	if [[ $line == "" ]]; then
		echo -e "error: get_sip_datetime(): EMPTY LINE! in $file at line#$nlines"
		echo -e "Contact developer.\n"
	else
		siptmp=""	
	if [[ $((vsyslog)) == 10 ]]; then 								# native vantage.log
		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(awk '{print $5}' <<< "$line")				# cut -d' ' -f5)
			sipyear=$(awk '{print $8}' <<< "$line")					# cut -d' ' -f8)
			sipday=$(awk '{printf "%02i",$2}' <<< "$line")
			month=$(cut -d' ' -f1 <<< "$line")
			get_sipmonth
		fi

		sipmsec=$(awk '{print $13}' <<< "$line") # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")

#			siptime=$(echo $line | awk '{print $3":"$8}')  # msec included in $8
####		siptmp=$(echo $line | awk '{print $6}')
####		tzhour=$(echo $siptmp |cut -d':' -f 1) # awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
####		tzmin=$(echo $siptmp | cut -d':' -f 2) # awk -F ':' '{print $2}')

	elif [[ $((vsyslog)) == 11 ]]; then 				# syslog UDP stream converted
# 10.16.4.24 ANDROID: +03:00 2020 000 0 | 06-19 12:39:08.793 D/DeskPhoneServiceAdaptor( 3111): [SIP]:SENDING 1425 bytes to 10.16.26.183:5061 {	
		foundipaddr=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d' ' -f4 <<< "$line")
		sipday=$(cut -d' ' -f8 <<< "$line" | cut -d'-' -f2)		# awk '{printf "%02i",$2}')
		sipmonth=$(cut -d' ' -f8 <<< "$line" | cut -d'-' -f1)		# awk '{printf "%02i",$2}')		
		
		sipmsec=$(cut -d' ' -f9 <<< "$line")			# awk '{print $9}') # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")

	elif [[ $((vsyslog)) == 175 ]]; then  			# EndpointLog
# Jan  2 00:18:37 149.49.139.118 SIPMESSAGE: +01:00 1970 745 1 .TEL | 0 Outbound SIP message to 149.49.138.49:5061	
		foundipaddr=$(awk '{print $4}' <<< "$line")
		sipyear=$(awk '{print $7}' <<< "$line")
		sipday=$(awk '{printf "%02i",$2}' <<< "$line")
		if [[ $line =~ ^\<1[0-9][0-9] ]]; then
			month=$(awk -F"<16[34567]>" '{print $2}' <<< "$line" | cut -d' ' -f1)
#			month=$(echo "$line"       | cut -d'>' -f2 | cut -d' ' -f1)				
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

	elif [[ $((vsyslog)) == 2 ]]; then  			# KIWI syslog
		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(awk '{print $5}' <<< "$line")
			sipyear=$(cut -d' ' -f1  <<< "$line" | awk -F '-' '{print $1}')
			sipmonth=$(cut -d' ' -f1 <<< "$line" | awk -F '-' '{print $2}')
			sipday=$(cut -d' ' -f1   <<< "$line" | awk -F '-' '{print $3}')			
		fi

		## endptaddr=$(echo $line | awk '{print $4}')
		## siplength=$(echo $line | awk '{print $13}')

##						xline=$(echo $line | awk -F '|' '{print $2}')
##						ip=$(echo $xline | awk '{print $(NF)}')
##						ip1=$(echo $ip | awk -F ":" '{print $1}')
##						ip2=$(echo $ip | awk -F ":" '{print $2}')
						
		siphour=$(awk '{print $7}' <<< "$line")
		sipmsec=$(awk '{print $12}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour") 				# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour") 				# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour") 			# awk -F ':' '{print $1}')

		siptmp=$(awk '{print $10}' <<< "$line")
		tzhour=$(cut -d':' -f1 <<< "$siptmp") 				# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
		tzmin=$(cut -d':' -f2 <<< "$siptmp")				# awk -F ':' '{print $2}')

		## ip=$(echo $line | awk '{print $NF}')
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

#		siphour=$(awk -F ':' '{print $1}' <<< "$sipmec") 				# awk -F ':' '{print $1}')
#		siphour=$(cut -d':'-f1 <<< "$sipmec") 				# awk -F ':' '{print $1}')
		sipmin=$(cut -d':' -f2 <<< "$siphour") 				# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour") 				# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour") 			# awk -F ':' '{print $1}')		
		sipmsec=$(awk '{print $12}' <<< "$line")
		siptmp=$(awk '{print $10}' <<< "$line")
	fi

	if [[ $((adjusthour)) == 1 ]]; then
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}')	 ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) 			## TODO need to print 2 digits eg printf "%02i",$((siphour))-24
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) 				## TODO need to print 2 digits
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
fi
} # get_sip_datetime()

function explore_logfolder () {
	targetfiles=""

	targetX=""; targetX=$(ls -r -t1 vantage.log.[0-9]* 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $((alllogs)) == 0 ]] && [[ $targetX != "" ]]; then
		targetfiles=$(tail -1 <<< $targetX)
	else
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -t1 vantage.log 2>/dev/null)
	if [[ $? == 0 ]]; then
		if [[ $((alllogs)) != 0 ]] && [[ $targetX != "" ]]; then
			if [[ $targetfiles != "" ]]; then
				targetfiles="$targetfiles $targetX"
			else
				targetfiles=$targetX
			fi
		elif [[ $targetX != "" ]]; then
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -r -t1 EndpointLog_B+sig+CPS.txt.[1-9] 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $((alllogs)) != 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	elif [[ $targetX != "" ]]; then
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -t1 EndpointLog_B+sig+CPS.txt 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $((alllogs)) != 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	elif [[ $targetX != "" ]]; then
		targetfiles=$targetX
	fi

	if [[ $((alllogs)) == 0 ]]; then
		if [[ "$targetfiles" != "" ]]; then
			targetfiles=$(tail -1 <<< $targetfiles)
		else
			targetfiles=$targetX
		fi
	fi

	file=""; filelist=""
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
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
	fi

	if [ -d var ]; then
		if [ -d "var/log" ]; then
			vantage=3			
			destdir="$destdir/var/log"
			cd "var/log"
		fi
	elif [ -d "data/vendor/var/log" ]; then
		vantage=2
		destdir="$destdir/data/vendor/var/log"
		cd "data/vendor/var/log"
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

	if [[ $file == "" ]]; then
		error=1
		echo -e "\nerror: could not find any K1xx/H175 related logs in $folder"
	fi

	cd $currdir
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

function convert_k1xx () {
#	conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
#  	conv=$(awk -e '/: \[SIP\]:/{flag=1} flag; /}/{flag=0}' "$file")
	conv=$(awk -W source='/: \[SIP\]:/{flag=1} flag; /}/{flag=0}' "$file")

	while IFS= read -r line
	do
#		linelength=${#line}
		nlines=$((nlines+1))
								
		if [[ $line == *"): [SIP]:"* ]]; then
			if [[ $endptaddr != "" ]]; then
				if [[ $line != *$endptaddr* ]]; then	
					continue
				fi
			elif [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
			fi

			insidesip=1 												# this is a new SIP msg
			get_sip_datetime

			if [[ $((vsyslog)) != 1 ]] || [[ $((sipsplit)) == 0 ]]; then
				if [[ $((dirdefined)) == 0 ]]; then
					sip_direction
					if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
						reset_sipmsg
						continue
					else
						siptotalmsg=$((siptotalmsg+1))
						sipmsg_header
					fi
				fi
			fi
				
#		elif [[ $((vsyslog)) -ge 10 ]] && [[ $((insidesip)) == 1 ]]; then  			## line does not have ": [SIP]:", so we are potentiall inside a new SIP msg
		elif [[ $((insidesip)) != 0 ]]; then
			if [[ $line =~ DeskPhoneServiceAdaptor ]]; then
				line=$(echo "$line" | awk -F'DeskPhoneServiceAdaptor' '{print $2}'| awk -F"[0-9]{4}): " '{print $2}')  # TODO: need a better regexp for [-0]{4}

				if [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
					if [[ ${#line} -lt 2 ]]; then
						continue
					else 
						start_sipmsg
					fi

				elif [[ $line == "}"* ]] || [[ $line == "[null]"* ]]; then
					complete_sipmsg
				
				elif [[ $((sipstart)) != 0 ]] && [[ ${#line} != 0 ]]; then
					if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
						if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
							calltime=$siptime
						elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
							callID=$line; callDIR=$dirdefined
						fi
					fi

					if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
						base64found=1
						echo "# Base64 dump found" >> "$newfile"
						if [[ -f $newfile.b64 ]]; then
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

			elif [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
			fi
		fi		
	done <<< "$conv"
} # convert_k1xx()

function convert_h175 () {		# same as convert_EndpointLog from trace96x1.sh
    conv=$(awk -W source='/SIPMESSAGE:/{flag=1} flag; /}/{flag=0}' "$file")

	while IFS= read -r line
	do
#		linelength=${#line}
		nlines=$((nlines+1))

		if [[ $line =~ SIPMESSAGE: ]]; then
			if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
				continue
			elif [[ $line == *" End of "* ]] && [[ $((sipstart)) != 0 ]]; then		# 1xAgent special line
				complete_sipmsg
			fi

			if [[ $((sipstart)) != 0 ]]; then
				if [[ $((sipsplit)) == 0 ]]; then
					complete_sipmsg
#				elif [[ $line =~ [MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				elif [[ $line =~ \[Part\  ]]; then
##				    if [[ $line =~ ^\<16[3-7]\> ]] || [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
##					    dummy=0															# dummy statement
##					elif [[ $line =~ .*\<16[3-7]\> ]]; then
##						echo "$line" | awk -F"<16[3-7]>" '{print $1}' >> "$newfile"					
##						line=$(awk -F"<16[3-7]>" '{print $2}' <<< "$line")
##					    siplines=$((siplines+1))					
##					elif [[ $line =~ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
##						awk -F "[JFMASOND][[:lower:]][[:lower:]] " '{print $1}' <<< "$line" >> "$newfile"
##						line=$(awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $2}' <<< "$line")
##						siplines=$((siplines+1))
##					fi

#					line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
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

#				elif [[ $partnum != "00" ]] && [[ $((sipsplit)) == 0 ]]; then
#					badmsg=1
#					complete_sipmsg				
#					continue

#				elif [[ $partnum != "01" ]] && [[ $((sipsplit)) == 0 ]]; then
#					badmsg=1
#					complete_sipmsg				
#					continue
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
#				sip_partnum
				get_sip_datetime

				if [[ $((sipsplit)) == 0 ]]; then					# ALERT: split messages may write in/Outbound message into next line !!!
					sip_direction
			        if [[ $((dirdefined)) != 0 ]]; then
#				  		if [[ $foundipaddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
#							reset_sipmsg
#							continue
#			  			else
						insidesip=2															
#				    	fi
					fi
				fi
			fi
 
	 	elif [[ $((insidesip)) == 0 ]]; then
			continue

# VDIC-beg
		elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^\<16[3-7]\> ]]; then
			if [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
				complete_sipmsg
			fi
		elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			if [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
				complete_sipmsg
			fi
		elif [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
			if [[ $((sipstart)) == 0 ]]; then
				continue
			elif [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
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
				if [[ $line == "RX "* ]] || [[ $line == "TX "* ]]; then						# 1xAgent special scenario
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
# VDICcut		if [[ $line =~ \<16[34567]\> ]] || [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
# VDICcut			complete_sipmsg
			if [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
				complete_sipmsg			

			elif [[ ${#line} != 0 ]]; then
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
} # convert_h175()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	lhost=""; 		platform="";		sample=""		
	basefile=""; 	filecontent=""; 	filecontent2=""
	error=0;		rec=0;				rec2=0

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "

	filecontent=$(egrep -a -m 1 -e "ANDROID:|SIPMESSAGE:" "$file")
	filecontent2=$(egrep -a -m 1 -e "SIPMESSAGE:" "$file")	

	if [[ $filecontent =~ ANDROID ]] && [[ $filecontent2 == "" ]]; then
		rec=$(egrep -a -c -e "\[SIP\]:[SR]" "$file")
		rec2=$(egrep -a -m 1 -c -e "CSeq:" "$file")					
		sample=$(egrep -a -m 1 "): \[SIP\]:" "$file")

		if [[ $((rec)) == 0 ]];	then
			echo -e "$basefile : No SIP messages have been found."
			echo "Perhaps this file is not a vantage.log or EndpointLog+sig+CPS.txt file."
			echo "Or, debug loglevel with SIPMESSAGE logcategory was not enabled."
	
			error=1; rec=$(egrep -a -c -e "^CSeq:*" "$file")
			if [[ $((rec)) == 0 ]]; then
				echo 'In fact, no sign of any "CSeq:" lines in '$file
				error=2; rec=0
			else
				echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages within '$basefile
			fi
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
				if [[ $footprint == 1 ]]; then
					echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			elif [[ $var != $file ]]; then
				echo -e "Verify source and content of $bvar -> $basefile.\n"
			else
				echo -e "Verify source and content of $bvar.\n"
			fi
			rec=0
		elif [[ $((rec2)) != 0 ]] && [[ $((vsyslog)) == 0 ]]; then
			lhost=$(echo $sample    | cut -d' ' -f4)
			platform=$(echo $sample | cut -d' ' -f6)

			if [[ $lhost == "localhost" ]] && [[ $platform == "ANDROID:" ]]; then
				vsyslog=10
			else
				rec=$(wc -l < "$file")
				platform=$(echo $sample | cut -d' ' -f2)				
				xlines=$(egrep -a -c "<16[34567]>" "$file")
				sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
				if [[ $((rec)) == 0 ]] && [[ $xlines != 0 ]]; then
					sed 's/<16[34567]>/\n/g' < "$file" > "$file.udpsyslog"
					rec=$(egrep -a -c -e "CSeq:" "$file")					
					file="$file.udpsyslog"; tmpfile=2
					vsyslog=11
				elif [[ $platform == "ANDROID:" ]]; then
					vsyslog=11
				fi
			fi
		fi
	elif [[ $filecontent2 =~ SIPMESSAGE: ]]; then
		sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
		rec=$(egrep -a -c -e "SIPMESSAGE:" "$file")	
#		filecontent=$(egrep -m 1 "H175" "$file")
#		if [[ $filecontent =~ H175 ]]; then
#			echo ''; error=3
#			echo "error: found \"SIPMESSAGE:\" and \"H175\" strings in $file"
#			echo "This hints that the logfile could rather be related to H175 phone."
#			echo "Try to run \"trace96x1.sh\" or \"traceVDIC.sh\" scripts instead."
#			echo ''; return
#		fi
		if [[ $sample =~ ^\<16[34567]\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then	# EndpointLog or 96x1/J1xx syslog from wireshark/Follow UDP stream
			sed 's/^<1[0-9][0-9]>//g' "$file" > "$file.sip"
			file="$file.sip"; tmpfile=2
			vsyslog=175

		elif [[ $sample =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			vsyslog=175

		elif [[ $sample =~ Local4.Debug|Local4.Info ]] && [[ $sample =~ \<010\> ]]; then					# KIWI syslog
#			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
#			sample=$(echo $sample | awk '{print $6}')
			vsyslog=20
			sed 's/<013><010>/\n/g' "$file" | sed 's/<010>/\n/g' | sed 's/<013>/\n/g' > "$file.kiwi"
			file="$file.kiwi"; tmpfile=2
#			rec=$(egrep -a -c -e "SIPMESSAGE:" "$file")

		elif [[ $sample =~ :\ INFO ]]; then
			sample2=$(awk -F": INFO    : " '{print $2}' <<< $sample)
			if [[ $sample2 =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				egrep "SIPMESSAGE" < "$file" | awk -F": INFO    : " '{print $2}' > "$file.syslog"			# H175/log35.txt
				file="$file.syslog"; tmpfile=2
				if [[ ${#sample} -lt 160 ]]; then
					vsyslog=175
				else																	# log35.txt SIPMESSAGE no linebreaks
					vsyslog=0
					echo -e "\nALERT: input file includes SIPMESSAGES in unrecognized format (no linebreaks?).  Contact developer.\n"
				fi
			fi
		fi
	fi

	if [[ $((vsyslog)) == 0 ]]; then
		if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
			footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
			if [[ $footprint == 1 ]]; then
				echo -e "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
			fi
		else
			echo "error: could not recognize content of $file"
			if [[ $var != $file ]]; then
				echo -e "Verify source and content of $file within $var.\n"
			else
				echo -e "Verify source and content of $file.\n"
			fi
		fi
		error=9; return

	elif [[ $((rec)) != 0 ]]; then
		logsec=$SECONDS
		base64msg=0
		foundipaddr=""
		lastfoundip=""
		basefile=""
		output=""
		useragent=""
		partnum="00"
		maxpart="99"
		nlines=0
		sipyear=0
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
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
		sipmaxpartmsg=0
		sipmaxsplit=0
		sipwordlist=""
		sipmaxpartsipword=""
		longestsipword=""
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

		if [[ $rec -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages)"
			echo -e "This may take a while... You may want to execute the script on a more powerful PC or server.\n"
		fi
	
		bakfile=""; output=""; 	bfile=""

		if [[ $basefile != "" ]] && [[ $basefile == *"."* ]]; then
			bfile=${basefile%.*}
		fi

		if [[ $var != $basefile ]] && [[ $basefile != $file ]]; then
			xfile=${bvar%%.*}
			if [[ $bvar == $basefile ]]; then
				output=$bvar
			elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
				output="$xfile-$basefile"
			else
				output=$bvar
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

		iohist=""
#		if [[ $var != $file ]]; then
#			echo -e "# Input/output file history: $var --> $file --> $output.asm\n" >> "$newfile"
#		else 
#			echo -e "# Input/output file history: $var\n" >> "$newfile"
#		fi
		if [[ $var != $file ]]; then
			if [[ $input2 != "" ]] && [[ $file != "" ]] && [[ $file != $input2 ]]; then
				iohist="$input2-decrypted.tgz"
			elif [[ $input != "" ]] && [[ $file != "" ]] && [[ $file != $input ]]; then
				iohist="$input.tmp"
			elif [ -d "$var" ]; then
				iohist="$var"
			fi

			if [[ $file != "" ]] && [[ $file != $output ]]; then
				if [[ $iohist != "" ]] && [[ $tmpfile != 0 ]]; then
					case $tmpfile in
					1)	iohist="$iohist -> $basefile";;				#	.txt
					3)	iohist="$iohist -> $basefile";;				#	.udpsyslog
					4) 	iohist="$iohist -> $basefile";;				#	.sip
					5)	iohist="$iohist -> $basefile";;				# 	.syslog
					esac
				elif [[ $tmpfile != 0 ]]; then
					case $tmpfile in
					1)	iohist="$basefile";;	#	.txt
					3)	iohist="$basefile";;	#	.udpsyslog
					4) 	iohist="$basefile";;	#	.sip
					5)	iohist="$basefile";;	#	.syslog
					esac
				else
					iohist="$var -> $basefile"
				fi
				if [[ $iohist != "" ]]; then
					iohist="$iohist -> $output.asm"
				else
					iohist="$output.asm"
				fi
			fi
		else 
			iohist="$var -> $var.asm"
		fi

		if [[ ${#iohist} -lt 48 ]]; then
			echo -e "# Input/output file history: $iohist\n" >> "$newfile"
		else
			echo -e "# Input/output file history:" >> "$newfile"
			echo -e "# $iohist\n" >> "$newfile"
		fi

		check=$(egrep -a -c -e "<1[36][34567]>" "$file")

		if [[ $((vsyslog)) == 1 ]] && [[ $((check)) == 0 ]]; then
			echo "ALERT: expecting SYSLOG extracted from Wireshark but did not find any lines with <166> pattern."
			echo "Could $file be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			echo ''; continue
#		elif [[ $((vsyslog)) -lt 10 ]] && [[ $((check)) != 0 ]]; then
#			echo "ALERT: expecting ANDROID: and D/DeskPhoneServiceAdaptor lines but instead found some lines with <166> pattern."
#			echo "Could $file be a SYSLOG extracted from Wireshark instead of vantage.log from a K1xx debugreport?"
#			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
#			exit 0
		fi

# if [ -f DEBUG.dbg ]; then
		case $vsyslog in
		10|11)		convert_k1xx;;
		2|20|175)	convert_h175;;
#		20)		convert_syslog_mega;;
		esac
# else
# echo basefile=$basefile bfile=$bfile file=$file output=$output newfile=$newfile
# 	echo Converting $vsyslog $file
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
				server=""; server=$(egrep -m 1 "^Server:" "$newfile")
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
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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

				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
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
			fi		
		fi

		if [[ $((error)) == 0 ]]; then
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

		if [[ $bDelTemp != 0 ]] && [[ $tmpfile != 0 ]] && [[ $var != $file ]]; then
			case $tmpfile in
			1|2|3|4|5)	rm $file;;
			esac
		fi

		if [[ $((error)) == 0 ]] && [[ $((bCAT)) != 0 ]]; then
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
	echo -e "convert_siplog() received null string for input. Contact developer.\n"
	error=6
fi	
} # convert_siplog()

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbf:sdk:v:ACIN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
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
	s)
		sipstat=0;;
	d)
		bDelTemp=0;;
	b)
		base64decode=0;;
	e)
		endptaddr=${OPTARG};;
	k)
		enckey=${OPTARG};;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 10 ]] || [[ $((vsyslog)) -gt 11 ]]; then
			vsyslog=0
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
unzip -qq -v >/dev/null 2>&1
if [[ $? -le 1 ]]; then
	bUnzip=1
fi
gunzip --version >/dev/null 2>&1
if [[ $? -le 1 ]]; then
	bGunzip=1
fi

for var in "$@"
do
	if [[ $var == "-"* ]]; then
  		if [[ $var == "-f"* ]]; then
			skipper=1
		elif [[ $var == "-e"* ]]; then
			skipper=2
		elif [[ $var == "-k"* ]]; then		
			skipper=3
		elif [[ $var == "-N"* ]]; then
			skipper=4
		elif [[ $var == "-v"* ]]; then
			skipper=9
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
			enckey=$var
		elif [[ $((skipper)) == 4 ]]; then
			findANI=$findANI				# finANI=$var
		elif [[ $((skipper)) == 9 ]]; then
			vsyslog=$var
		fi	
		skipper=0		
		continue
	fi

	file=""; 	filelist=""; filetype=""
	currtime=$(date +%R:%S); currdir=$PWD
	error=0;	vantage=0
	input="";	input2=""
	target="";	destdir=""
	bdir="";	bvar="";	folder=""
	tmpfile=0;	vsyslog=0

	bSinglefile=0
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
		target="K1xx"
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
		echo -en "\nExploring content in $var folder ... stand by\r"
		destdir="$var"
		cd "$var"; folder="$bvar"
		explore_folders
	
	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"
		file="$var"

		if [[ $filetype =~ text ]] || [[ $filetype == "data" ]]; then
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
		else
			filecontent="VANTAGE"		
		fi

		if [[ $filetype == "data" ]]; then
#			filecontent=$(egrep -m 1 "ANDROID:" "$file")
			recX=$(egrep -a -c -m 1 "CSeq:" "$file" 2>/dev/null)
			if [[ $filecontent =~ ANDROID ]]; then
				filecontent="ANDROID"
			elif [[ $enckey != "" ]]; then						# debugreport.tar.gz, encrypted is "data"
				openssl version >/dev/null
				if [[ $? == 0 ]]; then
					if [[ $file == *"."* ]]; then
						input2=${file%%.*}						# debugreport.tar.gz -> debugreport
					else
						input2="$file"
					fi
					openssl aes-128-cbc -d -salt -k $enckey -in "$file" -out "$input2-decrypted.tgz" 2>/dev/null
					if [[ $? != 0 ]] || [[ $(file -b "$input2-decrypted.tgz") == "data" ]]; then
						openssl aes-256-ctr -md sha256 -salt -k $enckey -in "$file" -out "$input2-decrypted.tgz" 2>/dev/null
						if [[ $? != 0 ]]; then
							echo "error: Could not decode $bvar using \"openssl aes-256-ctr -md sha256 -salt -k $enckey\""
							echo -e "Verify encryption key with provider.\n"
							filecontent="error"; error=6; continue
						else
							vantage=3
						fi
					else
						vantage=2
					fi
					if [[ $error == 0 ]] && [ -s "$input2-decrypted.tgz" ]; then
						file="$input2-decrypted.tgz"; tmpfile=2
						basefile=$(basename "$file")
						filecontent="DECRYPTED"
						filetype=$(file -b "$file")
						echo "Decoded $bvar into $basefile successfully using \"openssl\"."
					else						
						echo -e "error: could not create $input2-decrypted.tgz file.\n"
						error=4; file=""; filecontent="UNKNOWN"; continue
					fi
				else
					echo -e "error: "openssl" was not found, required for decoding $bvar\n"
					error=5; continue
				fi
			elif [[ $((recX)) == 0 ]]; then
				echo -e "\nerror: missing encryption key.  Re-try with -k option.\n"
				error=4; continue
			fi
		fi

		filetype2=$(file -bZ "$file")

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

			if [[ $filetype =~ compressed ]]; then
				if [[ $filetype2 =~ ASCII|text|data|tar ]]; then
					if [[ $bfile == *"."* ]]; then
						input2=${bfile%.*}
					else
						input2="$bfile"
					fi

					if [[ $bGunzip != 0 ]]; then
						echo "Uncompressing $zfile into $input2 ...                                                        "
						gunzip -q -c "$zfile" > "$input2" 2>/dev/null

						if [[ $? -le 1 ]]; then
							file="$input2"; tmpfile=2
							filetype=$(file -b "$file")
							filecontent="ASCII"
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
		fi

		if [[ $filetype =~ tar ]] || [[ $filetype2 =~ tar ]]; then
			tar --version >/dev/null 2>&1
			if [[ $? == 0 ]]; then
				if [[ $file == *"."* ]]; then
					input=${file%.*}					
				else
					input="$file"
				fi

				if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp" 2>/dev/null
					if [[ $? != 0 ]]; then						
						echo -e "\nerror: could not delete existing $input.tmp folder."
						echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
						error=7; cd $currdir; input=""; continue
					fi
				fi
				mkdir "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd $currdir; continue
				fi

				cd "$input.tmp"
				if [[ $file != "" ]] && [[ $file != $var ]]; then
					bfile=$(basename "$file")
				else
					bfile=$(basename "$var")
				fi

				echo "Extracting $bfile using \"tar\" ...                                                                "
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

		elif [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype =~ "Zip archive" ]]; then
			if [[ $bvar == *"."* ]]; then
				input=${bvar%.*}
			else
				input="$bvar"
			fi
			if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then				
					echo -e "\nerror: could not delete temp folder: $input.tmp in $PWD."
					echo -e "Check if any subfolders or files are open (in other shell sessions).\n"
					error=7; cd $currdir; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then				
				echo -e "\nerror: could not create $input.tmp folder in $PWD.\n"
				error=7; cd $currdir; continue
			fi
			cd "$input.tmp"
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")
			fi

			if [[ $bUnzip != 0 ]]; then
				echo "Uncompressing $bfile into $input.tmp using \"unzip\" ...                                                                            "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? != 0 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "\nerror: could not uncompress $bfile, using \"unzip\"."
					echo -e "Suggesting to validate \"unzip\" manually on \"$bfile\".\n"
					error=8; cd $currdir; input=""; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"					
					explore_folders
				fi
			else
				error=8; cd $currdir; rm -rf "$input.tmp" 2>/dev/null
				echo -e "\nerror: could not uncompress $bvar, \"unzip\" utility not found."
				echo -e "Suggesting to deploy \"unzip\" package. in Ubuntu, you can install it by typing: \"sudo apt install unzip\".\n"
				continue
			fi
			cd $currdir

		elif [[ $filetype =~ capture ]]; then
			if [[ $filetype =~ tcpdump ]] || [[ $filetype =~ pcap ]]; then
				n=0; line=$(whereis tshark)
				tshark --version >/dev/null 2>&1
				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
		     		echo -e "\nerror: unable to locate 'tshark' command"
					echo -e "'tshark' is required to extract syslog messages from $bvar into text file\n"
					error=10; continue
				else
#					origfile=$file
					echo -e "\nExtracting syslog out of $bvar ..."
					if [[ $endptaddr != "" ]]; then
						tshark -r "$file" -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					else
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi
# There is no SIPMESSAGE log category for Brio/Vantage
# SIP messages are found in ANDROID: log category
# TODO: R2 sends SIP msg in remote syslog, but R3 does not send any remote syslogs (yet to clarify/confirm this)
#					egrep DeskPhoneServiceAdaptor "$file.syslog" > "$file.syslog2"

					if [[ $? == 0 ]] && [ -s "$file.syslog2" ]; then
						n=$(egrep -m 1 -c "\n[RT]X\ " "$file.syslog2")
					elif [ ! -f "$file.syslog2" ]; then
						echo -e "\nerror: could not extract SYSLOG out of $bvar using tshark utility.  Verify tshark manually.\n"
						error=3; continue
					elif [ -f "$file.syslog2" ]; then
						echo -e "\nerror: no SYSLOG messages have been found in $bvar."
						echo -e "Was remote SYSLOG enabled in unsecure mode (udp:514) on this endpoint?\n"
						error=3; continue
					fi

					if [[ $((n)) != 0 ]]; then
						n=$(egrep -m 1 -c "SIPMESSAGE" "$file.syslog2")
						if [[ $((n)) != 0 ]]; then
#							sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
#							sed 's/\\r\\n\ /\'$'\n''/g' < "$file.syslog2" | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
							egrep "SIPMESSAGE:" "$file.syslog2" | sed 's/\\r\\n\ /\'$'\n''/g' | sed 's/\\nTX/\'$'\n''TX/g' | sed 's/\\nRX/\'$'\n''RX/g' | sed 's/\\r\\n/\'$'\n''/g' | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' | sed 's/&lt;/\</g' | sed 's/&gt;/\>/g' > "$file.syslog"
							if [[ $? == 0 ]] && [ -s "$file.syslog" ]; then
								file="$file.syslog"; tmpfile=2
								bSinglefile=1								
#								vsyslog=11
							else
								echo -e "\nerror: could not extract SIPMESSAGES out of $file.syslog2\n"
								error=3; continue
							fi
						else
							echo -e "\nerror: no SIPMESSAGES have been found in the extracted SYSLOG stream of $bvar\n"
							error=3; continue
						fi
					else
						file="$file.syslog2"; tmpfile=2
						bSinglefile=1						
#						vsyslog=11
					fi
				fi
		  	fi

		elif [[ $filetype =~ text ]]; then
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
			if [[ $filecontent =~ ANDROID: ]]; then 
				rec=$(wc -l < "$file")
				xlines=$(egrep -a -c "<16[34567]>" "$file")
				if [[ $rec == 0 ]] && [[ $xlines != 0 ]]; then				# TODO rec==0 sure? maybe rec != 0
					sed 's/<16[34567]>/\n/g' < "$file" > "$file.udpsyslog"
					if [[ $? == 0 ]] && [ -s "$file.udpsyslog" ]; then
						file="$file.udpsyslog"; tmpfile=2
						bSinglefile=1
#						vsyslog=11
					else
						echo -e "\nerror: could not filter $bvar for <16[34567]>\n"
						error=3
					fi
				fi
			fi

		elif [[ $file == "" ]] && [[ $error == 0 ]]; then
			echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
			error=4
		fi

	elif [[ $filetype =~ cannot|open ]]; then
		echo -e "\nerror: $bvar was not found or unable to open. Verify path and filename."
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
	if [[ $((alllogs)) != 0 ]] && [[ $filelist != "" ]]; then
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
			echo -e "\nWarning: about to convert multiple files ($nfiles x vantage.log/EndpointLog+sig+CPS.txt) found in $var."
			echo -e "This may take a while... you may want to execute this script on a more powerful PC or server.\n"

			let z=0; file=""
			for file in $filelist;
			do
				if [[ $file != "" ]]; then
					IFS=$origIFS
					z=$(egrep -m 1 -c "CSeq:" "$file")
					if [[ $((z)) != 0 ]]; then
						convert_siplog
					else
						bfile=$(basename "$file")
						echo -e "\n$bfile : No SIP messages have been found."
					fi				
					z=0; error=0
				fi
				IFS="="; currtime=$(date +%R:%S)
			done

			if [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
				echo -e "All converted files found in $bvar have been concatenated into $ctarget.\n"
				ls -l "$ctarget"; echo ''
			fi

		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
#			if [[ $input != "" ]]; then
#				file="$input.tmp/$file"
#			fi
			IFS=$origIFS
			convert_siplog	
		fi
		IFS=$origIFS

	elif [[ $file != "" ]]; then
		convert_siplog	
	fi

	if [[ $bDelTemp != 0 ]]; then
		if [[ $input2 != "" ]] && [ -d "$input2.tmp" ]; then
			rm -rf "$input2.tmp"
		fi
		if [[ $input != "" ]]; then 
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp"
			fi
			if [ -f "$input" ]; then
				rm "$input"
			fi
		fi
		if [[ $tmpfile == 2 ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
		fi		
	fi
done

if [[ $((converted)) != 0 ]] && [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget\n"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0