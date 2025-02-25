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
adjusthour=0
base64decode=1
localip="1.1.1.1:1111"
protocol="TLS"
enckey=""
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

## 10) vantage.log
## 1) from wireshark SYSLOG UDP stream - see ade_vdic_syslog1.txt
## <166>Jan 12 16:43:54 135.105.160.122 SIPMESSAGE: +01:00 2022 562 1 .TEL | 0 [Part 01 of 02]
## 2) created by KIWI Syslog r8.x, default ISO log file format - see EqVDI2-SyslogCatchAll.txt
## 2022-02-08 17:22:43	Local4.Info	135.123.66.134	Feb  8 17:22:43 135.123.66.134 SIPMESSAGE: +01:00 2022 338 1 .TEL | 0 [Part 02 of 02]<010>-id=1<013><010>Content-Length:     0<013>
## challenges: <013><010> } Length is bogus (666), Month is bogus (12)

## H175: 2021-01-29 12:22:32	Local4.Info	10.8.232.36	Jan 29 12:25:09 10.8.232.36 SIPMESSAGE: +01:00 2021 034 1 .TEL | 0 Outbound SIP message to 10.8.12.6:5061<010>TX INVITE sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook SIP/2.0<013><010>From: <sip:2470@smn.rosneft.ru>;tag=6013b855715502b6693p7t1r1q3l5f196nmh5h1k6j6l3o32_F247010.8.232.36<013><010>To: <sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook><013><010>Call-ID: 217_6013b855-7fb11eab4692x5j163b5x70316n6p8336jx5m2c32_I247010.8.232.36<013><010>CSeq: 535 INVITE<013><010>Max-Forwards: 70<013><010>Via: SIP/2.0/TLS 10.8.232.36:1026;branch=z9hG4bK217_6013b8559dc2a981w724ais5q1n3k5x385pw2t4z76442_I247010.8.232.36<013><010>Supported: 100rel,eventlist,feature-ref,replaces,tdialog<013><010>Allow: INVITE,ACK,BYE,CANCEL,SUBSCRIBE,NOTIFY,MESSAGE,REFER,INFO,PRACK,PUBLISH,UPDATE<013><010>User-Agent: Avaya H175 Collaboration Station H1xx_SIP-R1_0_2_3_3050.tar<013><010>Contact: <sip:2470@10.8.232.36:1026;transport=tls>;+avaya-cm-line=1<013><010>Accept-Language: ru<013><010>Expires: 30<013><010>Content-Length:     0<013>
## 9) Nov 15 10:41:56 localhost 192.168.202.19 ANDROID: +03:00 2021 000 0 | 11-15 13:41:55.866 D/DeskPhoneServiceAdaptor( 2432): [SIP]:RECEIVED 970 bytes from 192.168.70.104:5061 { - see vantage.log

function usage ()  {
    echo "traceK1xx.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceK1xx.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "    <LOG_FILE>\tcould be either a debugreport (encrypted or decrypted) pulled from Avaya Vantage (K1xx),"
	echo -e "\t\tor a pcap/pcapng file including remote syslog packets,"
	echo -e "\t\tor syslog text of \"Follow UDP Stream\" manually extracted from a pcap file using Wireshark,"
	echo -e "\t\tor remote syslog txt file captured by KIWI or other syslog server (refer to doc),"
	echo -e "\t\tor a vantage.log file found in a debugreport of a K1xx phone running Basic or Connect app."	
    echo -e "\t\tThis log file can be located in /var/log (R2.x) or in /data/vendor/var/log (R3.x)."
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-k:\t\tset decryption key for debugreport decoding"	
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution or result of this conversion"
	echo -e "\t-A:\t\tconvert all aditional logs in logreport where SIP message found (vantage.logX)"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	dirdefined=0
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	siplines=$((siplines+1))
	if [[ $((voutput)) == 1 ]]; then
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -en "\n$line" >> "$newfile"
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
	else
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
			if [[ ${#var} -lt 40 ]]; then
				echo -en "$var => $n/$rec Msgs converted                      \r"
			else
				echo -en "$file => $n/$rec Msgs converted                      \r"
			fi
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
		partnum=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
			maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | awk '{print $3}' | awk -F ']' '{print $1}')
			# maxpart=$(echo $line | awk -F "Part " '{print $2}' | cut -d ' ' -f 3)
		fi	
		sipsplit=1
	fi
} # sip_partnum()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line == *"[SIP]:RECEIVED"* ]]; then
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
		##ip=$(echo $line | awk '{print $5}')
	elif [[ $line == *"[SIP]:SENDING"* ]]; then
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
		##ip=$(echo $line | awk '{print $5}')
	fi
	
	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $((vsyslog)) == 10 ]]; then
	 		ip=$(echo "$line" | cut -d' ' -f20)
			siplength=$(echo "$line" | cut -d' ' -f17)
		elif [[ $((vsyslog)) == 11 ]]; then
		 	ip=$(echo "$line" | cut -d' ' -f16)
			siplength=$(echo "$line" | cut -d' ' -f13)
		fi
	fi
fi	
} # sip_direction()

function get_sipmonth () {
	sipmonth="66"	
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
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 10 ]]; then 								# native vantage.log
		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(echo "$line" | awk '{print $5}')			# cut -d' ' -f5)
			sipyear=$(echo "$line"     | awk '{print $8}')			# cut -d' ' -f8)
			sipday=$(echo "$line"      | awk '{printf "%02i",$2}')
			month=$(echo "$line"       | cut -d' ' -f1)
			get_sipmonth
		fi

		sipmsec=$(echo "$line" | awk '{print $13}') # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

		siphour=$(echo $sipmsec | cut -d':' -f1)
		sipmin=$(echo $sipmsec  | cut -d':' -f2)
		sipsec=$(echo $sipmsec  | cut -d':' -f3)
		sipmsec=$(echo $sipsec  | cut -d'.' -f2)		
		sipsec=$(echo $sipsec   | cut -d'.' -f1)

#			siptime=$(echo $line | awk '{print $3":"$8}')  # msec included in $8
####		siptmp=$(echo $line | awk '{print $6}')
####		tzhour=$(echo $siptmp |cut -d':' -f 1) # awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
####		tzmin=$(echo $siptmp | cut -d':' -f 2) # awk -F ':' '{print $2}')

	elif [[ $((vsyslog)) == 11 ]]; then 				# syslog UDP stream converted
# 10.16.4.24 ANDROID: +03:00 2020 000 0 | 06-19 12:39:08.793 D/DeskPhoneServiceAdaptor( 3111): [SIP]:SENDING 1425 bytes to 10.16.26.183:5061 {	
		foundipaddr=$(echo "$line" | cut -d' ' -f1)
		sipyear=$(echo "$line"     | cut -d' ' -f4)
		sipday=$(echo "$line"      | cut -d' ' -f8 | cut -d'-' -f2)		# awk '{printf "%02i",$2}')
		sipmonth=$(echo "$line"    | cut -d' ' -f8 | cut -d'-' -f1)		# awk '{printf "%02i",$2}')		
		
		sipmsec=$(echo "$line" | cut -d' ' -f9)			# awk '{print $9}') # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

		siphour=$(echo $sipmsec | cut -d':' -f1)
		sipmin=$(echo $sipmsec  | cut -d':' -f2)
		sipsec=$(echo $sipmsec  | cut -d':' -f3)
		sipmsec=$(echo $sipsec  | cut -d'.' -f2)		
		sipsec=$(echo $sipsec   | cut -d'.' -f1)

	elif [[ $((vsyslog)) == 2 ]]; then  			# KIWI syslog
		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(echo "$line" | awk '{print $5}')
			sipyear=$(echo "$line"     | cut -d' ' -f1 | awk -F '-' '{print $1}')
			sipmonth=$(echo "$line"    | cut -d' ' -f1 | awk -F '-' '{print $2}')
			sipday=$(echo "$line"      | cut -d' ' -f1 | awk -F '-' '{print $3}')			
		fi

		## endptaddr=$(echo $line | awk '{print $4}')
		## siplength=$(echo $line | awk '{print $13}')

##						xline=$(echo $line | awk -F '|' '{print $2}')
##						ip=$(echo $xline | awk '{print $(NF)}')
##						ip1=$(echo $ip | awk -F ":" '{print $1}')
##						ip2=$(echo $ip | awk -F ":" '{print $2}')
						
		siphour=$(echo "$line" | awk '{print $7}')
		sipmsec=$(echo "$line" | awk '{print $12}')
		sipmin=$(echo $siphour | cut -d':' -f2) 		# awk -F ':' '{print $2}')
		sipsec=$(echo $siphour | cut -d':' -f3) 		# awk -F ':' '{print $3}')
		siphour=$(echo $siphour| cut -d':' -f1) 		# awk -F ':' '{print $1}')

		siptmp=$(echo "$line"  | awk '{print $10}')
		tzhour=$(echo $siptmp  | cut -d':' -f1) 		# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
		tzmin=$(echo $siptmp   | cut -d':' -f 2)		# awk -F ':' '{print $2}')

		## ip=$(echo $line | awk '{print $NF}')
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

function convert_siplog () {
if [[ $file != "" ]]; then
	lhost=""
	platform=""
	rec=$(egrep -a -c "): \[SIP\]:" "$file")
	sample=$(egrep -a -m 1 "): \[SIP\]:" "$file")
	filecontent=$(egrep -a -m 1 "ANDROID:" "$file")

	if [[ $filecontent =~ ANDROID ]]; then
		if [[ $rec == 0 ]];	then
			echo "error: No SIP messages have been found in $file. Perhaps this file is not a vantage.log file."
			echo "Or, debug loglevel with SIPMESSAGE logcategory was not enabled."
			rec=$(egrep -a -c -e "^CSeq:*" "$file")
			error=1
			if [[ $rec == 0 ]]; then
				echo 'In fact, no sign of any "CSeq:" lines in '$file
				echo ''; error=2; return
			else
				echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages in '$file
				echo "Verify source and content of $file"
				echo ''; rec=0; return
			fi
		elif [[ $((vsyslog)) == 0 ]]; then
			lhost=$(echo $sample    | cut -d' ' -f4)
			platform=$(echo $sample | cut -d' ' -f6)

			if [[ $lhost == "localhost" ]] && [[ $platform == "ANDROID:" ]]; then
				vsyslog=10
			else
				platform=$(echo $sample | cut -d' ' -f2)
				if [[ $platform == "ANDROID:" ]]; then
					vsyslog=11
				fi
			fi
		fi
	else
		filecontent=$(egrep -m 1 "SIPMESSAGE:" "$file")
		if [[ $filecontent == *"SIPMESSAGE:"* ]]; then
			filecontent=$(egrep -m 1 "H175" "$file")
			if [[ $filecontent == *"H175"* ]]; then
				error=3
				echo "error: found \"SIPMESSAGE:\" and \"H175\" strings in $file"
				echo "This hints this logfile could rather be related to H175 phone"
				echo "Try to run \"trace96x1.sh\" or \"traceVDIC.sh\" script instead."
				echo ''; return
			fi
		fi
	fi

	if [[ $((vsyslog)) == 0 ]]; then
		error=9
		echo "error: could not recognize content of $file"
		echo "Verify source and content of $file"
		echo ''; return
	elif [[ file != "" ]] && [[ $rec != 0 ]]; then
		base64found=0
		base64msg=0
		foundipaddr=""
		basefile=""
		output=""
		useragent=""
#		prevline=""
		partnum="00"
		maxpart="99"
		nlines=0
		sipyear=0
		siphour=0
		sipmin=0
		sipmsec=0
		n=0
		sipmsg=0
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
		sipmaxsplit=0
		sipwordlist=""		
		longestmsg=0			

		reset_sipmsg

		if [[ $file == *"/"* ]]; then 
#			basefile=$(echo "${file#*/}")
			basefile=$(echo "${file##*/}")
		else
			basefile=$file
		fi
#		if [[ $file == *"."* ]]; then
#			basefile=$(echo "${basefile%.*}")
#		else
#			basefile=$file
#		fi

		if [[ $var != $basefile ]] && [[ $var != $file ]]; then
			if [[ $var == *"."* ]]; then
				xfile=$(echo "${var%%.*}")
				if [[ $var == $basefile ]]; then
					output=$var
				elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
					output="$xfile-$basefile"
				else
					output=$var
				fi
			fi
		else
			output=$var
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
			echo -e "# Input/output file: $var --> $file --> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var\n" >> "$newfile"
		fi

#			conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
#    	    conv=$(awk -e '/: \[SIP\]:/{flag=1} flag; /}/{flag=0}' "$file")
		conv=$(awk -W source='/: \[SIP\]:/{flag=1} flag; /}/{flag=0}' "$file")

		check=$(egrep -a -c -e "<1[36][34567]>" "$file")
		if [[ $((vsyslog)) == 1 ]] && [[ $((check)) == 0 ]]; then
			echo "ALERT: expecting SYSLOG extracted from Wireshark but did not find any lines with <166> pattern."
			echo "Could $file be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			exit 0
		elif [[ $((vsyslog)) -lt 10 ]] && [[ $((check)) != 0 ]]; then
			echo "ALERT: expecting ANDROID: and D/DeskPhoneServiceAdaptor lines but instead found some lines with <166> pattern."
			echo "Could $file be a SYSLOG extracted from Wireshark instead of vantage.log from a K1xx debugreport?"
			echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
			exit 0
		fi
		
		while IFS= read -r line
		do
			linelength=${#line}
			nlines=$((nlines+1))
								
			if [[ $line == *"): [SIP]:"* ]]; then
				if [[ $endptaddr != "" ]]; then
					if [[ $line != *$endptaddr* ]]; then	
						continue
					fi
				elif [[ $((sipstart)) != 0 ]]; then
					complete_sipmsg
				fi

				insidesip=1 # this is a new SIP msg
				get_sip_datetime

				if [[ $((vsyslog)) != 1 ]] || [[ $((sipsplit)) == 0 ]]; then
					if [[ $((dirdefined)) == 0 ]]; then
						sip_direction
						if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
							reset_sipmsg
							continue
						else
							base64found=0							
							siptotalmsg=$((siptotalmsg+1))
							sipmsg_header
						fi
					fi
				fi
				
			elif [[ $((vsyslog)) -ge 10 ]] && [[ $((insidesip)) == 1 ]]; then  ## line does not have ": [SIP]:", so we are potentiall inside a new SIP msg
				if [[ $line == *"DeskPhoneServiceAdaptor"* ]]; then
					line=$(echo "$line" | awk -F'DeskPhoneServiceAdaptor' '{print $2}'| awk -F"[0-9]{4}): " '{print $2}')  # TODO: need a better regexp for [-0]{4}

					if [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
						if [[ ${#line} -lt 2 ]]; then
							continue
						else 
							start_sipmsg
						fi

					elif [[ $line == "}"* ]] || [[ $line == "[null]"* ]]; then
						complete_sipmsg
				
					elif [[ ${#line} != 0 ]]; then
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
		done <<<"$conv"

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
					echo "    have been converted for addr=$endptaddr into $output.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				echo -e "$NL\tUser-Agent: $useragent"
				if [[ $foundipaddr != "" ]] && [[ $foundipaddr != "0.0.0.0" ]]; then
					echo -e "\t\tusing ipaddr = $foundipaddr"
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
		echo "Task started: $currtime - completed: $(date +%R:%S)"
		echo ''
		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd; ls -l "$output.asm"			
#		if [[ $tmpfile !=0 ]] && [[ $file != $var ]]; then
#			rm $file
#		fi
		# echo ''
	fi
fi	
} # convert_siplog()

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbf:sk:v:A" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)  
		alllogs=1;;
	s)
		sipstat=0;;
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
		elif [[ $var == "-k"* ]]; then
			skipper=3
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
		elif [[ $((skipper)) == 9 ]]; then
			vsyslog=$var
		fi	
		skipper=0		
		continue
	fi

	file=$var
	currtime=$(date +%R:%S)
	currdir=$PWD
	error=0
	vantage=0
	tmpfile=0
	input=""
	input2=""
	filelist=""
	
	if [ -f $file ]; then
		echo -en "Exploring content in $var... stand by\r"

		filetype=$(file -b "$file")

		if [[ $filetype == *"text"* ]] || [[ $filetype == "data" ]]; then
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
		else
			filecontent="VANTAGE"		
		fi

		if [[ $filetype == "data" ]]; then
#			filecontent=$(egrep -m 1 "ANDROID:" "$file")
			if [[ $filecontent =~ ANDROID ]]; then
				filecontent="ANDROID"
			elif [[ $enckey != "" ]]; then						# debugreport.tar.gz, encrypted is "data"
				openssl version >/dev/null
				if [[ $? == 0 ]]; then
					if [[ $file == *"."* ]]; then
						input=$(echo "${file%%.*}")			# debugreport.tar.gz -> debugreport
					else
						input="$file"
					fi
					openssl aes-128-cbc -d -salt -k $enckey -in "$file" -out "$input-decrypted.tgz"
					if [[ $? == 0 ]]; then
						openssl aes-256-ctr -md sha256 -salt -k $enckey -in "$file" -out "$input-decrypted.tgz"
						if [[ $? == 0 ]]; then
							error=6
							echo "error: Could not decode $var using \"openssl aes-256-ctr -md sha256 -salt -k $enckey\""
							echo "Verify encryption key with provider."
							echo ''; continue
						else
							vantage=3
						fi
					else
						vantage=2
					fi
					if [[ $error == 0 ]] && [ -f "$input-decrypted.tgz" ]; then
						tmpfile=2
						file="$input-decrypted.tgz"
						filecontent="DECRYPTED"
						filetype=$(file -b "$file")
					else
						error=4
						file=""
						filecontent="UNKNOWN"
						echo "error: could not create $input-decrypted.tgz file"
						echo ''; continue
					fi
				else
					error=5
					echo 'error: "openssl" was not found, required for decoding '$var
					echo ''; exit $error
				fi
			else
				error=4
				echo "error: missing encryption key.  Re-try with -k option."
				echo ''; continue
			fi
		fi

		if [[ $filetype == *"compressed data"* ]]; then
			if [[ $file == *"."* ]]; then
				input2=$(echo "${file%.*}")
			else
				input2="$file"
			fi
			if [ -d "$input2.tmp" ]; then
				rm -rf "$input2.tmp"
				if [[ $? != 0 ]]; then
					error=100
					echo "error: could not delete $input.tmp folder. Check if any subfolders or files currently opened."
					exit $error
				fi
			fi
			mkdir "$input2.tmp"
			cd "$input2.tmp"			

			gunzip --version >/dev/null
			if [[ $? != 0 ]]; then
				gunzip -q "../$file"
				if [[ $? != 0 ]]; then
					error=8
					echo "error: could not uncompress $file, using \"gunzip\"."
					echo ''; exit $error
				fi
			else
				tar --version >/dev/null
				if [[ $? == 0 ]]; then
					tar zxf "../$file"
					if [[ $? != 0 ]]; then
						error=8
						echo "error: unable to uncompress $file, using \"tar\" utility."
						echo ''; exit $error
					fi
				else
					error=8
					echo "error: could not execute \"tar\" utility"
					echo ''; exit $error
				fi
			fi
			cd ..

			if [[ $vantage == 0 ]]; then
				if [ -f "$input2.tmp/var/log/vantage.log" ]; then
					vantage=2
				elif [ -d "$input2.tmp/data/vendor/var/log" ] && [ -f "$input2.tmp/data/vendor/var/log/vantage.log" ]; then
					vantage=3
				fi
			fi
			if [[ $vantage == 2 ]]; then
				if [ -f "$input2.tmp/var/log/vantage.log" ]; then
					tmpfile=0
					file="$input2.tmp/var/log/vantage.log"
					filelist=$(ls -t1 $input2.tmp/var/log/vantage.log*)

					if [ -f "$file" ]; then
						filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
					else
						filecontent="notfound"
					fi
				else 
					file=""
					filecontent=""
					tmpfile=0
				fi
			elif [[ $vantage == 3 ]]; then
				if [ -d "$input2.tmp/data/vendor/var/log" ] && [ -f "$input2.tmp/data/vendor/var/log/vantage.log" ]; then
					tmpfile=0
					file="$input2.tmp/data/vendor/var/log/vantage.log"
					filelist=$(ls -t1 $input2.tmp/data/vendor/var/log/vantage.log*)
					if [ -f "$file" ]; then
						filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
					else
						filecontent="notfound"
					fi
				else
					file=""
					filecontent=""
					filelist=""
					tmpfile=0					
				fi
			elif [ -f "$input2.tmp/var/log/EndpointLog_B+sig+CPS.txt" ] || [ -f "$input2.tmp/EndpointLog_B+sig+CPS.txt" ]; then
				error=3;
				echo "error: found EndpointLog_B+sig+CPS.txt file in $file"
				echo "Which hints that this file could rather be related to H175 phone."
				echo "Try to execute \"trace96x1.sh\" or \"traceVDIC.sh\" scripts instead."
				echo ''; continue
			fi
		elif [[ $filetype == *"capture"* ]]; then
			if [[ $filetype == *"tcpdump"* ]] || [[ $filetype == *"pcap"* ]]; then
		  		line=$(whereis tshark)

				if [[ ${#line} -gt 10 ]]; then
		    		tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog"
					if [[ $input == "" ]]; then
						input=$file
					fi
					file="$file.syslog"
					tmpfile=1
					vsyslog=11
		      	else
		     		echo "error: unable to locate 'tshark' command"
					echo "'tshark' is required to extract syslog messages from $file into text file"
					error=10
					echo ''; exit $error
				fi
		  	fi
		elif [[ $filetype == *"text"* ]]; then
			filecontent=$(egrep -a -m 1 "ANDROID:" "$file")
			if [[ $filecontent == *"ANDROID"* ]]; then 
				rec=$(wc -l < "$file")
				xlines=$(egrep -a -c "<16[34567]>" "$file")
				if [[ $rec == 0 ]] && [[ $xlines != 0 ]]; then
					sed 's/<16[34567]>/\n/g' < "$file" > "$file.udpsyslog"
					if [[ $input == "" ]]; then
						input=$file
					fi
					file="$file.udpsyslog"
					tmpfile=1
					vsyslog=11
				fi
			fi
		fi

	nfiles=0
	if [[ $((alllogs)) != 0 ]]; then
		if [[ $filelist != "" ]]; then
			nfiles=$(echo $filelist | wc -w)
		fi

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x vantage.log) found in $var"
			echo "This may take a while... you may want to execute this script on a more powerful PC or server."
			echo ''

			for file in $filelist;
			do
				convert_siplog
			done
		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			convert_siplog				
		fi
	elif [[ $file != "" ]]; then
		convert_siplog	
	fi
	
else
	echo "error: file $var was not found."
	error=3
fi
done