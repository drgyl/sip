#!/bin/bash
version="2.0.0.3"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
AWKSRCFLAG="-W source="
today=$(date +%m/%d/%Y)
year=$(date +%Y)
findANI=""
findCALLID=""
filterI=""; filterX=""
filtdate=""
sipstat=1
converted=0
let bAllINC=1
let noINFO=0
let noOPTIONS=0
let noSUBSCRIBE=0
let noPUBLISH=0
let noNOTIFY=0
let noREG=0
let noUPDATE=0
let noPONG=0
let bEVX=0
let bEXC=0
let bEVI=0
let bINC=0
let bEvPresence=0
let bEvDialog=0
let bEvCC=0
let bEvReg=0
let bEvCMstat=0
let bEvMsgSum=0
let bEvCCSprof=0
let bEvRefer=0
let bEvScrUpd=0
let bEvUAprof=0
let bEvConf=0
bIgnoreMonth=0
adjusthour=0
localtime=0
base64decode=1
bDebug=1
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
## 10) Nov  7 09:55:31 localhost 10.16.176.12 ANDROID: +07:00 2018 000 0 | 11-07 09:55:31.356 D/DeskPhoneServiceAdaptor( 6599): DEBUG[SIP]:SENDING 1107 bytes to 10.16.26.183:5061 { - see logcat-vantage-basic-r201.log
## 12) 06-14 18:55:51.140  2037  2709 D DeskPhoneServiceAdaptor: [SIP]:SENDING 653 bytes to 198.152.85.104:5061 { - see working_0003.txt

# TODO find/collect pcap for H175 & K1xx

function usage ()  {
    echo "traceK1xx.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceK1xx.sh [OPTIONS] [<LOG_FILE> | <debugreport> | <folder> ...]'
	echo '  Where:'
	echo -e "  <debugreport>\tcould be either a debugreport file (.tar/.tgz/.zip) - either encrypted or decrypted -"
	echo -e "\t\tand pulled from either an Avaya Vantage (K1xx) device or Avaya H175 Collaboration Station,"
	echo -e "  <LOG_FILE>\tor a vantage.log file found in a debugreport of a K1xx phone running Basic or Connect app,"	
	echo -e "\t\tor an EndpointLog+sig+CPS.txt found in a debugreport of a H175 device."
	echo -e "\t\tor a pcap/pcapng file including remote syslog packets,"
	echo -e "\t\tor syslog text of \"Follow UDP Stream\" manually extracted from a pcap file using Wireshark,"
	echo -e "\t\tor remote syslog txt file captured by KIWI or other syslog server (refer to doc)."
	echo -e "  <folder>\tincludes one or more of the files extracted from a debugreport (eg. vantage.log.X)"	
#    echo -e "\nWithin debugreport these logfiles are located either in /var/log (r2.x) or in /data/vendor/var/log (r3.x).\n"
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-k \t\tset decryption key for debugreport decoding"	
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"
#	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"		
#	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-N ANI|id:CallID       find a call with From/To header matching to ANI (digit string) or to CallID"
	echo -e "\t-I str1,str2,str3,...  Include only SIP requests matching with string, eg. -I INFO,ev:reg,ev:pres"	
	echo -e "\t-X str1,str2,str3,...  eXclude SIP requests matching with string eg. -X ev:pres,OPTIONS,ev:ccs-pro"	
	echo -e "\t-s \t\tdo not provide statistics/progress on execution or result of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
	echo -e " Note: -I/-X option supports these SIP methods: INFO,NOTIFY,OPTIONS,PONG,PUBLISH,REGISTER,SUBSCRIBE,UPDATE"
	echo -e "\tas well as events for PUBLISH/NOTIFY messages: ev:pres(ence), ev:dia(log), ev:reg, ev:ccs(-profile),"
	echo -e "\tev:cm-feat(ure-status), ev:cc-info, ev:message(-summary), ev:conf(erence), ev:ref(er), ev:scr(een),"
	echo -e "\tev:ua(-profile) and ev:push(-notification)"
	echo ''		
} # usage()

function reset_sipmsg () {
	sipsplit=0;		partnum="00"; 	maxpart="99"; 	currpartnum="555"
	insidesip=0;	sipstart=0;		dirdefined=0
	siplines=0;   	base64found=0;  badmsg=0
	foundipaddr=""; ip=""
	sipdate="";		siptime=""
	linebuf=""; 	linebuf64="";	embedded=0
	prevcseq=$currcseq;	prevsipword=$sipword
	sipword="";		cseqword="";	currcseq=0
	notifyrefer=0;	sipnotify=0;	prevline="notempty"
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	sipword=$(cut -d' ' -f1 <<< "$line" | sed -e 's/[[:space:]]*$//')
	if [[ $sipword == "" ]]; then
		if [[ $((siplength)) == 4 ]]; then							# PONG message (empty SIP)
			sipword="PONG";	nPONG=$((nPONG+1))
		else
			echo -e "\nALERT: sipword in start_sipmsg() is null string on msgno:$sipmsg at $siptime! Contact developer."
			if [[ $line == "" ]]; then
				echo vsyslog=$vsyslog -- line#$nlines -- msgno=$sipmsg -- siptime=$siptime -- siplength=$siplength -- line is empty.
			else
				echo vsyslog=$vsyslog -- line#$nlines -- msgno=$sipmsg -- siptime=$siptime -- siplength=$siplength -- linelength=${#line} -- line=$line
			fi
		fi
	elif [[ $sipword == "SIP/2.0" ]]; then
	   sipword=$(awk -F"SIP/2.0 " '{print $2}' <<< "$line" | sed -e 's/[[:space:]]*$//' | tr -d "\r")
	elif [[ $sipword == "NOTIFY" ]]; then
		sipnotify=1
	fi

	if [[ $linebuf == "" ]]; then
		linebuf="$line"
	else
		linebuf="$linebuf\r\n$line"
	fi	
fi
} # start_sipmsg()

function complete_sipmsg () {
if [[ $((sipstart)) != 0 ]]; then	
	if [[ $linebuf != "" ]] && [[ $sipword != "" ]]; then
		sipmsg=$((sipmsg+1))
		timelast="$sipdate $siptime"

		if [[ $sipword != "" ]]; then
			lastmsg="$sipword"
			if [[ $sipwordlist != *$sipword* ]]; then
				if [[ $sipwordlist == "" ]]; then
					sipwordlist="$sipword"
				else
					sipwordlist="$sipwordlist | $sipword"
				fi
			fi

			if [[ $((sipmsg)) == 1 ]]; then
				firstmsg=$lastmsg; 	timefirst=$timelast
			fi
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

		elif [[ $partnum != "00" ]]; then
			echo -e "\nerror: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime"
			echo -e "# error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime" >> "$newfile"		
#			echo ''; exit 1
		fi

		if [[ $prevsiptime != "" ]]; then
			if [[ $siptime < $prevsiptime ]]; then
				badmsg=1
				if [[ $sipbadtimemsg == "" ]]; then
					sipbadtimemsg="$sipmsg $prevsiptime $siptime"
				fi
			fi
		fi
		prevsiptime=$siptime

		if [[ $siplength == 0 ]]; then
			siplength=${#linebuf}
		fi

		siplines=$(wc -l <<< "$linebuf")
		lineX=$(head -1  <<< "$linebuf")

		case $dirdefined in
		1) 	sipin=$((sipin+1))
			if [[ $((sipsplit)) != 0 ]]; then
				splitin=$((splitin+1))
			fi
			if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then
				sipmaxlines=$siplines
				longestmsg=$sipmsg
				longestsipword="RX $sipword"
			fi;;
		2)	sipout=$((sipout+1))
			if [[ $((sipsplit)) != 0 ]]; then
				splitout=$((splitout+1))
			fi
			if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then
				sipmaxlines=$siplines
				longestmsg=$sipmsg
				longestsipword="TX $sipword"
			fi;;
		esac

		if [[ $voutput != 3 ]] || [[ $prevsipword != "PONG" && $sipword != "PONG" ]]; then
			if [[ $((sipsplit)) != 0 ]]; then
				if [[ $base64found != 0 ]]; then
					if [[ $embedded != 0 ]]; then
						echo -e "# msgno: $sipmsg (split, embedded) - Base64dump found" >> "$newfile"
					else
						echo -e "# msgno: $sipmsg (split) - Base64dump found" >> "$newfile"
					fi
				elif [[ $embedded != 0 ]]; then
					echo -e "# msgno: $sipmsg (split, embedded)" >> "$newfile"
				else
					echo -e "# msgno: $sipmsg (split)" >> "$newfile"
				fi			
			elif [[ $base64found != 0 ]]; then
				if [[ $embedded != 0 ]]; then
					echo -e "# msgno: $sipmsg (Embedded) - Base64dump found" >> "$newfile"
				else
					echo -e "# msgno: $sipmsg - Base64dump found" >> "$newfile"
				fi
			elif [[ $embedded != 0 ]]; then
				echo -e "# msgno: $sipmsg (Embedded)" >> "$newfile"
			else
				echo -e "# msgno: $sipmsg" >> "$newfile"			
			fi
		fi

		if [[ $((sipstart)) == 1 ]] && [[ $((vsyslog)) -ge 211 ]]; then
			n=$((n+1))	
			echo -e "\n# error: incomplete SIP message (sipword=$sipword) at $sipdate $siptime ($n)\n" >> "$newfile"
			if [[ $bDebug == 0 ]]; then
				echo -e "\nerror: incomplete SIP message (sipword=$sipword) at $sipdate $siptime ($n)\n"
			fi
		else	
			case $voutput in
			1)	echo -e "[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
				echo -e "{$NL[$sipstream] $lineX" >> "$newfile"
				if [[ $((base64found)) != 0 ]] && [[ $linebuf64 != "" ]]; then
					encoding=$(egrep -m 1 -e "^Content-Encoding:" <<< "$linebuf" 2>/dev/null)
					if [[ $linebuf != "" ]]; then
						lastline=$(tail -1 <<< "$linebuf")
						if [[ $lastline =~ ^\.\.\.\ unprintable ]]; then
							linebuf=$(head --lines=-1 <<< "$linebuf")
						fi
					fi
					tail -n +2 <<< "$linebuf" >> "$newfile"
					if [[ $encoding =~ gzip ]] && [[ $bGunzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | gunzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					elif [[ $encoding =~ gzip ]] && [[ $bUnzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | unzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					else
						echo "$linebuf64" | base64 -d | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					fi
					base64msg=$((base64msg+1))
					base64found=0; 	linebuf64=""
				else
					tail -n +2 <<< "$linebuf" >> "$newfile"
				fi
				echo -e "$NL[$sipstream] }\x0d$NL" >> "$newfile";;
			2)	echo -e "[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
				echo -e "$NL$lineX" >> "$newfile"
				if [[ $((base64found)) != 0 ]] && [[ $linebuf64 != "" ]]; then
					encoding=$(egrep -m 1 -e "^Content-Encoding:" <<< "$linebuf" 2>/dev/null)
					if [[ $linebuf != "" ]]; then
						lastline=$(tail -1 <<< "$linebuf")
						if [[ $lastline =~ ^\.\.\.\ unprintable ]]; then
							linebuf=$(head --lines=-1 <<< "$linebuf")
						fi
					fi
					tail -n +2 <<< "$linebuf" >> "$newfile"
					if [[ $encoding =~ gzip ]] && [[ $bGunzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | gunzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					elif [[ $encoding =~ gzip ]] && [[ $bUnzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | unzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					else
						echo "$linebuf64" | base64 -d | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					fi
					base64msg=$((base64msg+1))
					base64found=0; 	linebuf64=""
				else
					tail -n +2 <<< "$linebuf" >> "$newfile"
				fi
				echo -e "$NL}$NL"       >> "$newfile";;
			3)	if [[ ! $sipword =~ PONG ]] || [[ $siplength != 4 ]]; then
					echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
					echo -e "$lineX" >> "$newfile"	
					if [[ $((base64found)) != 0 ]] && [[ $linebuf64 != "" ]]; then
						encoding=$(egrep -m 1 -e "^Content-Encoding:" <<< "$linebuf" 2>/dev/null)
						if [[ $linebuf != "" ]]; then
							lastline=$(tail -1 <<< "$linebuf")
							if [[ $lastline =~ ^\.\.\.\ unprintable ]]; then
								linebuf=$(head --lines=-1 <<< "$linebuf")
							fi
						fi
						tail -n +2 <<< "$linebuf" >> "$newfile"
						if [[ $encoding =~ gzip ]] && [[ $bGunzip != 0 ]]; then
							sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | gunzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
						elif [[ $encoding =~ gzip ]] && [[ $bUnzip != 0 ]]; then
							sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | unzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
						else
							echo "$linebuf64" | base64 -d | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
						fi
						base64msg=$((base64msg+1))
						base64found=0; 	linebuf64=""
					else
						tail -n +2 <<< "$linebuf" >> "$newfile"
					fi
					echo -e "--------------------" >> "$newfile"
				elif [[ $dirdefined == 1 ]]; then
					echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}octets: $siplength, Body Length: 0${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}SIPMsgContext: [NONE]${NL}--------------------" >> "$newfile"
					echo "${NL}${NL}" >> "$newfile"
				else
					echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}octets: $siplength, Body Length: 0${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}SIPMsgContext: [NONE]${NL}--------------------" >> "$newfile"
					echo "${NL}" >> "$newfile"
				fi;;
			esac
		fi
	
		if [[ $foundipaddr != "" ]]; then
			lastfoundip="$foundipaddr"
		elif [[ $dirdefined == 2 ]]; then
			contacthdr=""; contactip=""
			contacthdr=$(egrep -m 1 -e "^Contact:" <<< "$linebuf" 2>/dev/null)
			if [[ $contacthdr != "" ]]; then
				contactip=$(cut -d '@' -f2 <<< "$contacthdr" | cut -d ';' -f1)
				if [[ $contactip != "" ]] && [[ ! $contactip =~ 127\.0 ]]; then
					lastfoundip="$contactip"
				fi
			fi
		fi

		get_useragent4

		if [[ $((badmsg)) != 0 ]]; then
			echo -e "# This is a BAD message\n" >> "$newfile"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
		fi
    	reset_sipmsg

	else															# cannot complete a SIP message unless it started properly
		badmsg=1; sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadmsgnum == "" ]]; then
			sipbadmsgnum="$siptotalmsg $siptime"
		fi
	fi	
elif [[ $bDebug == 0 ]]; then
	echo -e "\nALERT: complete_sipmsg() was called with \$sipstart=0 at msgno: $sipmsg at $sipdate $siptime. Contact developer."
	exit 1
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
				echo -en "$var => $n/$rec Msgs converted                 \r"
			fi
		fi
	fi
elif [[ $bDebug == 0 ]]; then
	echo -e "error: sipmsg_header() was called with \$dirdefined=0 at msgno: $sipmsg at $sipdate $siptime. Contact developer.\n"
	exit 1	
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
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line == *" : RECEIVED"* ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line == *"[SIP]:SENDING"* ]]; then
		sipstream=1474; 			dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--";		dirstring2="egress";;
		esac

	elif [[ $line == *" : SENDING"* ]]; then
		sipstream=1474; 			dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--";		dirstring2="egress";;
		esac

	elif [[ $line == *"Inbound SIP"* ]] || [[ $line == *" <- "* ]] || [[ $line =~ ^RX\  ]] || [[ $line =~ RECEIVED ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1)	dirstring1="RECEIVED"; 	dirstring2="from";;
		2)	dirstring1="RECEIVED"; 	dirstring2="from";;
		3)	dirstring1="-->"; 	 	dirstring2="ingress";;
		esac

	elif [[ $line == *"Outbound SIP"* ]] || [[ $line == *" -> "* ]] || [[ $line =~ ^TX\  ]] || [[ $line =~ SENT|SENDING ]]; then
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

		case $vsyslog in
		10) if [[ $foundipaddr == "" ]]; then
				foundipaddr=$(awk '{print $4}' <<< "$line")
			fi
#	 		ip=$(cut -d' ' -f20 <<< "$line")
#			siplength=$(cut -d' ' -f17 <<< "$line")
	 		ip=$(awk '{print $19}'        <<< "$line" | tr -d '\n')
			siplength=$(awk '{print $16}' <<< "$line" | tr -d '\n');;
		11)
#		 	ip=$(cut -d' ' -f16 <<< "$line")
#			siplength=$(cut -d' ' -f13 <<< "$line")
		 	ip=$(awk '{print $16'}        <<< "$line" | tr -d '\n')
			siplength=$(awk '{print $13'} <<< "$line" | tr -d '\n');;
		12)
		 	ip=$(awk '{print $11'}        <<< "$line" | tr -d '\n')
			siplength=$(awk '{print $8'} <<< "$line"  | tr -d '\n');;
		13)
		 	ip=$(awk '{print $12'}        <<< "$line" | tr -d '\n')
			siplength=$(awk '{print $9'} <<< "$line"  | tr -d '\n');;

		2|175)
			if [[ $foundipaddr == "" ]] && [[ $vsyslog == 175 ]]; then
				foundipaddr=$(awk '{print $4}' <<< "$line")
			fi
			if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$line")				# cut -d' ' -f3  | tr -d "\n")
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")	#cut -d':' -f2  | tr -d "\n")
			fi
			ip=$ip1:$ip2;;
		20)
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
			fi;;
		211) ip=$(awk '{print $8}' <<< "$line" | sed -e 's/\.$//g')					# cut -d' ' -f10)
			 siplength=$(awk '{printf "%i",$NF}' <<< "$line")		
			 ip1=$(cut -d':' -f1 <<< "$ip")
			 ip2=$(cut -d':' -f2 <<< "$ip" | cut -d'.' -f1)			
			 ip=$ip1:$ip2;;
		212) ip=$(awk '{print $7}' <<< "$line" | sed -e 's/\.$//g')					# cut -d' ' -f10)
			 siplength=$(awk '{printf "%i",$4}' <<< "$line")
			 ip1=$(cut -d':' -f1 <<< "$ip")
			 ip2=$(cut -d':' -f2 <<< "$ip" | cut -d'.' -f1)			
			 ip=$ip1:$ip2;;
		esac
	fi
elif [[ $bDebug == 0 ]]; then
	echo -e "error: sip_direction() was called with dirdefined=$dirdefined. Contact developer.\n"
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

function get_useragent4 () {
	case $dirdefined in
	1) 	if [[ $scua == "" ]] && [[ $sipword == "INFO" ]]; then
			scip=""; sccontact=""
			scua=$(egrep -m 1 "^User-Agent" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
			if [[ $scua != "" ]]; then
				sccontact=$(egrep -m 1 "^Contact:" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
				if [[ $sccontact != "" ]]; then
					scip=$(awk -F "Contact:" '{print $2}' <<< "$sccontact"| cut -d ';' -f1 | cut -d '@' -f2)
				fi
			fi
		fi
		serverua=$(egrep -m 1 -e "^Server:" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
		if [[ $serverua != "" ]]; then
#			serverua=$(awk -F'Server: ' '{print $2}' <<< "$serverua" | tr -d "\r\n")
			if [[ ! $serverua =~ Presence ]]; then
				if [[ $server == "" ]]; then
					server="$serverua"; serverip="$ip"
				elif [[ ${#serverua} -gt ${#server} ]]; then
					server="$serverua"; serverip="$ip"
				fi
			fi
		fi;;
	2)	if [[ $useragent == "" ]]; then
			useragent=$(egrep -m 1 "^User-Agent" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
#			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$useragent"  | tr -d "\r\n")
		fi;;
	esac
} # get_useragent4()

function get_sip_datetime () {
	if [[ $line != "" ]]; then
		siptmp=""
		case $vsyslog in
		10)	if [[ $((n)) == 0 ]]; then								# native vantage.log
				foundipaddr=$(awk '{print $5}' <<< "$line")				# cut -d' ' -f5)
				sipyear=$(awk '{print $8}' <<< "$line")					# cut -d' ' -f8)
				sipday=$(awk '{printf "%02i",$2}' <<< "$line")
				month=$(cut -d' ' -f1 <<< "$line")
				get_sipmonth
			fi

			sipmsec=$(awk '{print $13}' <<< "$line") # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

			siphour=$(cut -d':' -f1 <<< "$sipmsec")
			sipmin=$(cut -d':' -f2  <<< "$sipmsec")
			sipsec=$(cut -d':' -f3  <<< "$sipmsec")
			sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
			sipsec=$(cut -d'.' -f1  <<< "$sipsec");;

#			siptime=$(echo $line | awk '{print $3":"$8}')  # msec included in $8
####		siptmp=$(echo $line | awk '{print $6}')
####		tzhour=$(echo $siptmp |cut -d':' -f 1) # awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
####		tzmin=$(echo $siptmp | cut -d':' -f 2) # awk -F ':' '{print $2}')

		11)											 				# syslog UDP stream converted
# 10.16.4.24 ANDROID: +03:00 2020 000 0 | 06-19 12:39:08.793 D/DeskPhoneServiceAdaptor( 3111): [SIP]:SENDING 1425 bytes to 10.16.26.183:5061 {	
			foundipaddr=$(cut -d' ' -f1 <<< "$line")
			sipyear=$(cut -d' ' -f4  <<< "$line")
			sipday=$(cut -d' ' -f8   <<< "$line" | cut -d'-' -f2)		# awk '{printf "%02i",$2}')
			sipmonth=$(cut -d' ' -f8 <<< "$line" | cut -d'-' -f1)		# awk '{printf "%02i",$2}')		
		
			sipmsec=$(cut -d' ' -f9 <<< "$line")						# awk '{print $9}') # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

			siphour=$(cut -d':' -f1 <<< "$sipmsec")
			sipmin=$(cut -d':' -f2  <<< "$sipmsec")
			sipsec=$(cut -d':' -f3  <<< "$sipmsec")
			sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
			sipsec=$(cut -d'.' -f1  <<< "$sipsec");;
		12)												 				# logcat Vantage r3.1
# 06-14 18:55:51.140  2037  2709 D DeskPhoneServiceAdaptor: [SIP]:SENDING 653 bytes to 198.152.85.104:5061 {
			if [[ $sipyear == "" ]]; then
				sipyear=$(cut -d'/' -f3 <<< "$today")
			fi
			sipday=$(cut -d' ' -f1  <<< "$line"  | cut -d'-' -f2)		# awk '{printf "%02i",$2}')
			sipmonth=$(cut -d' ' -f1 <<< "$line" | cut -d'-' -f1)		# awk '{printf "%02i",$2}')		

			sipmsec=$(cut -d' ' -f2 <<< "$line")			# awk '{print $9}') # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

			siphour=$(cut -d':' -f1 <<< "$sipmsec")
			sipmin=$(cut -d':' -f2  <<< "$sipmsec")
			sipsec=$(cut -d':' -f3  <<< "$sipmsec")
			sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
			sipsec=$(cut -d'.' -f1  <<< "$sipsec");;
		175)												  			# EndpointLog
# Jan  2 00:18:37 149.49.139.118 SIPMESSAGE: +01:00 1970 745 1 .TEL | 0 Outbound SIP message to 149.49.138.49:5061	
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
#			fi

			siphour=$(awk '{print $3}' <<< "$line")	
			sipmin=$(cut -d':' -f2     <<< "$siphour")	# awk -F ':' '{print $2}')
			sipsec=$(cut -d':' -f3     <<< "$siphour")	# awk -F ':' '{print $3}')
			siphour=$(cut -d':' -f1    <<< "$siphour")	# awk -F ':' '{print $1}')
			sipmsec=$(awk '{print $8}' <<< "$line")
			siptmp=$(awk '{print $6}'  <<< "$line");;
		2)													  			# KIWI syslog
			if [[ $((n)) == 0 ]]; then
				foundipaddr=$(awk '{print $5}' <<< "$line")
				sipyear=$(cut -d' ' -f1  <<< "$line" | awk -F '-' '{print $1}')
				sipmonth=$(cut -d' ' -f1 <<< "$line" | awk -F '-' '{print $2}')
				sipday=$(cut -d' ' -f1   <<< "$line" | awk -F '-' '{print $3}')			
			fi

		## endptaddr=$(echo $line | awk '{print $4}')
		## siplength=$(echo $line | awk '{print $13}')

##				xline=$(echo $line | awk -F '|' '{print $2}')
##				ip=$(echo $xline | awk '{print $(NF)}')
##				ip1=$(echo $ip | awk -F ":" '{print $1}')
##				ip2=$(echo $ip | awk -F ":" '{print $2}')
						
			siphour=$(awk '{print $7}'  <<< "$line")
			sipmsec=$(awk '{print $12}' <<< "$line")
			sipmin=$(cut -d':' -f2  <<< "$siphour") 				# awk -F ':' '{print $2}')
			sipsec=$(cut -d':' -f3  <<< "$siphour") 				# awk -F ':' '{print $3}')
			siphour=$(cut -d':' -f1 <<< "$siphour") 				# awk -F ':' '{print $1}')

			siptmp=$(awk '{print $10}' <<< "$line")
			tzhour=$(cut -d':' -f1 <<< "$siptmp") 				# awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
			tzmin=$(cut -d':' -f2  <<< "$siptmp");;				# awk -F ':' '{print $2}')
		## ip=$(echo $line | awk '{print $NF}')
		20) 														 ## KIWI syslog aka SyslogCatchAll
# 2022-02-11 17:33:11	Local4.Debug	135.105.129.244	Feb 11 16:33:09 135.105.129.244 SIPMESSAGE: +01:00 2022 653 1 .TEL | 0 [Part 01 of 02]<010>CSIPServer::SendToNetwork(): Outbound SIP message to 10.134.117.194:5061<010>TX 
# TODO: date format can depend on Windows / KIWI server locale
			foundipaddr=$(awk '{print $4}' <<< "$line")
#			if [[ $((n)) == 0 ]]; then
			sipyear=$(cut -d' ' -f1  <<< "$line")					#| cut -d'-' -f1)	# awk -F'-' '{print $1}')
			sipmonth=$(cut -d'-' -f2 <<< "$sipyear")						# awk -F'-' '{print $2}')			
			sipday=$(cut -d'-' -f3   <<< "$sipyear")						# awk -F'-' '{print $3}')			
			sipyear=$(cut -d'-' -f1  <<< "$sipyear")			
#			fi
		
			if [[ $localtime == 1 ]]; then
				siphour=$(awk '{print $2}' <<< "$line")
			else
				siphour=$(awk '{print $7}' <<< "$line")
			fi

#			siphour=$(awk -F ':' '{print $1}' <<< "$sipmec") 		# awk -F ':' '{print $1}')
#			siphour=$(cut -d':'-f1      <<< "$sipmec") 				# awk -F ':' '{print $1}')
			sipmin=$(cut -d':' -f2      <<< "$siphour") 			# awk -F ':' '{print $2}')
			sipsec=$(cut -d':' -f3      <<< "$siphour") 			# awk -F ':' '{print $3}')
			siphour=$(cut -d':' -f1     <<< "$siphour") 			# awk -F ':' '{print $1}')		
			sipmsec=$(awk '{print $12}' <<< "$line")
			siptmp=$(awk '{print $10}'  <<< "$line");;
		211) if [[ $line =~ DBH: ]] && [[ ${line:0:1} == '[' ]]; then												# 1XC
			    sipday=$(cut -d' ' -f1   <<< "$line" | cut -d'[' -f2)
				sipyear=$(cut -d'/' -f3  <<< "$sipday")
				sipmonth=$(cut -d'/' -f1 <<< "$sipday")
    			sipday=$(cut -d'/' -f2   <<< "$sipday")
									
				sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d']' -f1)
				siphour=$(cut -d':' -f1 <<< "$sipmsec")
				sipmin=$(cut -d':' -f2  <<< "$sipmsec")
				sipsec=$(cut -d':' -f3  <<< "$sipmsec")
				sipmsec=$(cut -d':' -f4 <<< "$sipmsec")
			fi;;
		212) if [[ $line =~ \]\ R|SE ]]; then																		# ACiOS
		    	sipday=$(cut -d' ' -f1   <<< "$line" | cut -d'[' -f2)
				sipyear=$(cut -d'/' -f1  <<< "$sipday")
				sipmonth=$(cut -d'/' -f2 <<< "$sipday")
	    		sipday=$(cut -d'/' -f3   <<< "$sipday")
									
				sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d']' -f1)
				siphour=$(cut -d':' -f1 <<< "$sipmsec")
				sipmin=$(cut -d':' -f2  <<< "$sipmsec")
				sipsec=$(cut -d':' -f3  <<< "$sipmsec")
				sipmsec=$(cut -d':' -f4 <<< "$sipmsec")				
		    fi;;
		esac

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
	elif [[ $bDebug == 0 ]]; then
		echo -e "error: get_sip_datetime(): EMPTY LINE! in $file at line#$nlines"
		echo -e "Contact developer.\n"
		exit 1
	fi
} # get_sip_datetime()

function reset_filters () {
	bAllINC=1; bEVX=0; bEVI=0

	noINFO=0; noOPTIONS=0; noUPDATE=0; noREG=0; noPONG=0
	noSUBSCRIBE=0; noPUBLISH=0; noNOTIFY=0
		
	bEvPresence=0;	bEvDialog=0; bEvCC=0
	bEvReg=0; bEvCMstat=0; bEvMsgSum=0
	bEvCCSprof=0; bEvRefer=0; bEvPush=0
	bEvScrUpd=0; bEvUAprof=0; bEvConf=0
} # reset_filters()

function explore_filters () {
if [[ $filterX != "" ]]; then
#	declare -A filtarr
	filt="";		evfilt=""
	oldIFS=$IFS; 	IFS=','
	bEVX=0; 		bEXC=0

	read -ra filtarr <<< "$filterX"
	for filt in "${filtarr[@]}"
	do
		if [[ $filt =~ ev:|EV:|Ev:|eV: ]]; then
			filt="${filt,,*}"																			# lowercase
#		else
#			filt="${filt^^*}"																			# uppercase
		fi
		if [[ $filt =~ ev: ]]; then
			case ${filt/ev:/} in
			all|any) 	bEVX=1; bEXC=1
						bEvPresence=1; bEvDialog=1; bEvReg=1; bEvMsgSum=1; bEvScrUpd=1; bEvUAprof=1; bEvConf=1
						bEvCC=1; bEvCCSprof=1; bEvCMstat=1; bEvRefer=1; bEvPush=1;;
			pres*)
				if [[ $bEvPresence == 2 ]]; then
					echo "error: ev:presence was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPresence == 1 ]]; then
					echo "warning: ev:presence was already specified by -X option."
				else
					bEvPresence=1; bEVX=1; bEXC=1
				fi;;
			dia*)
				if [[ $bEvDialog == 2 ]]; then
					echo "error: ev:dialog was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvDialog == 1 ]]; then
					echo "warning: ev:dialog was already specified by -X option."
				else
					bEvDialog=1; bEVX=1; bEXC=1
				fi;;
			reg)
				if [[ $bEvReg == 2 ]]; then
					echo "error: ev:cc-info was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvReg == 1 ]]; then
					echo "warning: ev:cc-info was already specified by -X option."
				else
					bEvReg=1; bEVX=1; bEXC=1
				fi;;
			mwi|message*)
				if [[ $bEvMsgSum == 2 ]]; then
					echo "error: ev:message-summary was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvMsgSun == 1 ]]; then
					echo "warning: ev:message-summary was already specified by -X option."
				else
					bEvMsgSum=1; bEVX=1; bEXC=1
				fi;;
			cc-info*|avaya-cm-cc-*)
				if [[ $bEvCC == 2 ]]; then
					echo "error: ev:cc-info was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCC == 1 ]]; then
					echo "warning: ev:cc-info was already specified by -X option."
				else
					bEvCC=1; bEVX=1; bEXC=1
				fi;;
			ccs|ccs-prof*|avaya-cm-ccs-prof*)
				if [[ $bEvCCSprof == 2 ]]; then
					echo "error: ev:ccs-prof was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCCSprof == 1 ]]; then
					echo "warning: ev:ccs-prof was already specified by -X option."
				else
					bEvCCSprof=1; bEVX=1; bEXC=1
				fi;;
			cm-feat|avaya-cm-feat)
				if [[ $bEvCMstat == 2 ]]; then
					echo "error: ev:cm-feature was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCMstat == 1 ]]; then
					echo "warning: ev:cm-feature was already specified by -X option."
				else
					bEvCMstat=1; bEVX=1; bEXC=1
				fi;;
			push*|avaya-push*)
				if [[ $bEvPush == 2 ]]; then
					echo "error: ev:push-notification was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPush == 1 ]]; then
					echo "warning: ev:push-notification was already specified by -X option."
				else
					bEvPush=1; bEVX=1; bEXC=1
				fi;;
			scr*|screen-update)
				if [[ $bEvScrUpd == 2 ]]; then
					echo "error: ev:screen-update was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvScrUpd == 1 ]]; then
					echo "warning: ev:screen-update was already specified by -X option."
				else
					bEvScrUpd=1; bEVX=1; bEXC=1
				fi;;
			ua*|ua-profile)
				if [[ $bEvUAprof == 2 ]]; then
					echo "error: ev:ua-profile was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvUAprof == 1 ]]; then
					echo "warning: ev:ua-profile was already specified by -X option."
				else
					bEvUAprof=1; bEVX=1; bEXC=1
				fi;;
			conf*)
				if [[ $bEvConf == 2 ]]; then
					echo "error: ev:conf was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvConf == 1 ]]; then
					echo "warning: ev:conf was already specified by -X option."
				else
					bEvConf=1; bEVX=1; bEXC=1
				fi;;				
			ref*)
				if [[ $bEvRefer == 2 ]]; then
					echo "error: ev:refer was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvRefer == 1 ]]; then
					echo "warning: ev:refer was already specified by -X option."
				else
					bEvRefer=1; bEVX=1; bEXC=1
				fi;;
			*)
				echo "Warning: \"ev:\" string in -X option includes an unrecognized value: $filt"
				echo "Supporting pres(ence), dia(log), cc-info, reg, message(-summary), ccs-prof(ile), cm-feat(ure-status), refer"
				echo "push(-notification), screen(-update), ua(-profile)";;
			esac

		else case ${filt^^*} in 
		INFO)
			if [[ $noINFO == 2 ]]; then
				echo "error: INFO was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noINFO == 1 ]]; then
				echo "warning: INFO was already specified by -X option."
			else
				noINFO=1; bEXC=1
			fi;;
		OPTIONS)
			if [[ $noOPTIONS == 2 ]]; then
				echo "error: INFO was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noOPTIONS == 1 ]]; then
				echo "warning: INFO was already specified by -X option."
			else
				noOPTIONS=1; bEXC=1
			fi;;
		SUB*)
			if [[ $noSUBSCRIBE == 2 ]]; then
				echo "error: SUBSCRIBE was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noSUBSCRIBE == 1 ]]; then
				echo "warning: SUBSCRIBE was already specified by -X option."
			else
				noSUBSCRIBE=1; bEXC=1
			fi;;
		PUB*)
			if [[ $noPUBLISH == 2 ]]; then
				echo "error: PUBLISH was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noPUBLISH == 1 ]]; then
				echo "warning: PUBLISH was already specified by -X option."
			else
				noPUBLISH=1; bEXC=1
			fi;;
		NOTIFY)
			if [[ $noNOTIFY == 2 ]]; then
				echo "error: NOTIFY was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noNOTIFY == 1 ]]; then
				echo "warning: NOTIFY was already specified by -X option."
			else
				noNOTIFY=1; bEXC=1
			fi;;
		UPDATE)
			if [[ $noUPDATE == 2 ]]; then
				echo "error: UPDATE was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noUPDATE == 1 ]]; then
				echo "warning: UPDATE was already specified by -X option."
			else
				noUPDATE=1; bEXC=1
			fi;;
		PONG)
			if [[ $noPONG == 2 ]]; then
				echo "error: UPDATE was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noPONG == 1 ]]; then
				echo "warning: UPDATE was already specified by -X option."
			else
				noPONG=1; bEXC=1
			fi;;
		REG*)
			if [[ $noREG == 2 ]]; then
				echo "error: REGISTER was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noREG == 1 ]]; then
				echo "warning: REGISTER was already specified by -X option."
			else
				noREG=1; bEXC=1
			fi;;
		*)
			echo "Warning: -X option includes unrecognized value(s): $filt"
			echo "Supported strings are INFO, OPTIONS, NOTIFY, PUBLISH, REG(ISTER), SUB(SCRIBE), UPDATE.";;	
		esac
		fi
	done
	IFS=$oldIFS; filterX=""
fi

if [[ $filterI != "" ]]; then
#	declare -A filtarr
	if [[ $filterI =~ only: ]]; then
		bAllINC=0
		filterI="${filterI/only:/}"
	elif [[ $filterI =~ ONLY: ]]; then
		bAllINC=0
		filterI="${filterI/ONLY:/}"
	fi

	filt=""; 		evfilt="";
	bEVI=0; 		bINC=0
	oldIFS=$IFS; 	IFS=','

	read -ra filtarr <<< "$filterI"
	for filt in "${filtarr[@]}"
	do
		if [[ $filt =~ ev:|EV:|Ev:|eV: ]]; then
			filt="${filt,,*}"
#		else
#			filt="${filt^^*}"
		fi
		if [[ $filt =~ ev: ]]; then
			case ${filt/ev:/} in
			all|any)	bEVI=1; bINC=1
						bEvPresence=2; bEvDialog=2; bEvReg=2; bEvMsgSum=2; bEvScrUpd=2; bEvUAprof=2; bEvConf=2
						bEvCC=2; bEvCCSprof=2; bEvCMstat=2; bEvRefer=2; bEvPush=2;;
			pres*)
				if [[ $bEvPresence == 1 ]]; then
					echo "error: ev:presence was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPresence == 2 ]]; then
					echo "warning: ev:presence was already specified by -I option."
				else
					bEvPresence=2; bEVI=1; bINC=1
				fi;;
			dia*)
				if [[ $bEvDialog == 1 ]]; then
					echo "error: ev:dialog was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvDialog == 2 ]]; then
					echo "warning: ev:dialog was already specified by -I option."
				else
					bEvDialog=2; bEVI=1; bINC=1
				fi;;
			reg)
				if [[ $bEvReg == 1 ]]; then
					echo "error: ev:cc-info was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvReg == 2 ]]; then
					echo "warning: ev:cc-info was already specified by -I option."
				else
					bEvReg=2; bEVI=1; bINC=1
				fi;;
			message*)
				if [[ $bEvMsgSum == 1 ]]; then
					echo "error: ev:message-summary was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvMsgSun == 2 ]]; then
					echo "warning: ev:message-summary was already specified by -I option."
				else
					bEvMsgSum=2; bEVI=1; bINC=1
				fi;;
			cc-info*|avaya-cm-cc-*)
				if [[ $bEvCC == 1 ]]; then
					echo "error: ev:cc-info was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCC == 2 ]]; then
					echo "warning: ev:cc-info was already specified by -I option."
				else
					bEvCC=2; bEVI=1; bINC=1
				fi;;
			ccs*|avaya-cm-ccs*)
				if [[ $bEvCCSprof == 1 ]]; then
					echo "error: ev:ccs-prof was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCCSProf == 2 ]]; then
					echo "warning: ev:ccs-prof was already specified by -I option."
				else
					bEvCCSprof=2; bEVI=1; bINC=1
				fi;;
			cm-feat*|avaya-cm-feat*)
				if [[ $bEvCMstat == 1 ]]; then
					echo "error: ev:cm-feature was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCMstat == 2 ]]; then
					echo "warning: ev:cm-feature was already specified by -I option."
				else
					bEvCMstat=2; bEVI=1; bINC=1
				fi;;
			push*|avaya-push*)
				if [[ $bEvPush == 1 ]]; then
					echo "error: ev:push-notification was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPush == 2 ]]; then
					echo "warning: ev:push-notification was already specified by -I option."
				else
					bEvPush=2; bEVI=1; bINC=1
				fi;;
			scr*|screen-update)
				if [[ $bEvScrUpd == 1 ]]; then
					echo "error: ev:screen-update was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvScrUpd == 2 ]]; then
					echo "warning: ev:screen-update was already specified by -I option."
				else
					bEvScrUpd=2; bEVI=1; bINC=1
				fi;;
			ua*|ua-profile)
				if [[ $bEvUAprof == 1 ]]; then
					echo "error: ev:ua-profile was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvUAprof == 2 ]]; then
					echo "warning: ev:ua-profile was already specified by -I option."
				else
					bEvUAprof=2; bEVI=1; bINC=1
				fi;;
			conf*)
				if [[ $bEvConf == 1 ]]; then
					echo "error: ev:conf was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvConf == 2 ]]; then
					echo "warning: ev:conf was already specified by -I option."
				else
					bEvConf=2; bEVI=1; bINC=1
				fi;;				
			ref*)
				if [[ $bEvRefer == 1 ]]; then
					echo "error: ev:refer was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvRefer == 2 ]]; then
					echo "warning: ev:refer was already specified by -I option."
				else
					bEvRefer=2; bEVI=1; bINC=1
				fi;;
			*)	
				echo "Warning: \"ev:\" string in -I option includes unrecognized value(s): $filt"
				echo "Supporting pres(ence), dia(log), cc-info, reg, message(-summary), ccs-prof(ile), cm-feat(ure-status), refer"
				echo "push(-notification), screen(-update), ua(-profile)";;
			esac

		else case ${filt^^*} in 
		INFO)
			if [[ $noINFO == 1 ]]; then
				echo "error: INFO was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noINFO == 2 ]]; then
				echo "warning: INFO was already specified by -I option."
			else
				noINFO=2; bINC=1
			fi;;
		OPTIONS)
			if [[ $noOPTIONS == 1 ]]; then
				echo "error: INFO was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noOPTIONS == 2 ]]; then
				echo "warning: INFO was already specified by -I option."
			else
				noOPTIONS=2; bINC=1
			fi;;
		SUB*)
			if [[ $noSUBSCRIBE == 1 ]]; then
				echo "error: SUBSCRIBE was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noSUBSCRIBE == 2 ]]; then
				echo "warning: SUBSCRIBE was already specified by -I option."
			else
				noSUBSCRIBE=2; bINC=1
			fi;;
		PUB*)
			if [[ $noPUBLISH == 1 ]]; then
				echo "error: PUBLISH was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noPUBLISH == 2 ]]; then
				echo "warning: PUBLISH was already specified by -I option."
			else
				noPUBLISH=2; bINC=1
			fi;;
		NOTIFY)
			if [[ $noNOTIFY == 1 ]]; then
				echo "error: NOTIFY was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noNOTIFY == 2 ]]; then
				echo "warning: NOTIFY was already specified by -I option."
			else
				noNOTIFY=2; bINC=1
			fi;;
		UPDATE)
			if [[ $noUPDATE == 1 ]]; then
				echo "error: UPDATE was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noUPDATE == 2 ]]; then
				echo "warning: UPDATE was already specified by -I option."
			else
				noUPDATE=2; bINC=1
			fi;;
		PONG)
			if [[ $noPONG == 1 ]]; then
				echo "error: UPDATE was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noPONG == 2 ]]; then
				echo "warning: UPDATE was already specified by -I option."
			else
				noPONG=2; bINC=1
			fi;;
		REG*)
			if [[ $noREG == 1 ]]; then
				echo "error: REGISTER was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noREG == 2 ]]; then
				echo "warning: REGISTER was already specified by -I option."
			else
				noREG=2; bINC=1
			fi;;
		*)
			echo "Warning: -X option includes unrecognized value(s): $filt"
			echo "Supported strings are INFO, OPTIONS, NOTIFY, PUBLISH, REG(ISTER), SUB(SCRIBE), UPDATE.";;	
		esac
		fi
	done
	IFS=$oldIFS; filterI=""
fi
} # explore_filters()

function validate_sipmsg () {
	let ncseq=0
	let nrseq=0
	ncseq=$(egrep -ce "^CSeq:"    <<< "$linebuf" 2>/dev/null)
	nrseq=$(egrep -ce "^RSeq:"    <<< "$linebuf" 2>/dev/null)

	if [[ $((ncseq)) == 0 ]] || [[ $cseqline == "" ]]; then
		if [[ $siplength != 4 ]]; then
			passed=0; sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadtimemsg == "" ]]; then
				sipbadtimemsg="$siptime"
			fi
			echo -e "\nALERT: Found a SIP message without a CSeq: header - $sipword in msgno#$sipmsg at $siptime. Contact developer.\n"
			echo $linebuf
		fi

	elif [[ $((ncseq)) -gt 1 ]]; then
		passed=0; sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadtimemsg == "" ]]; then
			sipbadtimemsg="$siptime"
		fi
		echo -e "\nALERT: Found a SIP message with multiple CSeq: headers ($ncseq) - $sipword in msgno#$sipmsg  at $siptime. Contact developer.\n"

#	elif [[ $prevsipword == $sipword ]] && [[ $prevcseq == $currcseq ]]; then
#		if [[ $ip == $previp ]] && [[ $localip == $prevlocalip ]]; then
#			passed=0
#			echo -e "\nALERT: Found duplicate SIP message (two SIP requests with same CSeq:) - $sipword : $cseqline in msgno#$sipmsg at $siptime. Contact developer.\n"
#		fi

	elif [[ ${#cseqword} -lt 3 ]]; then						 # SIP msg without CSeq: is considered invalid
		passed=0; sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadtimemsg == "" ]]; then
			sipbadtimemsg="$siptime"
		fi
		echo -e "\nALERT: Found a SIP message with an invalid CSeq: header - $sipword : $cseqline in msgno#$sipmsg at $siptime. Contact developer.\n"

	elif [[ $((nrseq)) != 0 ]]; then
		if [[ $((nrseq)) != 1 ]]; then
			passed=0; sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadtimemsg == "" ]]; then
				sipbadtimemsg="$siptime"
			fi
			echo -e "\nALERT: Found a SIP message with multiple RSeq: headers - $sipword in msgno#$sipmsgat $siptime. Contact developer.\n"
		else
# TODO: validate RSeq counter and/or seq# number and string		
			rseqline=""; rseqline=$(egrep -m 1 -e "^RSeq:"  <<< "$linebuf" 2>/dev/null | tr -d '\r')
#			rseqword=""; rseqword=$(cut -d' ' -f3 <<< "$rseqline" | tr -d '\r') # ; rseqword=${rseqword//'\r\n'$//}			
			rseq=0; rseq=$(awk '{print $2}' <<< "$rseqline")
			if [[ $((rseq)) -lt 1 ]]; then
				passed=0; sipbadmsg=$((sipbadmsg+1))
				if [[ $sipbadtimemsg == "" ]]; then
					sipbadtimemsg="$siptime"
				fi
				echo -e "\nALERT: Found a SIP message with an invalid RSeq: header - $sipword : $rseqline at $siptime. Contact developer.\n"
			fi
		fi

	elif [[ ! $sipword =~ ^[A-Z]+|^[1-7][0-9][0-9]\ |^SIP\/2.0\  ]]; then					# invalid $sipword
		passed=0;sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadtimemsg == "" ]]; then
			sipbadtimemsg="$siptime"
		fi
		echo -e "\nALERT: Found a SIP msg with an unknown or invalid SIP request - $sipword in msgno#$sipmsg at $siptime. Contact developer.\n"

	elif [[ $filtdate != "" ]]; then
		if [[ ! $sipday =~ ${filtdate:2:2} ]]; then
			passed=0
		elif [[ ! $sipmonth =~ ${filtdate:0:2} ]]; then
			passed=0
		fi
	fi

	if [[ $passed != 0 ]] && [[ $userext != "" ]]; then
		fromhdr=""; tohdr="";
		fromhdr=$(egrep -m 1 "^From:" <<< "$linebuf" 2>/dev/null)
		tohdr=$(egrep -m 1 "^To:" <<< "$linebuf" 2>/dev/null)
		if [[ ! $fromhdr =~ $userext ]] && [[ ! $tohdr =~ $userext ]]; then
			passed=0
		fi
	fi
} # validate_sipmsg()

function ignore_sipmsg () {
	notpassed=$((notpassed+1))
	case $dirdefined in
	1) notpassedin=$((notpassedin+1));;
	2) notpassedout=$((notpassedout+1));;
	esac		

	if [[ $sipword == "INFO" ]]; then
		nINFO=$((nINFO+1))
		case $dirdefined in
		1) infoin=$((infoin+1));;
		2) infoout=$((infoout+1));;
		esac
	fi

	echo "# msgno: $siptotalmsg (not passed) - $sipdate $siptime $dirstring1 $dirstring2 $ip" >> "$newfile"
	if [[ $eventstr == "" ]]; then
		echo -e "# $(head -1 <<< "$linebuf" | tr -d '\r') / $cseqline\n" >> "$newfile"		
	else
		echo -e "# $(head -1 <<< "$linebuf" | tr -d '\r') / $cseqline / $eventstr\n" >> "$newfile"
	fi

	reset_sipmsg
	currcseq=0; cseqword=""	
} # ignore_sipmsg()

function explore_sipmsg () {
if [[ $linebuf != "" ]]	; then
	passed=1
	currcseq=0; cseqline="";	cseqword=""

#	linebkup="$line"																			# last line of the SIP msg
	linebuf=$(sed 's/\\r\\n/\n/g' <<< "$linebuf")
	cseqline=$(egrep -m 1 -e "^CSeq:"  <<< "$linebuf" 2>/dev/null | tr -d '\r')
#	cseqline=$(egrep -m 1 -e "^CSeq:"  <<< "$linebuf" 2>/dev/null); cseqline=${cseqline//'\r\n$'/}
	currcseq=$(cut -d' ' -f2 <<< "$cseqline")
	cseqword=$(cut -d' ' -f3 <<< "$cseqline" | tr -d '\r') # ; cseqword=${cseqword//'\r\n'$//}
#	cseqword=$(awk '{print $3}' <<< "$cseqline" | tr -d [:cntrl:])

	validate_sipmsg

	if [[ $passed == 0 ]]; then
		ignore_sipmsg

	elif [[ $bINC != 0 ]] || [[ $bEXC != 0 ]]; then
		ipassed=0; xpassed=1; match=0; eventstr=""
		evcheck=0; evseqcheck=0; evtype=0; evmatch=0

		if [[ $passed != 0 ]]; then
			case $sipword in
			INFO)		if [[ $noINFO == 1 ]]; 		then match=1; xpassed=0;	elif [[ $noINFO == 2 ]];	then match=1; ipassed=1; fi;;
			OPTIONS)	if [[ $noOPTIONS == 1 ]];	then match=1; xpassed=0;	elif [[ $noOPTIONS == 2 ]]; then match=1; ipassed=1; fi;;
			REGISTER)	if [[ $noREG == 1 ]];		then match=1; xpassed=0;	elif [[ $noREG == 2 ]];		then match=1; ipassed=1; fi;;
			UPDATE)		if [[ $noUPDATE == 1 ]];	then match=1; xpassed=0;	elif [[ $noUPDATE == 2 ]];	then match=1; ipassed=1; fi;;
			PONG)		if [[ $noPONG == 1 ]];		then match=1; xpassed=0;	elif [[ $noPONG == 2 ]];	then match=1; ipassed=1; fi;;
			SUBSCRIBE)	if [[ $noSUBSCRIBE == 1 ]]; then match=1; xpassed=0;	elif [[ $noSUBSCRIBE == 2 ]]; then match=1; ipassed=1; fi
						if [[ $bEVI == 1 ]]; 		then evcheck=2; evtype=1;	elif [[ $bEVX == 1 ]];		then evcheck=1; evtype=1; fi;;
			PUBLISH)	if [[ $noPUBLISH == 1 ]];	then match=1; xpassed=0;	elif [[ $noPUBLISH == 2 ]]; then match=1; ipassed=1; fi
						if [[ $bEVI == 1 ]];		then evcheck=2; evtype=2;	elif [[ $bEVX == 1 ]]; 		then evcheck=1; evtype=2; fi;;
			NOTIFY)		if [[ $noNOTIFY == 1 ]]; 	then match=1; xpassed=0;	elif [[ $noNOTIFY == 2 ]];	then match=1; ipassed=1; fi
						if [[ $bEVI == 1 ]]; 		then evcheck=2; evtype=3;	elif [[ $bEVX == 1 ]]; 		then evcheck=1; evtype=3; fi
#			*)			if [[ $bINC != 0 ]] && [[ $bAllINC == 1 ]]; then ipassed=1; fi;;
			esac
			if [[ $match == 0 ]] && [[ $evtype == 0 ]]; then
				case $cseqword in
				INFO)		if [[ $noINFO == 1 ]]; 		then match=1; xpassed=0; 	elif [[ $noINFO == 2 ]];	then match=1; ipassed=1; fi;;
				OPTIONS)	if [[ $noOPTIONS == 1 ]];	then match=1; xpassed=0; 	elif [[ $noOPTIONS == 2 ]]; then match=1; ipassed=1; fi;;
				REGISTER)	if [[ $noREG == 1 ]];		then match=1; xpassed=0; 	elif [[ $noREG == 2 ]];		then match=1; ipassed=1; fi;;
				UPDATE)		if [[ $noUPDATE == 1 ]];	then match=1; xpassed=0; 	elif [[ $noUPDATE == 2 ]];	then match=1; ipassed=1; fi;;
				PONG)		if [[ $noPONG == 1 ]];		then match=1; xpassed=0; 	elif [[ $noPONG == 2 ]];	then match=1; ipassed=1; fi;;			
				SUBSCRIBE)	if [[ $noSUBSCRIBE == 1 ]]; then match=1; xpassed=0; 	elif [[ $noSUBSCRIBE == 2 ]]; then match=1; ipassed=1; fi
							if [[ $bEVI == 1 ]]; 		then evseqcheck=2; evtype=1; elif [[ $bEVX == 1 ]]; 	then evseqcheck=1; evtype=1; fi;;
				PUBLISH)	if [[ $noPUBLISH == 1 ]];	then match=1; xpassed=0; 	elif [[ $noPUBLISH == 2 ]]; then match=1; ipassed=1; fi
							if [[ $bEVI == 1 ]]; 		then evseqcheck=2; evtype=2; elif [[ $bEVX == 1 ]]; 	then evseqcheck=1; evtype=2; fi;;
				NOTIFY)		if [[ $noNOTIFY == 1 ]];	then match=1; xpassed=0; 	elif [[ $noNOTIFY == 2 ]];	then match=1; ipassed=1; fi
							if [[ $bEVI == 1 ]]; 		then evseqcheck=2; evtype=3; elif [[ $bEVX == 1 ]]; 	then evseqcheck=1; evtype=3; fi
#				*)			if [[ $bINC != 0 ]] && [[ $bAllINC == 1 ]]; then ipassed=1; fi;;
				esac
			fi
		fi

		case $noPONG in
		1)  siplines=$(wc -l <<< "$linebuf")
			if [[ $((siplines)) -lt 2 ]] || [[ $((siplength)) -le 4 ]]; then
				passed=0
			fi;;
		2)  if [[ $bAllINC != 0 ]]; then
				siplines=$(wc -l <<< "$linebuf")
				if [[ $((siplines)) -gt 2 ]] || [[ $((siplength)) -gt 4 ]]; then
					passed=0
				fi
			fi;;
		esac

		if [[ $passed != 0 ]] && [[ $evcheck != 0 ]]; then
			eventstr=$(egrep -m 1 -e "^Event:" <<< "$linebuf" | tr -d '\r')
			case ${eventstr/Event: /} in 
			dialog)
				if [[ $bEvDialog != 0 ]];	then evmatch=$bEvDialog; fi;;
			avaya-cm-cc-info)
				if [[ $bEvCC != 0 ]]; 		then evmatch=$bEvCC; fi;;
			reg)
				if [[ $bEvReg != 0 ]];		then evmatch=$bEvReg; fi;;
			avaya-cm-feature*)
				if [[ $bEvCMstat != 0 ]];	then evmatch=$bEvCMstat; fi;;
			message*)
				if [[ $bEvMsgSum != 0 ]];	then evmatch=$bEvMsgSum; fi;;
			avaya-ccs*)
				if [[ $bEvCCSprof != 0 ]];	then evmatch=$bEvCCSprof; fi;;
			presence*)
				if [[ $bEvPresence != 0 ]]; then evmatch=$bEvPresence; fi;;
			refer)
				if [[ $bEvRefer != 0 ]];	then evmatch=$bEvRefer; fi;;
			screen-update)
				if [[ $bEvScrUpd != 0 ]];	then evmatch=$bEvScrUpd; fi;;
			ua-profile*)
				if [[ $bEvUAprof != 0 ]];	then evmatch=$bEvUAprof; fi;;
			conf*)
				if [[ $bEvConf != 0 ]];		then evmatch=$bEvConf; fi;;				
			avaya-push*)
				if [[ $bEvPush != 0 ]];	    then evmatch=$bEvPush; fi;;
			*)  evunknown=$((evunknown+1))
				evstrings="$evstrings| ${eventstr/Event: }"
				if [[ $bDebug != 0 ]]; then
					echo "warning: found an unknown \"$eventstr\" in $sipword message in msgno#$sipmsg at $siptime - Contact developer."
				fi
				echo "# warning: found an unknown \"$eventstr\" in $sipword message in msgno#$sipmsg at $siptime - Contact developer." >> "$newfile";;
			esac
# echo -e "\nPH1:$siptime AllINC=$bAllINC EVI=$bEVI EVX=$bEVX INC=$bINC EXC=$bEXC - $sipword - $cseqline - $eventstr - $ipassed - $xpassed - $evcheck - $evseqcheck - $evtype evmatch=$evmatch"
# if [[ $sipword == "SUBSCRIBE" ]] || [[ $cseqword == "SUBSCRIBE" ]]; then
#	echo -e "\n$siptime EVI=$bEVI EVX=$bEVX - $sipword - $cseqword - $eventstr - $ipassed - $xpassed - $evcheck - $evseqcheck - $evtype evmatch=$evmatch"
# fi
			if [[ $evmatch == 1 ]]; then
				passed=0
#			if [[ $ipassed == 0 ]]; then			
				case $evtype in
				1)	if [[ $prevSUBseq1 != "" ]]; then
						if [[ $prevSUBseq2 != "" ]]; then
							if [[ $prevSUBseq3 != "" ]]; then
								if [[ $prevSUBseq4 != "" ]]; then
									echo -e "\n# SUBSCRIBE to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet!\n"	>> "$newfile"
									if [[ $bDebug != 0 ]]; then
										echo -e "\nSUBSCRIBE to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet! Contact developer.\n"
									fi
								fi
								prevSUBseq4="$cseqline"
								prevSUBcallid4=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
							else
								prevSUBseq3="$cseqline"
								prevSUBcallid3=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
							fi
						else
							prevSUBseq2="$cseqline"
							prevSUBcallid2=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
						fi
					else
						prevSUBseq1="$cseqline"
						prevSUBcallid1=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid1=${prevSUBcallid1//'\r\n$'//};;
					fi;;
				2)	if [[ $prevPUBseq != "" ]]; then
						echo -e "\n# PUBLISH to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet!\n" >> "$newfile"
						if [[ $bDebug != 0 ]]; then
							echo -e "\nPUBLISH to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet! Contact developer.\n"
						fi
					fi
					prevPUBseq="$cseqline"
					prevPUBcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevPUBcallid=${prevPUBcallid//'\r\n$'//};;
				3)	if [[ $prevNOTIFYseq != "" ]]; then
						echo -e "\n# NOTIFY to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet!\n" >> "$newfile"
						if [[ $bDebug != 0 ]]; then
							echo -e "\nNOTIFY to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet! Contact developer.\n"
						fi
					fi
					prevNOTIFYseq="$cseqline"
					prevNOTIFYcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevNOTIFYcallid=${prevNOTIFYcallid//'\r\n$'//};
				esac
 
			elif [[ $evmatch == 2 ]]; then
				passed=1
#				if [[ $xpassed == 0 ]] || [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
				if [[ $xpassed == 0 ]] || [[ $ipassed == 0 ]]; then				
# echo -e "\nPH2:$siptime AllINC=$bAllINC EVI=$bEVI EVX=$bEVX INC=$bINC EXC=$bEXC - $sipword - $cseqline - $eventstr - $ipassed - $xpassed - $evcheck - $evseqcheck - $evtype evmatch=$evmatch"			
					case $evtype in			
					1)	if [[ $prevSUBseq1 != "" ]]; then
							if [[ $prevSUBseq2 != "" ]]; then
								if [[ $prevSUBseq3 != "" ]]; then
									if [[ $prevSUBseq4 != "" ]]; then
										if [[ $xpassed == 0 ]]; then
											echo -e "\n# SUBSCRIBE msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet!\n" >> "$newfile"
											if [[ bDebug != 0 ]]; then
												echo -e "\nSUBSCRIBE msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet! Contact developer.\n"
											fi
										elif [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
											echo -e "\n# SUBSCRIBE msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet!\n" >> "$newfile"
											if [[ $bDebug != 0 ]]; then
												echo -e "\nSUBSCRIBE msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"prevSUBseq2\" has not been found yet! Contact developer.\n"
											fi
										fi
									fi
									prevSUBseq4="$cseqline"
									prevSUBcallid4=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
								else
									prevSUBseq3="$cseqline"
									prevSUBcallid3=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
								fi
							else
								prevSUBseq2="$cseqline"
								prevSUBcallid2=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
							fi
						else
							prevSUBseq1="$cseqline"
							prevSUBcallid1=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid1=${prevSUBcallid1//'\r\n$'//};;
						fi;;

					2)  if [[ $prevPUBseq != "" ]]; then
							if [[ $xpassed == 0 ]]; then				
								echo -e "\n# PUBLISH msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nPUBLISH msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet! Contact developer.\n"
								fi
							elif [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
								echo -e "\n# PUBLISH msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nPUBLISH msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet! Contact developer.\n"
								fi
							fi						
						fi	
						prevPUBseq="$cseqline"
						prevPUBcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevPUBcallid=${prevPUBcallid//'\r\n$'//};;

					3)	if [[ $prevNOTIFYseq != "" ]]; then
							if [[ $xpassed == 0 ]]; then				
								echo -e "\n# NOTIFY msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nNOTIFY msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet! Contact developer.\n"
								fi
							elif [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
								echo -e "\n# NOTIFY msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nNOTIFY msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet! Contact developer.\n"
								fi
							fi						
						fi
						prevNOTIFYseq="$cseqline"
						prevNOTIFYcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevNOTIFYcallid=${prevNOTIFYcallid//'\r\n$'//};
					esac

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi

			elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
				if [[ $ipassed == 0 ]]; then passed=0; fi

			elif [[ $match == 0 ]]; then
				if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
			fi

		elif [[ $passed != 0 ]] && [[ $evseqcheck != 0 ]]; then
			currcallid=$(egrep -m 1 -e "^Call-ID:" <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')  #; currcallid=${currcallid//'\r\n$'//}
			case $evtype in
			1)	subseqfound=0
				if [[ $prevSUBseq4 != "" ]]; then
					if [[ $cseqline == $prevSUBseq4 ]] && [[ $currcallid == $prevSUBcallid4 ]]; then
						prevSUBseq4=""; subseqfound=1
					fi
				fi
				if [[ $subseqfound == 0 ]] && [[ $prevSUBseq3 != "" ]]; then
					if [[ $cseqline == $prevSUBseq3 ]] && [[ $currcallid == $prevSUBcallid3 ]]; then
						prevSUBseq3=""; subseqfound=1
					fi
				fi
				if [[ $subseqfound == 0 ]] && [[ $prevSUBseq2 != "" ]]; then
					if [[ $cseqline == $prevSUBseq2 ]] && [[ $currcallid == $prevSUBcallid2 ]]; then
						prevSUBseq2=""; subseqfound=1
					fi
				fi		
				if [[ $subseqfound == 0 ]] && [[ $prevSUBseq1 != "" ]]; then
					if [[ $cseqline == $prevSUBseq1 ]] && [[ $currcallid == $prevSUBcallid1 ]]; then
						prevSUBseq1=""; subseqfound=1
					fi
				fi
				if [[ $subseqfound != 0 ]]; then
					if [[ $evseqcheck == 1 ]]; then passed=0; else passed=1; fi
#			else
#				echo -e "\n# SUBSCRIBE anomaly at $siptime: evtype=$evtype cseqword=$cseqword\n" >> "$newfile"			
#				if  [[ $bDebug != 0 ]]; then
#					echo -e "\nSUBSCRIBE anomaly at $siptime: evtype=$evtype cseqword=$cseqword. Contact developer.\n"
#				fi

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi;;

			2)	if [[ $prevPUBseq != "" ]]; then
					if [[ $cseqline == $prevPUBseq ]] && [[ $currcallid == $prevPUBcallid ]]; then
						prevPUBseq=""
						if [[ $evseqcheck == 1 ]]; then passed=0; else passed=1; fi
					elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
						if [[ $ipassed == 0 ]]; then passed=0; fi
					elif [[ $match == 0 ]]; then
						if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi					
					fi

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi;;
#			else
#				echo -e "\n# PUBLISH anomaly at $siptime: evtype=$evtype cseqword=$cseqword\n" >> "$newfile"			
#				if  [[ $bDebug != 0 ]]; then
#					echo -e "\nPUBLISH anomaly at $siptime: evtype=$evtype cseqword=$cseqword. Contact developer.\n"
#				fi
#			fi;;

			3) 	if [[ $prevNOTIFYseq != "" ]]; then
					if [[ $cseqline == $prevNOTIFYseq ]] && [[ $currcallid == $prevNOTIFYcallid ]]; then
						prevNOTIFYseq=""
						if [[ $evseqcheck == 1 ]]; then passed=0; else passed=1; fi
					elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
						if [[ $ipassed == 0 ]]; then passed=0; fi
					elif [[ $match == 0 ]]; then
						if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi					
					fi

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi;;
#			else
#				echo -e "\n# NOTIFY anomaly at $siptime: evtype=$evtype cseqword=$cseqword\n" >> "$newfile"			
#				if  [[ $bDebug != 0 ]]; then
#					echo -e "\nNOTIFY anomaly at $siptime: evtype=$evtype cseqword=$cseqword. Contact developer.\n"
#				fi
#			fi;;
			esac

		elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
			if [[ $ipassed == 0 ]]; then passed=0; fi

		elif [[ $match == 0 ]]; then
			if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
		fi
# echo -e "Found $sipword passed=$passed xpassed=$xpassed ipassed=$ipassed evcheck=$evcheck evseqcheck=$evseqcheck evtype=$evtype EVI=$bEVI EVX=$bEVX\n"
	elif [[ $bDebug == 0 ]]; then
		if [[ $sipword =~ PUB|SUB|NOTIFY ]]; then
			eventstr=$(egrep -m 1 -e "^Event:" <<< "$linebuf" | tr -d '\r')
			eventstr=${eventstr/Event: /}
			case $eventstr in 
			dialog)
				if [[ $evdialog == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evdialog=$((evdialog+1));;
			avaya-cm-cc-info)
				if [[ $evccinfo == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evccinfo=$((evccinfo+1));;				
			reg)
				if [[ $evreg == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evreg=$((evreg+1));;
			avaya-cm-feature*)
				if [[ $evcmfeat == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evcmfeat=$((evcmfeat+1));;
			message*)
				if [[ $evmsgsum == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evmsgsum=$((evmsgsum+1));;
			avaya-ccs*)
				if [[ $evccs == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evccs=$((evccs+1));;
			presence*)
				if [[ $evpres == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evpres=$((evpres+1));;
			refer)
				if [[ $evrefer == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evrefer=$((evrefer+1));;
			screen*)
				if [[ $evscrupd == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evscrupd=$((evscrupd+1));;
			avaya-push*)
				if [[ $evpush == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evpush=$((evpush+1));;
			conf*)
				if [[ $evconf == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evconf=$((evconf+1));;
			ua*)
				if [[ $evuaprof == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evuaprof=$((evuaprof+1));;					
			*)	
				if [[ ! $evstrings =~ $eventstr ]]; then
					evstrings="$evstrings|UNKNOWN:$eventstr"
				fi
				evunknown=$((evunknown+1));;
			esac
		fi
	fi

# echo sipmonth=$sipmonth sipday=$sipday filtdate=$filtdate MO=${filtdate:2:2} DA=${filtdate:0:2}	

	if [[ $passed == 0 ]]; then
		ignore_sipmsg
	else
		if [[ $findANI != "" ]] && [[ $findCALLID != "" ]]; then
			callid=$(egrep -m 1 -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)
			if [[ $callid != "" ]] && [[ $callid =~ $findCALLID ]]; then
				linefrom=""; lineto=""
				linefrom=$(egrep -e "^From:" <<< "$linebuf" 2>/dev/null)
			
				if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
					callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
					callDIR=$dirdefined; calltime=$siptime
					if [[ $callidtime1 == "" ]]; then
						callidtime1=$siptime; callmsgnum1=$((sipmsg+1))
						callidword1=$sipword
					else
						callidtime2=$siptime; callmsgnum2=$((sipmsg+1))
						callidword2=$sipword
					fi
				else
					lineto=$(egrep -e "^To:" <<< "$linebuf" 2>/dev/null)
					if [[ $lineto != "" ]] && [[ $lineto =~ $findANI ]]; then
						callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
						callDIR=$dirdefined; calltime=$siptime
						if [[ $callidtime1 == "" ]]; then
							callidtime1=$siptime; callmsgnum1=$((sipmsg+1))
							callidword1=$sipword						
						else
							callidtime2=$siptime; callmsgnum2=$((sipmsg+1))
							callidword2=$sipword						
						fi
					fi
				fi
			fi
		else
			if [[ $findANI != "" ]] && [[ $sipword == "INVITE" ]]; then
				linefrom=""; lineto=""
				linefrom=$(egrep -e "^From:" <<< "$linebuf" 2>/dev/null)
			
				if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
					callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
					callDIR=$dirdefined; calltime=$siptime
				else
					lineto=$(egrep -e "^To:" <<< "$linebuf" 2>/dev/null)
					if [[ $lineto != "" ]] && [[ $lineto =~ $findANI ]]; then
						callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
						callDIR=$dirdefined; calltime=$siptime
					fi
				fi
			fi

			if [[ $findCALLID != "" ]]; then
				callid=$(egrep -m 1 -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)
				if [[ $callid != "" ]] && [[ $callid =~ $findCALLID ]]; then
					if [[ $callidtime1 == "" ]]; then
						callidtime1=$siptime; callmsgnum1=$((sipmsg+1))
						callidword1=$sipword
					else
						callidtime2=$siptime; callmsgnum2=$((sipmsg+1))
						callidword2=$sipword						
					fi
				fi
			fi
		fi

		if [[ $dirdefined == 1 ]] && [[ $sipword =~ PUBLISH|NOTIFY ]]; then				# incoming Presence payload is usually ugly
			if [[ $eventstr == "" ]]; then
				eventstr=$(egrep -m 1 -e "^Event:" <<< "$linebuf" | tr -d '\r')
			fi
			if [[ $eventstr =~ Presence ]]; then
				dummy=0
#				presence_beutify
			fi
		fi

		complete_sipmsg
	fi
fi
# set +x	
} # explore_sipmsg ()

function multi_sipmsg () {
	if [[ $bDebug == 0  ]]; then	
		echo -e "\n\ndebug: multiple SIP message at line#$nlines found at $siptime and notiref=$notifyrefer"
		echo line=$line	
	fi
	multimsg=$((multimsg+1))
	case $dirdefined in
	1)	multimsgin=$((multimsgin+1));;
	2)	multimsgout=$((multimsgout+1));;
	esac
	psipdate=$sipdate; 		psiptime=$siptime
	pinsidesip=$insidesip;	psipstart=$sipstart;	pdirdefined=$dirdefined
	pip=$ip;				plocalip=$localip
#	pprevip=$previp;		pprevlocalip=$prevlocalip		
	embedded=1
	complete_sipmsg

	sipdate=$psipdate;		siptime=$psiptime
	insidesip=$pinsidesip; 	dirdefined=$pdirdefined
	ip=$pip; localip=$plocalip; base64found=0
	siptotalmsg=$((siptotalmsg+1))			
	sipmsg_header
	start_sipmsg
	sipstart=$psipstart
	linebuf="$line"
	prevline="$line"
} # multi_sipmsg()

function save_sipline() {
	if [[ $sipnotify != 0 ]] && [[ $line =~ "Event: refer" ]]; then
		notifyrefer=1
	elif [[ $line =~ xml\ version= ]] && [[ ${#line} -gt 80 ]]; then
		line=$(sed 's/>\s*</>\n</g' <<< "$line" | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g')
	fi

   	if [[ $linebuf == "" ]] && [[ $line != "" ]]; then
		linebuf="$line"
	elif [[ $line != "" ]]; then
		linebuf="$linebuf\r\n$line"
	fi
} # save_sipline()

function explore_logfolder () {
	targetfiles=""

	targetX=""; targetX=$(ls -r -t1 vantage.log.[0-9]* 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $((alllogs)) == 0 ]] && [[ $targetX != "" ]]; then
#		targetfiles=$(tail -1 <<< $targetX)
		targetfiles=${targetX##* }							# last word
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
#			targetfiles=$(tail -1 <<< $targetfiles)
			targetfiles=${targetfiles##* }							# last word
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
	elif [ -f "MR_Report.txt" ] && [ -f "audio_configuration.txt" ]; then
		echo -e "\nerror: $bvar appears to be related to a media_report file. Ignored."
		error=99; file=""; filelist=""; return
	fi

	explore_logfolder

	if [[ $file == "" ]]; then
		error=1
		echo -e "\nerror: could not find any K1xx/H175 related logs in $folder"
	fi

	cd "$currdir"
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

function convert_1xc () {
	while IFS= read -r line
	do
		nlines=$((nlines+1))

#		if [[ $line =~ DBH\ \[.*\]\ SIGNAL ]]; then
#		if [[ $line =~ DBH\ \[.*SIGNAL ]] || [[ $line =~ DBH:.*SIGNAL: ]] || [[ $line =~ \]\ R|SE.*bytes\  ]]; then

		if [[ $line =~ DBH.*Length= ]] || [[ $line =~ bytes\  ]]; then
			if [[ $((sipstart)) != 0 ]]; then
				explore_sipmsg
			fi
			insidesip=1
			siptotalmsg=$((siptotalmsg+1))	
			sip_direction
			get_sip_datetime	

		elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
			if [[ $line == "{"* ]] || [[ ${#line} == 0 ]];	then
				sipstart=1
			else
				insidesip=0
				if [[ $((bDebug)) != 0 ]]; then
					echo "error: found a new SIP message candidate with invalid 2nd line. Contact developer."
				fi			
			fi

		elif [[ $((sipstart)) == 1 ]];	then
			if [[ $((vsyslog)) == 211 ]] && [[ ${line:0:1} == "[" ]]; then
				line=$(cut -d' ' -f2- <<< "$line")
			fi
			sipmsg_header	
			start_sipmsg
			sipstart=2

		elif [[ $((sipstart)) == 2 ]]; then
			if [[ $line == *"}"* ]]; then
				explore_sipmsg
				continue
			fi
		
			if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				line=$(awk -F"Base64 dump" '{print $1}' <<< "$line")
				save_sipline

			elif [[ $((base64found)) != 0 ]] && [[ $line != "" ]]; then
				if [[ $linebuf64 == "" ]]; then
					linebuf64="$line"
				else
					linebuf64="$linebuf64$line"
				fi
				
			elif [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then												# due to multiple SIP msg in the same RX SIPMESSAGE				
#			elif [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then								# due to multiple SIP msg in the same RX SIPMESSAGE
#			elif [[ $dirdefined == 1 ]] && [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then	# it can occur only in RX direction
				if [[ ! $line =~ ^GUID= ]]; then
					multi_sipmsg
				fi
			else
				save_sipline		
#				prevline="$line"				
			fi
		fi				
	done <<< "$conv"
} # convert_1xc()

function convert_k1xx () {
#	conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
#  	conv=$(awk -e '/: \[SIP\]:/{flag=1} flag; /}/{flag=0}' "$file")
#	conv=$(awk -W source='/: \[SIP\]:[RS]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
	if [[ $((vsyslog)) == 13 ]]; then
		conv=$(awk -W source='/D\ SIP\ \ \ \ \ :\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)	
		if [ $? != 0 ]; then
#			conv=$(awk -e '/: \[SIP\]:[RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			conv=$(awk -e '/D\ SIP\ \ \ \ \ :\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		fi
	else
		conv=$(awk -W source='/\[SIP\]:[RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)	
		if [ $? != 0 ]; then
#			conv=$(awk -e '/: \[SIP\]:[RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			conv=$(awk -e '/\[SIP\]:[RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)		
		fi
	fi

	while IFS= read -r line
	do
#		linelength=${#line}
		nlines=$((nlines+1))
								
#		if [[ $line =~ \):\ \[SIP\]:[RS] ]]; then
		if [[ $line =~ \[SIP\]:[RS]E ]] || [[ $line =~ D\ SIP\ \ \ \ \ :\ [RS]E ]]; then
			if [[ $endptaddr != "" ]]; then
				if [[ $line != *$endptaddr* ]]; then	
					continue
				fi
			elif [[ $((sipstart)) != 0 ]]; then
				explore_sipmsg
#				complete_sipmsg
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
			if [[ $line =~ DeskPhoneServiceAdaptor ]] || [[ $line =~ D\ SIP\ \ \ \ \ :\  ]]; then
				if [[ $((vsyslog)) == 12 ]]; then
					line=$(awk -F'DeskPhoneServiceAdaptor: ' '{print $2}' <<< "$line")
				elif [[ $((vsyslog)) == 13 ]]; then
					line=$(awk -F'D SIP     : ' '{print $2}' <<< "$line")
				else
					line=$(awk -F'DeskPhoneServiceAdaptor' '{print $2}' <<< "$line" | awk -F"[0-9]{4}): " '{print $2}')  # TODO: need a better regexp for [-0]{4}
				fi

				if [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
					if [[ ${#line} -lt 2 ]]; then
						continue
					else 
						start_sipmsg
					fi

				elif [[ $line == "}"* ]] || [[ $line == "[null]"* ]]; then
					explore_sipmsg
#					complete_sipmsg
				
				elif [[ $((sipstart)) != 0 ]] && [[ ${#line} != 0 ]]; then
				    if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then		# this may need to go into explore_sipmsg()
				    	base64found=1
						line=$(awk -F"Base64 dump" '{print $1}' <<< "$line")
						save_sipline
			    	elif [[ $((base64found)) != 0 ]] && [[ $line != "" ]]; then
						if [[ $linebuf64 == "" ]]; then
							linebuf64="$line"
						else
							linebuf64="$linebuf64$line"
						fi

					elif [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then	# due to multiple SIP msg in the same RX SIPMESSAGE
						if [[ ! $line =~ ^GUID= ]]; then
							multi_sipmsg
						fi
					else
						save_sipline
					fi
				fi

			elif [[ $((sipstart)) != 0 ]]; then
				explore_sipmsg
#				complete_sipmsg
			fi
		fi		
	done <<< "$conv"
} # convert_k1xx()

function convert_h175 () {		# same as convert_EndpointLog from trace96x1.sh
    conv=$(awk -W source='/SIPMESSAGE:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
	if [[ $? != 0 ]]; then
    	conv=$(awk -e '/SIPMESSAGE:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
	fi

	while IFS= read -r line
	do
		nlines=$((nlines+1))

		if [[ $line =~ SIPMESSAGE: ]]; then
			if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
				continue
			elif [[ $line == *" End of "* ]] && [[ $((sipstart)) != 0 ]]; then		# 1xAgent special line
				explore_sipmsg
#				complete_sipmsg
			fi

			if [[ $((sipstart)) != 0 ]]; then
				if [[ $((sipsplit)) == 0 ]]; then
					explore_sipmsg				
#					complete_sipmsg
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
						explore_sipmsg					
#						complete_sipmsg
					fi
				else
					explore_sipmsg				
#					complete_sipmsg				
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
					explore_sipmsg					
#					complete_sipmsg

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
				explore_sipmsg			
#				complete_sipmsg
			fi
		elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			if [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
				explore_sipmsg			
#				complete_sipmsg
			fi
		elif [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
			if [[ $((sipstart)) == 0 ]]; then
				continue
			elif [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
				explore_sipmsg			
#				complete_sipmsg
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
					sipmsg_header
					start_sipmsg
            	    insidesip=3
				fi
#		  fi
			fi

		elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
			if [[ $line =~ RX\ |TX\  ]]; then
				line=$(awk -F "RX |TX " '{print $2}' <<< "$line")
				sipmsg_header
				start_sipmsg
                insidesip=3
			fi

		elif [[ $((sipstart)) != 0 ]]; then
# VDICcut		if [[ $line =~ \<16[34567]\> ]] || [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
# VDICcut			complete_sipmsg
			if [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[04] ]]; then
				explore_sipmsg			
#				complete_sipmsg			

			elif [[ ${#line} != 0 ]]; then
				sipline=$(egrep -c "<16[3-7]>" <<< "$line")
				if [[ $((sipline)) -gt 0 ]]; then					
				##if [[ $line == *" SIPMESSAGE: "* ]]; then
					line=$(awk -F "<16[37]>" '{print $1}' <<< "$line")
					if [[ ${#line} != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then				# this may need to go into explore_sipmsg()
					    	base64found=1
							line=$(awk -F"Base64 dump" '{print $1}' <<< "$line")
							save_sipline
			    		elif [[ $((base64found)) != 0 ]] && [[ $line != "" ]]; then
							if [[ $linebuf64 == "" ]]; then
								linebuf64="$line"
							else
								linebuf64="$linebuf64$line"
							fi
						elif [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then			# due to multiple SIP msg in the same RX SIPMESSAGE
							if [[ ! $line =~ ^GUID= ]]; then
								multi_sipmsg	
							fi
						else
							save_sipline
						fi
					fi
# VDIC-beg
					if [[ $((sipsplit)) == 0 ]]; then
						explore_sipmsg					
#						complete_sipmsg
					fi
# VDIC-end
			    elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then				# this may need to go into explore_sipmsg()
			    	base64found=1
					line=$(awk -F"Base64 dump" '{print $1}' <<< "$line")
					save_sipline
	    		elif [[ $((base64found)) != 0 ]] && [[ $line != "" ]]; then
					if [[ $linebuf64 == "" ]]; then
						linebuf64="$line"
					else
						linebuf64="$linebuf64$line"
					fi

				elif [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then			# due to multiple SIP msg in the same RX SIPMESSAGE
					if [[ ! $line =~ ^GUID= ]]; then
						multi_sipmsg
					fi
				else
					save_sipline
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
		basefile="$file"
	fi

#	filecontent=$(egrep -a -m 1 -e "ANDROID:|SIPMESSAGE:" "$file")
	filecontent=$(egrep -a -m 1 -e "DeskPhoneServiceAdaptor|\ D\ SIP|SIPMESSAGE:" "$file" 2>/dev/null)
	filecontent2=$(egrep -a -m 1 -e "SIPMESSAGE:" "$file" 2>/dev/null)

#	if [[ $filecontent =~ ANDROID ]] && [[ $filecontent2 == "" ]]; then
	if [[ $filecontent =~ DeskPhoneServiceAdaptor ]] && [[ $filecontent2 == "" ]]; then	
		rec2=$(egrep -a -c -e "\[SIP\]:[SR]E" "$file" 2>/dev/null)
		rec=$(egrep -a -c -e "CSeq:" "$file" 2>/dev/null)
#		sample=$(egrep -a -m 1 "): \[SIP\]:" "$file" 2>/dev/null)
		sample=""; sample=$(egrep -a -m 1 "\[SIP\]:[SR]E" "$file" 2>/dev/null)		

		if [[ $((rec2)) == 0 ]];	then
			if [[ $sample == "" ]]; then
				echo "$basefile: found \"[SIP]:[<>]\" lines only, which means debug loglevel with SIPMESSAGE logcategory was not enabled."
				echo $sample
			else
				echo "$basefile : No SIP messages have been found in the expected format."
				echo "Perhaps this file is not a vantage.log or EndpointLog+sig+CPS.txt file."
			fi
	
			error=1
			if [[ $((rec)) == 0 ]]; then
				echo 'In fact, no sign of any "CSeq:" lines in '$basefile
				error=2; rec=0
			else
				echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages within '$basefile
			fi
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
				if [[ $footprint == 1 ]]; then
					echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
				fi
#			elif [[ $var != $file ]]; then
#				echo -e "Verify source and content of $bvar -> $basefile\n"
#			else
#				echo -e "Verify source and content of $bvar\n"
			fi

			if [[ $input != "" ]] && [ -d "$input.tmp" ] && [ -d "$input.tmp/data/cp" ] && [ -s "$input.tmp/data/cp/configcache.xml" ]; then
				echo "Verifying logging configuration in configcache.xml:"
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG|VERBOSITY" "$input.tmp/../configcache.xml" 2>/dev/null
	 		elif [[ $folder != "" ]] && [ -d "$folder/../../data/cp" ] && [ -s "$folder/../../data/cp/configcache.xml" ]; then
				echo "Verifying logging configuration in configcache.xml:"
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG|VERBOSITY" "$folder/../configcache.xml" 2>/dev/null
			fi

			if [[ $input != "" ]] && [ -d "$input.tmp" ] && [ -d "$input.tmp/data/cp" ] && [ -s "$input.tmp/data/cp/config.xml" ]; then
				echo "Verifying logging configuration in config.xml:"
				egrep -A 1 "LocalLogLevel|LogCategoryList|LogLevel|Verbosity|LogServer" "$input.tmp/data/cp/config.xml" 2>/dev/null
			elif [[ $folder != "" ]] && [ -d "$folder/../../data/cp" ] && [ -s "$folder/../../data/cp/config.xml" ]; then
				echo "Verifying logging configuration in config.xml:"
				egrep -A 1 "LocalLogLevel|LogCategoryList|LogLevel|Verbosity|LogServer" "$folder/../../data/cp/config.xml" 2>/dev/null			
			fi

		elif [[ $((rec)) != 0 ]] && [[ $((vsyslog)) == 0 ]]; then
			lhost=$(awk '{print $4}' <<< "$sample")							# cut -d' ' -f4)
			platform=$(awk '{print $6}' <<< "$sample")						# cut -d' ' -f6)

			if [[ $lhost == "localhost" ]] && [[ $platform == "ANDROID:" ]]; then
# Nov  7 09:55:31 localhost 10.16.176.12 ANDROID: +07:00 2018 000 0 | 11-07 09:55:31.356 D/DeskPhoneServiceAdaptor( 6599): DEBUG[SIP]:SENDING 1107 bytes to 10.16.26.183:5061 {			
				vsyslog=10
			elif [[ $sample =~ DeskPhoneServiceAdaptor:\ \[SIP\] ]]; then
# 06-14 18:55:51.140  2037  2709 D DeskPhoneServiceAdaptor: [SIP]:SENDING 653 bytes to 198.152.85.104:5061 {
# 06-14 18:55:51.140  2037  2709 D DeskPhoneServiceAdaptor: User-Agent: Avaya Vantage Connect/3.1.1.2 (0001; K175CW0A; 409.0.0)^M

				vsyslog=12
			else
				rec=$(wc -l < "$file")
				platform=$(awk '{print $2}' <<< "$sample")
				xlines=$(egrep -a -c "<16[34567]>" "$file" 2>/dev/null)
				sample=""; sample=$(egrep -m 1 "SIPMESSAGE:" "$file" 2>/dev/null)
				if [[ $((rec)) == 0 ]] && [[ $xlines != 0 ]]; then
					sed 's/<16[34567]>/\n/g' < "$file" > "$file.udpsyslog"
					file="$file.udpsyslog"; tmpfile=2
					rec=$(egrep -a -c -e "CSeq:" "$file")					
					vsyslog=11
				elif [[ $platform == "ANDROID:" ]]; then
					vsyslog=11
				fi
			fi
		fi
	elif [[ $filecontent2 =~ SIPMESSAGE: ]]; then
		sample=""; sample=$(egrep -m 1 "SIPMESSAGE:" "$file" 2>/dev/null)
		rec2=$(egrep -a -c -e "SIPMESSAGE:" "$file" 2>/dev/null)
		rec=$(egrep -a -c -e "CSeq:" "$file" 2>/dev/null)		
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
			sample2=""; sample2=$(awk -F": INFO    : " '{print $2}' <<< $sample)
			if [[ $sample2 =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				egrep "SIPMESSAGE" < "$file" | awk -F": INFO    : " '{print $2}' > "$file.syslog"			# H175/log35.txt
				file="$file.syslog"; tmpfile=2
				if [[ ${#sample} -lt 160 ]]; then
					vsyslog=175
				else																						# log35.txt SIPMESSAGE no linebreaks
					vsyslog=0
					echo -e "\nALERT: input file includes SIPMESSAGES in unrecognized format (no linebreaks?).  Contact developer.\n"
				fi
			fi
		fi
	elif [[ $filecontent =~ \ D\ SIP ]] && [[ $filecontent2 == "" ]]; then
		rec2=$(egrep -a -c -e "D\ SIP\ \ \ \ \ :\ [SR]E" "$file" 2>/dev/null)
		rec=$(egrep -a -c -e "CSeq:" "$file" 2>/dev/null)
#		sample=$(egrep -a -m 1 "): \[SIP\]:" "$file" 2>/dev/null)
		sample=""; sample=$(egrep -a -m 1 "D\ SIP\ \ \ \ \ :\ [SR]E" "$file" 2>/dev/null)		

		if [[ $((rec2)) == 0 ]];	then
			if [[ $sample == "" ]]; then
				echo "$basefile: found \"D SIP     : [<>]\" lines only, which means debug loglevel with SIPMESSAGE logcategory was not enabled."
				echo $sample
			else
				echo "$basefile : No SIP messages have been found in the expected format."
				echo "Perhaps this file is not a vantage.log or EndpointLog+sig+CPS.txt file."
			fi
	
			error=1
			if [[ $((rec)) == 0 ]]; then
				echo 'In fact, no sign of any "CSeq:" lines in '$basefile
				error=2; rec=0
			else
				echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages within '$basefile
				asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
				if [[ $((asmfile)) != 0 ]]; then
					asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
					if [[ $((asmfile)) != 0 ]]; then
						echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
						echo "This kind of input is not (yet) supported by this tool."
					fi
				fi
			fi
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
				if [[ $footprint == 1 ]]; then
					echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
				fi
#			elif [[ $var != $file ]]; then
#				echo -e "Verify source and content of $bvar -> $basefile\n"
#			else
#				echo -e "Verify source and content of $bvar\n"
			fi
			rec=0
		else
			vsyslog=13
		fi
	else 
		rec=$(egrep -c -e "^CSeq:*" "$file" 2>/dev/null)
    	rec2=$(egrep -c " bytes Re" "$file" 2>/dev/null)
	    if [[ $((rec2)) == 0 ]]; then
			rec2=$(egrep -ce "DBH \[.*SIGNAL" "$file" 2>/dev/null)												# AAFD
			if [[ $((rec2)) == 0 ]]; then
				rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)											# 1XC/1XM
				if [[ $((rec2)) != 0 ]]; then			
					vsyslog=211
					if [[ $bINC == 0 ]] && [[ $bEXC == 0 ]]; then
	       		    	echo "Warning: no conversion would be really required on $basefile."
						echo "You could use this file along with \"traceSM\" as it is."
					fi
					conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					if [[ $? != 0 ]]; then
			    		conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					fi	
				fi
			else
				vsyslog=211
				conv=$(awk -W source='/DBH\ \[.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				if [[ $? != 0 ]]; then
	    			conv=$(awk -e '/DBH\ \[.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				fi		
			fi
			if [[ $((rec2)) == 0 ]]; then
				rec2=$(egrep -ce "[0-9]\]\ [RS]E.*bytes " "$file" 2>/dev/null)										# ACiOS
				if [[ $((rec2)) != 0 ]]; then
					vsyslog=212
					if [[ $bINC == 0 ]] && [[ $bEXC == 0 ]]; then
	       		    	echo "Warning: no conversion would be really required on $basefile."
						echo "You could use this file along with \"traceSM\" as it is."
					fi
					conv=$(awk -W source='/]\ R|SE.*bytes\ /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					if [[ $? != 0 ]]; then
		    			conv=$(awk -e '/]\ R|SE.*bytes\ /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					fi
				else
					error=1
				   	echo "error: $basefile file is empty - no TX/RX SIP messages found in the expected format."
			    	if [[ $rec == 0 ]]; then
				    	echo "In fact, no sign of any \"CSeq:\" lines within $basefile"
					    error=2
					else
					    echo "Though, found $rec lines with \"CSeq:\" - so there might be some SIP messages within $basefile"
						rec=0; error=3
						asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
						if [[ $((asmfile)) != 0 ]]; then
							asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
							if [[ $((asmfile)) != 0 ]]; then
								echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
								echo "This kind of input is not (yet) supported by this tool."
							fi
						fi
					fi
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
			echo "error: could not recognize content of $basefile"
			if [[ $var != $file ]]; then
				echo -e "Verify source and content of $basefile within $bvar.\n"
			else
				echo -e "Verify source and content of $basefile.\n"
			fi
		fi
		error=9; return

	elif [[ $((rec)) != 0 ]]; then
		logsec=$SECONDS
		base64msg=0
	    line="";		linebuf="";		linebuf64=""		
		partnum="00";	maxpart="99"
		sipmaxpart=0;	sipmaxpartmsg=0
		sipmaxsplit=0;	sipmaxpartsipword=""
		lastfoundip="";	foundipaddr="";	ip=""
		insidesip=0;	sipstart=0;		dirdefined=0		
		sipmsg=0;		siptotalmsg=0
		nlines=0;		siplines=0;		sipmaxlines=0
		sipword="";		sipwordlist="";	longestsipword="";	prevsipword=""
		firstmsg="";	lastmsg="";		longestmsg=0
		timefirst="";	timelast=""
		siptime="";		prevsiptime=""
		sipin=0;		sipout=0		
		callID="";		calltime="";	callDIR=0
		callidtime1="";	callmsgnum1=0;	callidword1=""
		callidtime2="";	callmsgnum2=0;	callidword2=""
		nINFO=0;		infoin=0;		infoout=0
		notpassed=0;	notpassedin=0; 	notpassedout=0
		currcseq=0;		prevcseq=0;		cseqword=""
		sipbadmsg=0;	sipbadmsgnum=0
		sipbadtime=0;	sipbadtimemsg=""
		nPONG=0;		embedded=0
		useragent="";	server=""; 	serverip=""; serverua=""
		scua="";		scip=""		
		multimsg=0; 	multimsgin=0;	multimsgout=0
		notifyrefer=0; 	sipnotify=0;	prevline="notempty"
		n=0
		prevINFOseq=""
		prevNOTIFYseq="";	prevNOTIFYcallid=""		
		prevPUBseq="";		prevPUBcallid=""
		prevSUBseq1=""; 	prevSUBcallid1=""
		prevSUBseq2="";		prevSUBcallid2=""
		prevSUBseq3="";		prevSUBcallid3=""
		prevSUBseq4="";		prevSUBcallid4=""				
		prevline="notempty"	

		evdialog=0; evccinfo=0; evreg=0; evcmfeat=0; evmsgsum=0
		evunknown=0; evpush=0; evscrupd=0; evrefer=0; evccs=0; evconf=0; evuaprof=0

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
				output="$bvar"
			elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
				output="$xfile-$basefile"
			else
				output="$bvar"
			fi
		else
			output="$basefile"
		fi

		if [[ $output != "" ]]; then
			newfile="$output.asm.tmp"
			bakfile="$output"
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
		10|11|12|13)	convert_k1xx;;
		2|20|175)		convert_h175;;
		211|212)		convert_1xc;;
#		20)		convert_syslog_mega;;
		esac
# else
# echo basefile=$basefile bfile=$bfile file=$file output=$output newfile=$newfile
# 	echo Converting $vsyslog $file
# fi

		if [[ $((sipstart)) != 0 ]]; then
			explore_sipmsg
#			complete_sipmsg
		fi
		echo '' >> "$newfile"
		
		if [[ $output == "" ]]; then
			output="$var"
		fi
		
		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error\n\n"

		elif [[ $((sipmsg)) -lt 1 ]]; then
			echo -e "\nError: No SIP messages have been found in $basefile. Contact developer."

        elif [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $bvar file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    have been converted for addr=$endptaddr into $output.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				firmware=""; firmware=$(egrep -m 1 "K1xx_SIP|K1xxB_SIP" "$file" 2>/dev/null | sed -e 's/[[:space:]]*$//')
				if [[ $firmware != "" ]]; then
					firmware=$(awk -F"K1xx" '{print $2}' <<< "$firmware")
					if [[ $firmware != "" ]]; then
						firmware=${firmware/.tar/}
						firmware="K1xx$firmware"
					fi
				fi

				if [[ $lastfoundip != "" ]] && [[ $lastfoundip != "0.0.0.0" ]]; then
					lastfoundip=$(sed -e 's/\.$//g' <<< $lastfoundip)
					printf "\t%-48s ip.addr == %s\n" "${useragent:0:48}" "$lastfoundip"
					if [[ $firmware != "" ]]; then
						printf "\tFirmware: %-61s\n" "${firmware:0:61}"
					fi
				elif [[ $firmware != "" ]]; then
					printf "\t%-48s %s\n" "${useragent:0:48}" "${firmware:0:30}"
				else
					printf "\t%-73s\n" "${useragent:0:73}"
				fi

				if [[ $scua != "" ]]; then
					scua=$(awk -F "Agent: " '{print $2}' <<< "$scua")
					if [[ $scip != "" ]]; then
						printf "\tSC session with %-33s ip.addr == %s\n" "${scua:0:33}" "$scip"
					else
						printf "\tFound SC session with %-51s" "${scua:0:51}"
					fi
				fi

				if [[ $server == "" ]]; then
					serverip=""; server=$(egrep -m 1 -e "^Server:(?!.*Presence).*$" "$newfile" | tr -d "\r\n")				
				fi				
				if [[ $server != "" ]]; then
					if [[ $serverip != "" ]]; then
						serverip=$(sed -e 's/\.$//g' <<< "$serverip")
					fi
					if [[ $serverip != "" ]]; then
						printf "\t%-48s ip.addr == %s\n" "${server:0:48}" "$serverip"
					else
						printf "\t%-73s\n" "${server:0:73}"
					fi
				fi
			fi

			echo -e "\tTotal # of lines digested:\t\t\t $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
				if [[ $((notpassed)) != 0 ]]; then
					echo -e "\tTotal # of SIP messages filtered  (RX/TX):\t $notpassed ($notpassedin/$notpassedout)"
				fi			
				if [[ $((nINFO)) != 0 ]]; then
					if [[ $noINFO == 1 ]]; then
						echo -e "\tINFO messages ignored:\t\t\t\t  $nINFO ($infoin/$infoout)"
					elif [[ $noINFO == 2 ]]; then
						echo -e "\tINFO messages found:\t\t\t\t  $nINFO ($infoin/$infoout)"
					fi
				fi
				if [[ $((nPONG)) != 0 ]]; then
					echo -e "\tPONG messages found:\t\t\t\t $nPONG"
				fi
				if [[ $((multimsg)) != 0 ]]; then
					echo -e "\tEmbedded SIP messages:\t\t\t\t $multimsg ($multimsgin/$multimsgout)"
					echo -e "# Embedded SIP messages:\t\t\t $multimsg ($multimsgin/$multimsgout)" >> "$newfile"					
				fi
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
				if [[ $((sipmaxsplit)) != 0 ]]; then			# .log.sipmessages are already re-constructed - do not expect split stat
					echo -e "\tSplit SIP messages (with 2 or more parts):\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts maxpart: $sipmaxpart msg# $sipmaxpartmsg $sipmaxpartsipword"
					echo -e "\tSplit SIP messages (with 2 or more parts):\t $sipmaxsplit ($splitin/$splitout) parts: $splitparts maxpart: $sipmaxpart msg# $sipmaxpartmsg $sipmaxpartsipword" >> "$newfile"
				fi
				if [[ $((sipbadmsg)) != 0 ]]; then
					if [[ $sipbadmsgnum != 0 ]]; then
						echo -e "\tBad SIP messages (eg \"Part\" starts with \"02\"):\t $sipbadmsg at msg #$sipbadmsgnum"
						echo -e "# Bad SIP messages (eg \"Part\" starts with \"02\"):  $sipbadmsg at msg #$sipbadmsgnum" >> "$newfile"
					else
						echo -e "\tBad SIP messages (eg \"Part\" starts with \"02\"):\t $sipbadmsg"
						echo -e "# Bad SIP messages (eg \"Part\" starts with \"02\"):  $sipbadmsg" >> "$newfile"
					fi
				fi
				if [[ $((sipbadtime)) != 0 ]]; then
					echo -e "\tBad SIP messages (timestamps out of order):\t  $sipbadtime at msg #$sipbadtimemsg"
					echo -e "# Bad SIP messages (timestamps out of order):\t  $sipbadtime at msg #$sipbadtimemsg" >> "$newfile"
				fi
				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
				fi

				if [[ ${#firstmsg} -le 11 ]] && [[ ${#lastmsg} -le 12 ]]; then					
					printf "\tFirst msg: %-11s %s\t Last msg: %-12s %s\n" "$firstmsg" "$timefirst" "$lastmsg" "$timelast"
				else
					printf "\tFirst msg: %-33s\t %s\n" "${firstmsg:0:33}" "$timefirst"
					printf "\tLast msg: %-36s\t %s\n"  "${lastmsg:0:36}"  "$timelast"
				fi
				if [[ $findANI != "" ]] && [[ $callID != "" ]] && [[ $calltime != "" ]]; then
					if [[ $callDIR == 1 ]]; then
						echo -e "\tIncoming call from $findANI at $calltime\t $callID"
					elif [[ $callDIR == 2 ]]; then
						echo -e "\tOutgoing call to $findANI at $calltime\t $callID"
					fi
				fi
				if [[ $findCALLID != "" ]] && [[ $callidtime1 != "" ]]; then
					if [[ $callidtime2 != "" ]]; then
						echo -e "\tCallID= $findCALLID:\tfirst seen at $callidtime1 ($callidword1) / last at $callidtime2 ($callidword2)"
					else
						echo -e "\tCallID= $findCALLID:\tfirst seen at $callidtime1 ($callidword1)"
					fi
				fi

				if [[ $bDebug == 0 ]]; then
					if [[ $evstrings != "" ]]; then
						echo -e "\n# Events found: $evstrings" >> "$newfile"
						echo -en "# " >> "$newfile"
					fi
					if [[ $evdialog != 0 ]]; then
						echo -en "dialog: $evdialog| " >> "$newfile"
					fi
					if [[ $evccinfo != 0 ]]; then
						echo -en "avaya-cm-info: $evccinfo| " >> "$newfile"
					fi
					if [[ $evreg != 0 ]]; then
						echo -en "reg: $evreg| " >> "$newfile"
					fi
					if [[ $evcmfeat != 0 ]]; then
						echo -en "avaya-cm-feature-status: $evcmfeat| " >> "$newfile"
					fi
					if [[ $evmsgsum != 0 ]]; then
						echo -en "message-summary: $evmsgsum| " >> "$newfile"
					fi
					if [[ $evpush != 0 ]]; then
						echo -en "avaya-push-notification: $evpush| " >> "$newfile"
					fi
					if [[ $evrefer != 0 ]]; then
						echo -en "refer: $evrefer| " >> "$newfile"
					fi
					if [[ $evccs != 0 ]]; then
						echo -n "avaya-ccs-profile: $evccs| " >> "$newfile"
					fi
					if [[ $evconf != 0 ]]; then
						echo -en "conference: $evconf| " >> "$newfile"
					fi
					if [[ $evuaprof != 0 ]]; then
						echo -en "us-profile: $evuaprof| " >> "$newfile"
					fi						
					if [[ $evunknown != 0 ]]; then
						echo -e "\n# Unknown events: $evunknown\n" >> "$newfile"
					else
						echo '' >> "$newfile"
					fi
				fi
			fi		
		fi

		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.3f "$(($((n)) * 1000 / $tmpsec))e-3")
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t Total spent: $SECONDS sec   Avg. SIP msg/sec: $avgmsg\n"
		else
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t  Time spent: $SECONDS sec\n"
		fi
		currtime=$(date +%R:%S)

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
		else
			echo "Conversion of $file has ended with error code: $error n=$n sipwords=$sipwordlist"
		fi	

		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd; ls -l "$output.asm"

		if [[ $bDebug != 0 ]] && [[ $tmpfile != 0 ]] && [[ $var != $file ]]; then
			case $tmpfile in
			1|2|3|4|5)	rm "$file" 2>/dev/null;;
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
  while getopts ":e:hbf:sdk:v:ACI:X:N:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)  
		alllogs=1;;
	C)
		bCAT=1;;
    I)
		filterI=${OPTARG}
		explore_filters;;
	X)
		filterX=${OPTARG}
		explore_filters;;
	N)	
		if [[ $OPTARG =~ ^id: ]]; then			
			findCALLID=${OPTARG/id:/}
		elif [[ $OPTARG =~ ^ID: ]]; then			
			findCALLID=${OPTARG/ID:/}
		elif [[ $OPTARG =~ [A-Za-z]+ ]]; then
			findANI=""
		else
			findANI=${OPTARG}									
		fi;;
	s)
		sipstat=0;;
	d)
		bDebug=0;;
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
origctarget=""; var=""

file --help >/dev/null 2>&1
if [[ $? != 0 ]]; then
	echo -e "\nerror: unable to find "file" utility.  You may want to install it with "apt install file" command."
	echo -e "This tool relies heavily upon "file" command. Cannot continue execution. Aborting...\n"
	exit 1
fi

if [[ $((base64decode)) != 0 ]]; then
	base64 --help >/dev/null 2>&1
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
		elif [[ $var == "-X"* ]]; then
			skipper=5
		elif [[ $var == "-I"* ]]; then
			skipper=6			
		elif [[ $var == "-v"* ]]; then
			skipper=9
		else
			skipper=0
		fi
		var=""; continue
	elif [[ $skipper != 0 ]]; then
		if [[ $((skipper)) == 1 ]]; then
			voutput="$var"
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
				voutput=1
			fi
		elif [[ $((skipper)) == 2 ]]; then
			endptaddr="$var"
		elif [[ $((skipper)) == 3 ]]; then
			enckey="$var"
		elif [[ $((skipper)) == 4 ]]; then
			if [[ $findANI == "" ]] || [[ $findCALLID == "" ]]; then
				if [[ $OPTARG =~ ^id: ]]; then			
					findCALLID=${OPTARG/id:/}
				elif [[ $OPTARG =~ ^ID: ]]; then			
					findCALLID=${OPTARG/ID:/}
				elif [[ $OPTARG =~ [A-Za-z]+ ]]; then
					findANI=""
				else
					findANI=${OPTARG}									
				fi
			else
				findANI="$findANI"		# findANI=$var
			fi
		elif [[ $((skipper)) == 5 ]] && [[ $filterX == "" ]]; then
			filterX=${OPTARG}
			explore_filters
		elif [[ $((skipper)) == 6 ]] && [[ $filterI == "" ]]; then
			filterI=${OPTARG}
			explore_filters
		elif [[ $((skipper)) == 9 ]]; then
			vsyslog="$var"
		fi	
		skipper=0	; var=""	
		continue
	fi

	file=""; 	filelist=""; filetype=""
	currtime=$(date +%R:%S); currdir="$PWD"
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
		target="$bvar"
	fi

#	target=${target%%.*}										# TODO: what about ../folder or ../filename - note the leading ".."	
	if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
		target=${target%.*}
		if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
			target=${target%.*}
		fi
	fi

	if [ -d "$var" ]; then
		echo -en "\nExploring content in $bvar folder ... stand by\n"
		destdir="$var"; folder="$bvar"
		cd "$var"
		explore_folders
		cd "$currdir"
	
	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $bvar... stand by\n"
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
						openssl aes-256-ctr -md sha256 -d -salt -k $enckey -in "$file" -out "$input2-decrypted.tgz" 2>/dev/null
						if [[ $? != 0 ]]; then
							echo "error: Could not decode $bvar using \"openssl aes-256-ctr -md sha256 -salt -k $enckey\""
							echo -e "Verify encryption key with provider.\n"
							error=6; filecontent="error"; continue
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
						if [[ $filetype == "data" ]] && [[ $enckey != "" ]]; then
							echo -e "\nerror: Unable to extract $file"
							echo "encryption key: $enckey may not be the correct one."
							echo "Verify encryption key with provider of $bvar"
							error=7; file=""; filecontent="UNKNOWN"; continue							
						else
							echo "Decoded $bvar into $basefile successfully using \"openssl\"."
						fi
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

					if [[ $input2 == $zfile ]]; then input2="$input2.uncompressed"; fi

					if [ -d "$input2" ]; then
						input2="$input2-tmp"
						if [ -f "$input2" ]; then
							rm "$input2" 2>/dev/null
						fi
					fi

					if [[ $bGunzip != 0 ]]; then
						echo "Uncompressing $zfile into $input2 ...                                                        "
						gunzip -q -c "$zfile" > "$input2" 2>/dev/null

						if [[ $? -le 1 ]]; then
							file="$input2"; tmpfile=2
							filetype=$(file -b "$file")
							filecontent="ASCII"
						else
							echo -e "error: failed to uncompress $bfile, using \"gunzip\" utility."
							echo -e "Tip: could this file be an encrypted debugreport? Try with \"-k key\" option.\n"
							error=8; continue
						fi
					else
						echo -e "error: unable to uncompress $bfile, \"gunzip\" utility not found.\n"
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
						echo -e "error: could not delete existing $input.tmp folder."
						echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
						error=7; cd "$currdir"; input=""; continue
					fi
				fi
				mkdir "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "error: could not create $input.tmp folder at $PWD.\n"
					error=7; cd "$currdir"; continue
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
					echo -e "error: failed to extract $bfile using \"tar [z]xf\" command."
					echo -e "Tip: could this file be an encrypted debugreport? Try with \"-k key\" option.\n"				
					if [[ $bGunzip != 0 ]]; then
						echo "Trying to extract using \"gunzip\"..."
						gunzip -q "../$file" 2>/dev/null
						if [[ $? != 0 ]]; then
							echo -e "error: could not uncompress $bfile, using neither \"tar\" nor \"gunzip\" utilities.\n"
							error=8; cd "$currdir"; input=""; continue
						else
							tar xf $input 2>/dev/null										# TODO verify the exact new filename after gunzip
							if [[ $? != 0 ]]; then
								cd ..; rm -rf "$input.tmp"						
								echo -e "error: failed to uncompress $bfile, using \"tar\" utility.\n"
								error=8; cd "$currdir"; input=""; continue
							else
								destdir="$PWD"; tmpfile=1
								folder="$input"
								explore_folders
							fi
						fi
					else 
						cd ..; rm -rf "$input.tmp"						
						echo -e "error: failed to uncompress $bfile, using \"tar\" utility.\n"
						error=8; cd "$currdir"; input=""; continue
					fi
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"					
					explore_folders
				fi

				cd "$currdir"
			else
				echo -e "error: unable to uncompress $bvar, \"tar\" utility not found.\n"
				error=1; continue
			fi

		elif [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "error: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "error: unfortunately, this script is unable to extract RaR archives."
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
					echo -e "error: could not delete temp folder: $input.tmp in $PWD."
					echo -e "Check if any subfolders or files are open (in other shell sessions).\n"
					error=7; cd "$currdir"; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then				
				echo -e "error: could not create $input.tmp folder in $PWD.\n"
				error=7; cd "$currdir"; continue
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
					echo -e "error: could not uncompress $bfile, using \"unzip\"."
					echo -e "Suggesting to validate \"unzip\" manually on \"$bfile\".\n"
					error=8; cd "$currdir"; input=""; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"					
					explore_folders
				fi
			else
				error=8; cd "$currdir"; rm -rf "$input.tmp" 2>/dev/null
				echo -e "error: could not uncompress $bvar, \"unzip\" utility not found."
				echo -e "Suggesting to deploy \"unzip\" package. in Ubuntu, you can install it by typing: \"sudo apt install unzip\".\n"
				continue
			fi
			cd "$currdir"

		elif [[ $filetype =~ capture ]]; then
			if [[ $filetype =~ tcpdump ]] || [[ $filetype =~ pcap ]]; then
				n=0; line=$(whereis tshark 2>&1)
				tshark --version >/dev/null 2>&1
				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
		     		echo -e "error: unable to locate 'tshark' command"
					echo -e "'tshark' is required to extract syslog messages from $bvar into text file\n"
					error=10; continue
				else
					echo -e "Extracting syslog out of $bvar ..."
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
						echo -e "error: could not extract SYSLOG out of $bvar using tshark utility.  Verify tshark manually.\n"
						error=3; continue
					elif [ -f "$file.syslog2" ]; then
						echo -e "error: no SYSLOG messages have been found in $bvar."
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
								echo -e "error: could not extract SIPMESSAGES out of $bvar.syslog2\n"
								error=3; continue
							fi
						else
							echo -e "error: no SIPMESSAGES have been found in the extracted SYSLOG stream of $bvar\n"
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
						echo -e "error: could not filter $bvar for <16[34567]>\n"
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

	if [[ $bDebug != 0 ]]; then
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
		if [[ $tmpfile == 2 ]] && [[ $var != $file ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
		fi		
	fi
done

if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
elif [[ $((converted)) != 0 ]] && [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All $converted converted files have been concatenated into $ctarget\n"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0