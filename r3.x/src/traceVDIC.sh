#!/bin/bash
# shopt -s extglob
version="2.0.0.3"
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
bDebug=1
bFilterSIP=0
filtdate=""
filterI=""; filterX=""
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
findANI=""
findCALLID=""
adjusthour=0
localtime=1
base64decode=1
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
	echo 'Usage: traceVDIC.sh [OPTIONS] [<LOG_FILE>, <folder> ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either an EndpointLog.txt from VDIC, 1XA or SparkEmulator,"
	echo -e "\t\t\tEquinox/Workplace for VDI logreport (ZIP file) from Windows, iGEL, or eLux platforms"
	echo -e "\t\t\tis a syslog stream sent by a VDIC client, captured either via a remote SYSLOG server"
	echo -e "\t\t\tor captured via wireshark (pcap), or extracted using \"Follow UDP stream\" function"
	echo -e "\t\t\tor either a debugreport, an EndpointLog_B_sig_CPS.txt or syslog from an H175 phone"
	echo -e "\t<folder>\tis a path to a folder which includes above files eg. \"Avaya Workplace VDI/logs\""	
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
#	echo -e "\t-i \t\tconvert syslog messages only sent by SM IP addr: a.b.c.d"						
	echo -e "\t-a \t\tconvert all aditional logs in logreport where SIP message found"
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-c \t\tconcatenate output (.asm) files (if converted multiple logfiles)"
	echo -e "\t-e ipaddr\tconvert messages only with IP addr: \"a.b.c.d\""
	echo -e "\t-k \t\tset decryption key for debugreport decoding"	
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-D MMdd\t\tcollect SIP messages for the specified date only eg. 0820"
#	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"
#	echo -e "\t-N ANI|id:CallID       find a call with caller/called number matching to ANI (digit string) or CallID"
	echo -e "\t-N ANI|id:CallID       find a call with From/To header matching to ANI (digit string) or to CallID"
	echo -e "\t-I str1,str2,str3,...  Include only SIP requests matching with string, eg. -I INFO,ev:reg,ev:pres"
	echo -e "\t-X str1,str2,str3,...  eXclude SIP requests matching with string eg. -X ev:pres,OPTIONS,ev:ccs-pro"

	echo -e "\t-f [1,2,3]\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
	echo -e " Note: -I/-X option supports these SIP methods: INFO,NOTIFY,OPTIONS,PONG,PUBLISH,REGISTER,SUBSCRIBE,UPDATE"
	echo -e "\tas well as events for PUBLISH/NOTIFY messages: ev:pres(ence), ev:dia(log), ev:reg, ev:ccs(-profile),"
	echo -e "\tev:cm-feat(ure-status), ev:cc-info, ev:message(-summary), ev:conf(erence), ev:ref(er), ev:scr(een),"
	echo -e "\tev:ua(-profile) and ev:push(-notification)"
	echo ''	
} # usage()

function reset_sipmsg () {
	partnum="00"; maxpart="99"; currpartnum="555";	sipsplit=0
	insidesip=0;  sipstart=0; 	dirdefined=0;		embedded=0
	siplines=0;   base64found=0;  badmsg=0
	emptyline=0;  foundipaddr=""; ip=""

	sipdate="";			siptime="";		sipyear=""
	linebuf=""; 		linebuf64=""
	prevcseq=$currcseq;	prevsipword=$sipword
	sipword="";			cseqword="";	currcseq=0
	prevline="notempty"; notifyrefer=0;	sipnotify=0	
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then	
	sipstart=1
	sipword=$(cut -d' ' -f1 <<< "$line" | sed -e 's/[[:space:]]*$//' | tr -d "\r")
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
			if [[ $((sipmsg)) == 1 ]]; then
				firstmsg=$lastmsg;	timefirst=$timelast
			fi
			if [[ $sipwordlist != *$sipword* ]]; then
				if [[ $sipwordlist == "" ]]; then
					sipwordlist="$sipword"
				else
					sipwordlist="$sipwordlist | $sipword"
				fi
			fi
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

		if [[ $((sipsplit)) != 0 ]]; then
			sipmaxsplit=$((sipmaxsplit+1))
			if [[ $maxpart == "99" ]] || [[ $partnum == "00" ]]; then
				echo -e "\nerror: SIP msg was split but found invalid partnum=$partnum or maxpart=$maxpart in msg#$sipmsg at $siptime"
				echo "nlines=$nlines vsyslog=$vsyslog - Contact developer.\n"

			elif [[ $maxpart != "99" ]]; then
				splitparts=$((splitparts+10#$maxpart-1))
				if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
					sipmaxpart=${maxpart#0}
					sipmaxpartmsg=$sipmsg
					if [[ $dirdefined == 1 ]]; then
						sipmaxpartsipword="RX $sipword"
					elif [[ $dirdefined == 2 ]]; then
						sipmaxpartsipword="TX $sipword"
					fi
				fi
				if [[ $partnum != $maxpart ]]; then
					badmsg=1
				fi
			else
				splitparts=$((splitparts+1))				# this will increase number of parts, but we do not know how many parts were actually seen in this sip msg		
			fi
		elif [[ $partnum != "00" ]]; then
			echo -e "error: SIP msg was not split but found invalid partnum=$partnum in msg#$sipmsg at $siptime"
			echo "nlines=$nlines vsyslog=$vsyslog - Contact developer.\n"
		fi

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
						echo -e "# msgno: $sipmsg (split x$maxpart, embedded) - Base64dump found" >> "$newfile"
					else
						echo -e "# msgno: $sipmsg (split x$maxpart) - Base64dump found" >> "$newfile"
					fi
				elif [[ $embedded != 0 ]]; then
					echo -e "# msgno: $sipmsg (split x$maxpart, embedded)" >> "$newfile"
				else
					echo -e "# msgno: $sipmsg (split x$maxpart)" >> "$newfile"
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

		if [[ $((sipstart)) == 1 ]] && [[ $((vsyslog)) -le 12 ]]; then
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
		sipstart=0; n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted             \r"
			else
				echo -en "$var => $n/$rec Msgs converted                  \r"
			fi
		fi
	fi
elif [[ $bDebug == 0 ]]; then
	echo -e "\nerror: sipmsg_header() was called with \$dirdefined=0 at msgno: $((n+1)) at $sipdate $siptime. Contact developer.\n"
	exit 1
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
			sipsplit=1
		elif [[ $currpartnum == "00" ]]; then								# new SIP msg split, but does not start with 01 - BAD
			currpartnum="660"
		elif [[ ${partnum#0} -gt ${maxpart#0} ]]; then
			currpartnum="666"
		elif [[ ${partnum#0} != $((${currpartnum#0}+1)) ]]; then
			currpartnum="663"
		elif [[ $((sipsplit)) != 0 ]]; then
			sipsplit=2
		else
			sipsplit=1
		fi
	else
		currpartnum="555"		
	fi
} # sip_partnum()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line =~ Inbound\ SIP|^RX|RECEIVED ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac
		if [[ $line =~ ^RX ]]; then ip="6.6.6.6:6666"; fi

	elif [[ $line =~ Outbound\ SIP|^TX|SENT|SENDING ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
		if [[ $line =~ ^TX ]]; then ip="6.6.6.6:6666"; fi
	else
		echo -e "\nerror: direction of message could not be determined at msgno: $sipmsg. Contact developer.\n"
		echo $line
	    reset_sipmsg
	fi

	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $foundipaddr == "" ]]; then
			case $vsyslog in
			9) 	foundipaddr=$(cut -d' ' -f6 <<< "$line"    | tr -d "\r\n")
				localip="$foundipaddr:1111";;
			10) foundipaddr=$(cut -d' ' -f1 <<< "$line"    | tr -d "\r\n")
				localip="$foundipaddr:1111";;
			11)	localip="1.1.1.1:1111";;
			12)	localip="1.1.1.1:1111";;
			*)	foundipaddr=$(awk '{print $4}' <<< "$line" | tr -d "\r\n")
				localip="$foundipaddr:1111";;
			esac
		fi

		case $vsyslog in
		1)	if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")
				ip=$ip1:$ip2
			elif [[ $line == *"bound SIP message "* ]]; then
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")
				ip=$ip1:$ip2
			fi;;
		
		2|3) if [[ $line =~ port: ]]; then  # 96x1/J1xx prints Inbound SIP message line in / from ip = a.b.c.d port: X/ format
				ip=$(awk -F" from ip = " '{print $2}' <<< "$line")
				ip1=$(cut -d' ' -f1 <<< "$ip")
				ip2=$(awk '{printf "%i",$3}' <<< "$ip")				# cut -d' ' -f3  | tr -d "\n")
				ip=$ip1:$ip2
			else
				ip=$(awk '{print $NF}' <<< "$line")
				ip1=$(cut -d':' -f1 <<< "$ip")
				ip2=$(awk -F":" '{printf "%i",$2}' <<< "$ip")	#cut -d':' -f2  | tr -d "\n")
				ip=$ip1:$ip2					
			fi;;
		6)
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
			fi;;
		7)
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
			fi;;
		8)
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
			fi;;
		9)
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
			fi;;
		10)
			ip1=$(awk '{printf "%i",$3}' <<< "$line")			# cut -d' ' -f3 | tr -d "\r")	# TODO: ANB missing port
			ip2="5061"
			ip=$ip1:$ip2;;
		11)
			ip=$(awk '{print $8}' <<< "$line" | sed -e 's/\.$//g')	# cut -d' ' -f10)
			siplength=$(awk '{printf "%i",$NF}' <<< "$line")		
			ip1=$(cut -d':' -f1 <<< "$ip")
			ip2=$(cut -d':' -f2 <<< "$ip" | cut -d'.' -f1)			
			ip=$ip1:$ip2;;
		12)
			ip=$(awk '{print $7}' <<< "$line" | sed -e 's/\.$//g')	# cut -d' ' -f10)
			siplength=$(awk '{printf "%i",$4}' <<< "$line")
			ip1=$(cut -d':' -f1 <<< "$ip")
			ip2=$(cut -d':' -f2 <<< "$ip" | cut -d'.' -f1)			
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
			fi;;
		esac
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
		echo -e "\nerror: found non-english MONTH: $month at line#$nlines / $siptime - Contact developer.\n"
		echo -e "Line=\n$line"; echo ''; exit 1
	fi
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line" | tr -d "\r\n")
		fi
	fi
} # get_useragent()

function get_useragent3 () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		useragent=$(egrep -m 1 "^User-Agent" <<< "$linebuf" 2>/dev/null)
#		useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$useragent" | tr -d "\r\n")
	fi
} # get_useragent3()

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
	if [[ $line == "" ]]; then
		sipdate="N/A"; siptime="A/N"
	else case $vsyslog in
	1)		 											# syslog UDP stream from wireshark
#		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(awk '{print $4}' <<< "$line" | tr -d "\r\n")
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
		siptmp=$(awk '{print $6}' <<< "$line");;
# echo datetime: year=$sipyear month=$month day=$sipday hour=$siphour min=$sipmin sec=$sipsec
# echo $line
	11)
	if [[ $line =~ DBH: ]] && [[ ${line:0:1} == '[' ]]; then												# 1XC
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

	12)
	if [[ $line =~ \]\ R|SE ]]; then																		# ACiOS
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

	20)					 								 ## KIWI syslog aka SyslogCatchAll
#		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(awk '{print $4}' <<< "$line" | tr -d "\r\n")
			sipyear=$(cut -d' ' -f1 <<< "$line")						# | cut -d'-' -f1)	# awk -F'-' '{print $1}')
			if [[ $bIgnoreMonth == 0 ]]; then
				sipmonth=$(cut -d'-' -f2 <<< "$sipyear")				# awk -F'-' '{print $2}')
			fi
			sipday=$(cut -d'-' -f3 <<< "$sipyear")						# awk -F'-' '{print $3}')			
			sipyear=$(cut -d'-' -f1 <<< "$sipyear")
#		fi

		siphour=$(awk '{print $7}' <<< "$line")
		sipmin=$(cut -d':' -f2 <<< "$siphour") 					# awk -F ':' '{print $2}')
		sipsec=$(cut -d':' -f3 <<< "$siphour") 					# awk -F ':' '{print $3}')
		siphour=$(cut -d':' -f1 <<< "$siphour") 				# awk -F ':' '{print $1}')
		sipmsec=$(awk '{print $12}' <<< "$line")
		siptmp=$(awk '{print $10}' <<< "$line");;
		esac
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
		echo -e "\n\ndebug: multiple SIP message at line#$nlines found at $siptime and notiref=$notifyrefer\n"
		echo $line	
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
#	partnum="00"; maxpart="99";	currpartnum="555"
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
			if [[ $((vsyslog)) == 11 ]] && [[ ${line:0:1} == "[" ]]; then
				line=$(cut -d' ' -f2- <<< "$line")
			fi
			sipmsg_header	
			start_sipmsg
			sipstart=2

		elif [[ $((sipstart)) == 2 ]]; then
			if [[ $line == *"}"* ]]; then
				explore_sipmsg
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
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

function convert_EndpointLog () {
while IFS= read -r line
do
#	linelength=${#line}
	nlines=$((nlines+1))

# if [[ $((n)) -gt 12 ]]; then
#	break
# fi

	if [[ $line == *" SIPMESSAGE: "* ]]; then
		if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
			continue
		elif [[ $((sipstart)) != 0 ]] && [[ $line == *" End of "* ]]; then			# 1xAgent special line
			explore_sipmsg
		fi

#		if [[ $((vsyslog)) == 1 ]] && [[ $((sipstart)) != 0 ]]; then
		if [[ $((sipstart)) != 0 ]]; then
			if [[ $((sipsplit)) == 0 ]]; then
				explore_sipmsg			
#			elif [[ $line =~ [MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			elif [[ $line =~ Part\  ]]; then
# echo -e "\nNew part: $line"
# echo partnum=$partnum maxpart=$maxpart		
				if [[ $line =~ ^\<16[3-7]\> ]]; then
					dummy=0																				# dummy statement
				elif [[ $((vsyslog)) == 1 ]] || [[ $((vsyslog)) == 20 ]]; then
					if [[ $line =~ .*\<16[3-7]\> ]]; then
						xline=$(awk -F"<16[3-7]>" '{print $1}' <<< "$line")
						line=$(awk -F"<16[3-7]>"  '{print $2}' <<< "$line")
# echo -e "\nSTICK1 msgno#$sipmsg prevline=$prevline line=$line"
						if [[ $prevline =~ \;$ ]] || [[ $line =~ ^[^A-Z] ]]; then
							linebuf="$linebuf$line"
						elif [[ $linebuf == "" ]]; then
							linebuf="$xline"
						else
							linebuf="$linebuf\r\n$xline"
						fi
						prevline="$xline"
					elif [[ $line =~ \ [JFMASOND][[:lower:]][[:lower:]]\  ]]; then
						xline=$(awk -F " [JFMASOND][[:lower:]][[:lower:]] " '{print $1}' <<< "$line")
						line=$(awk -F " [JFMASOND][[:lower:]][[:lower:]] "  '{print $2}' <<< "$line")
# echo -e "\nSTICK2 msgno#$sipmsg prevline=$prevline line=$line"
						if [[ $prevline =~ \;$ ]] || [[ $line =~ ^[^A-Z] ]]; then
							linebuf="$linebuf$line"
						else
							save_sipline
						fi
						prevline="$xline"
					fi

#				elif [[ $((vsyslog)) == 1 ]] && [[ $line =~ \ [JFMASOND]..?[cglnprtyv]\  ]]; then
#					echo "$line" | awk -F " [JFMASOND]..?[cglnprtyv] " '{print $1}' >> "$newfile"
#					line=$(awk -F " [JFMASOND]..?[cglnprtyv] " '{print $2}' <<< "$line")
#					siplines=$((siplines+1))
				fi
#				line=$(echo "$line" | awk -F "[MTWFS][orehau][neduitn]\ [JFMASOND][[:lower:]][[:lower:]]\ " '{print $1}')
				if [[ $partnum == $maxpart ]]; then
					explore_sipmsg				
				fi
			else
				explore_sipmsg
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
				badmsg=1
				explore_sipmsg				
#				complete_sipmsg
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
			insidesip=1
			get_sip_datetime
			siptotalmsg=$((siptotalmsg+1))

			if [[ $((sipsplit)) == 0 ]]; then										# ALERT: split messages may write In/Outbound message into next line !!!
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
		if [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
			explore_sipmsg		
#			complete_sipmsg
		fi
	elif [[ $((vsyslog)) == 20 ]] && [[ $line =~ Local[0-9] ]]; then
		if [[ $((sipstart)) == 0 ]]; then
			continue
		elif [[ $((sipsplit)) == 0 ]] || [[ $partnum == $maxpart ]]; then
			explore_sipmsg		
#			complete_sipmsg
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
				line=$(awk -F "RX |TX " '{print $2}' <<< "$line")
#				if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
#					nINFO=$((nINFO+1))
#					reset_sipmsg;
#					continue
#				else
	                insidesip=3
					sipmsg_header
					start_sipmsg			
#				fi
			fi
#		  fi
		else
			echo -e "\nALERT: could not determine SIP msg direction at line#$nlines at $siptime - Contact developer."
			echo -e "line=\n$line"; exit 1
		fi

	elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $line =~ RX\ |TX\  ]]; then		
			line=$(awk -F "TX |RX " '{print $2}' <<< "$line")
            insidesip=3
			sipmsg_header
			start_sipmsg							
		fi

	elif [[ $((sipstart)) != 0 ]] && [[ ${#line} != 0 ]]; then
		sipline=$(egrep -c "<16[3-7]>" <<< "$line")
		if [[ $((sipline)) -gt 0 ]]; then
			##if [[ $line == *" SIPMESSAGE: "* ]]; then
			line=$(awk -F "<16[3-7]>" '{print $1}' <<< "$line")
			if [[ ${#line} != 0 ]]; then
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
				elif [[ $((sipsplit)) == 2 ]]; then
					if [[ $line =~ xml\ version= ]] && [[ ${#line} -gt 80 ]]; then
						line=$(sed 's/>\s*</>\n</g' <<< "$line" | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g')						
					fi
					linebuf="$linebuf$line"
					prevline="$line"						
					sipsplit=1
				else
					save_sipline
					prevline="$line"						
				fi					
			fi

			if [[ $((sipsplit)) == 0 ]]; then
				explore_sipmsg				
#				complete_sipmsg
			fi

		elif [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then	# due to ANB exception observed in r4.1.1 (multiple SIP msg in the same RX SIPMESSAGE)
#		elif [[ $dirdefined == 1 ]] && [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then	# it can occur only in RX direction
			if [[ ! $line =~ ^GUID= ]]; then
				multi_sipmsg
			fi

		elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
			base64found=1
#			echo "# Base64 dump found" >> "$newfile"
		elif [[ $((base64found)) != 0 ]] && [[ $line != "" ]]; then
			if [[ $linebuf64 == "" ]]; then
				linebuf64="$line"
			else
				linebuf64="$linebuf64$line"
			fi
		elif [[ $((sipsplit)) == 2 ]]; then
			if [[ $line =~ xml\ version= ]] && [[ ${#line} -gt 80 ]]; then
				line=$(sed 's/>\s*</>\n</g' <<< "$line" | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g')						
			fi
			linebuf="$linebuf$line"
			prevline="$line"			
			sipsplit=1
		else
			save_sipline
			prevline="$line"
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

	targetX=""; targetX=$(ls -t1 EndpointLog_prev.tx* 2>/dev/null)							# TODO: eLux has strange character in EndpointLog_prev.txt filename: EndpointLog_prev.txt▓í
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		targetX=$(head -1 <<< $targetX)
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
#			targetfiles=$(awk '{print $NF}' <<< "$targetfiles")
			targetfiles=${targetfiles##* }		# last word
			targetfiles=${targetfiles%% *}		# first word
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

	elif [ -d "setup/elux/.workplace-vdi/logs" ]; then									# TODO: what was the folder name on eLux for Equinox VDI or VDI-C?
		destdir="$destdir/setup/elux/.workplace-vdi/logs"
		cd "setup/elux/.workplace-vdi/logs"

	elif [ -d "setup/eLux/.equinox-vdi/logs" ]; then
		destdir="$destdir/setup/eLux/.equinox-vdi/logs"
		cd "setup/eLux/.equinox-vdi/logs"

	elif [ -d "setup/elux/.equinox-vdi/logs" ]; then
		destdir="$destdir/setup/elux/.equinox-vdi/logs"
		cd "setup/elux/.equinox-vdi/logs"

	elif [ -d "setup/eLux/.vdi-communicator/logs" ]; then
		destdir="$destdir/setup/eLux/.vdi-communicator/logs"
		cd "setup/eLux/.vdi-communicator/logs"

	elif [ -d "setup/elux/.vdi-communicator/logs" ]; then
		destdir="$destdir/setup/elux/.vdi-communicator/logs"
		cd "setup/elux/.vdi-communicator/logs"

	elif [ -d "home/eLux/.workplace-vdi/logs" ]; then
		destdir="$destdir/home/eLux/.workplace-vdi/logs"
		cd "home/eLux/.workplace-vdi/logs"

	elif [ -d "home/elux/.workplace-vdi/logs" ]; then
		destdir="$destdir/home/elux/.workplace-vdi/logs"
		cd "home/elux/.workplace-vdi/logs"

	elif [ -d "home/eLux/.equinox-vdi/logs" ]; then
		destdir="$destdir/home/eLux/.equinox-vdi/logs"
		cd "home/eLux/.equinox-vdi/logs"

	elif [ -d "home/elux/.equinox-vdi/logs" ]; then
		destdir="$destdir/home/elux/.equinox-vdi/logs"
		cd "home/elux/.equinox-vdi/logs"

	elif [ -d "home/eLux/.vdi-communicator/logs" ]; then
		destdir="$destdir/home/eLux/.vdi-communicator/logs"
		cd "home/eLux/.vdi-communicator/logs"

	elif [ -d "home/elux/.vdi-communicator/logs" ]; then
		destdir="$destdir/home/elux/.vdi-communicator/logs"
		cd "home/elux/.vdi-communicator/logs"

	elif [ -d "eLux/.workplace-vdi/logs" ]; then
		destdir="$destdir/eLux/.workplace-vdi/logs"
		cd "eLux/.workplace-vdi/logs"

	elif [ -d "elux/.workplace-vdi/logs" ]; then
		destdir="$destdir/elux/.workplace-vdi/logs"
		cd "elux/.workplace-vdi/logs"

	elif [ -d "eLux/.equinox-vdi/logs" ]; then
		destdir="$destdir/eLux/.equinox-vdi/logs"
		cd "eLux/.equinox-vdi/logs"

	elif [ -d "elux/.equinox-vdi/logs" ]; then
		destdir="$destdir/elux/.equinox-vdi/logs"
		cd "elux/.equinox-vdi/logs"

	elif [ -d "eLux/.vdi-communicator/logs" ]; then
		destdir="$destdir/eLux/.vdi-communicator/logs"
		cd "eLux/.vdi-communicator/logs"

	elif [ -d "elux/.vdi-communicator/logs" ]; then
		destdir="$destdir/elux/.vdi-communicator/logs"
		cd "elux/.vdi-communicator/logs"

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
		ls -l "target";	cd "$currdir"; return

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
	rec=$(egrep -c -e "CSeq:" "$file")
	rec2=$(egrep -ac "SIPMESSAGE:" "$file" 2>/dev/null)
	sample=$(egrep -a -m 1 "SIPMESSAGE:" "$file" 2>/dev/null)

#	if [[ $rec == 0 ]];	then
#		rec=$(egrep -c -e "CSeq:" "$file" 2>/dev/null)
#	fi				
	if [[ $((rec2)) == 0 ]];	then
		rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)												# 1XC/1XM
		if [[ $((rec2)) != 0 ]]; then
			vsyslog=11
			if [[ $filterI == "" ]] && [[ $filterX == "" ]]; then
   		    	echo "Warning: no conversion would be really required on $basefile."
				echo "You could use this file along with \"traceSM\" as it is."
			fi
			conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			if [[ $? != 0 ]]; then
		    	conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			fi
		else
			rec2=$(egrep -ce "[0-9]\]\ [RS]E.*bytes " "$file" 2>/dev/null)										# ACiOS
			if [[ $((rec2)) != 0 ]]; then
				vsyslog=12
				if [[ $filterI == "" ]] && [[ $filterX == "" ]]; then
       		    	echo "Warning: no conversion would be really required on $basefile."
					echo "You could use this file along with \"traceSM\" as it is."
				fi
				conv=$(awk -W source='/]\ R|SE.*bytes\ /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				if [[ $? != 0 ]]; then
		    		conv=$(awk -e '/]\ R|SE.*bytes\ /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				fi
			fi
		fi

		if [[ $((rec)) == 0 ]] || [[ $((rec2)) == 0 ]]; then
			echo -e "\nerror: No SIP messages have been found in $basefile in the expected format."
			if [[ $((rec)) == 0 ]]; then
				echo "In fact, no sign of any "CSeq:" lines in $basefile"
				error=2
			else
			    echo "Though, found $rec lines with \"CSeq:\" - so there might be some SIP messages within $basefile"
				rec=0; error=3
			fi
			asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)
			if [[ $((asmfile)) != 0 ]]; then
				asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
				if [[ $((asmfile)) != 0 ]]; then
					echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
					echo "This kind of input is not (yet) supported by this tool."
				fi
			else
				echo "Perhaps this file is not a logfile from VDIC client...(or 1XA client or H175 phone)."
				echo -e "Or, debug (INFO) loglevel was not enabled - Verify source and content of $basefile\n"
				egrep -m 2 "Logging level" "$file" 2>/dev/null
			fi
			echo ''

			if [[ $input != "" ]] && [ -d "$input.tmp" ] && [ -s "$input.tmp/../configcache.xml" ]; then
				echo "Verifying logging configuration in configcache.xml:"
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG" "$input.tmp/../configcache.xml" 2>/dev/null
	 		elif [[ $folder != "" ]] && [ -s "$folder/../configcache.xml" ]; then
				echo "Verifying logging configuration in configcache.xml:"
				echo "configcache.xml (46xxsettings.txt or local admin menu) includes:"
				egrep -A 1 "LOGSRVR|SYSLOG|LOG_CATEGORY|LOCAL_LOG" "$folder/../configcache.xml" 2>/dev/null
			fi

			if [[ $input != "" ]] && [ -d "$input.tmp" ] && [ -s "$input.tmp/../config.xml" ]; then
				echo "Verifying logging configuration in config.xml:"
				egrep -A 1 "LocalLogLevel|LogCategoryList|LogLevel|LogServer|Verbosity" "$input.tmp/../config.xml" 2>/dev/null
			elif [[ $folder != "" ]] && [ -s "$folder/../config.xml" ]; then
				echo "Verifying logging configuration in config.xml:"
				egrep -A 1 "LocalLogLevel|LogCategoryList|LogLevel|Logserver|Verbosity" "$folder/../config.xml" 2>/dev/null
			fi
		fi

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
			if [[ $sample2 =~ SIPMESSAGE: ]]; then
				vsyslog=1
				##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
        		conv=$(awk -W source='/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				if [[ $? != 0 ]]; then
        			conv=$(awk -e '/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
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

		elif [[ $sample =~ Local4.Info|Local4.Debug ]] && [[ $sample =~ \<010\> ]]; then		# KIWI syslog
#			sample=$(echo $sample | awk '{print $6}')
			vsyslog=20
			input2="$file"
			sed 's/<013><010>/\n/g' "$file" | sed 's/<010>/\n/g' | sed 's/<013>/\n/g' > "$file.kiwi"
			file="$file.kiwi"; tmpfile=2
			sample=$(egrep -m 1 "SIPMESSAGE:" "$file")
			if [[ $sample =~ SIPMESSAGE: ]]; then		
	    	    conv=$(awk -W source='/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				if [[ $? != 0 ]]; then
    		    	conv=$(awk -e '/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				fi
			else
				error=2; echo -e "\nerror: no SIPMESSAGE found in $file. vsyslog=$vsyslog"
				echo "Verify source and content of $bvar.\n"
			fi

		elif [[ $sample =~ :\ INFO ]]; then
			sample2=$(awk -F": INFO    : " '{print $2}' <<< $sample)
			if [[ $sample2 =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				egrep "SIPMESSAGE" < "$file" | awk -F": INFO    : " '{print $2}' > "$file.syslog"			# H175/log35.txt
				file="$file.syslog"; tmpfile=2
				if [[ ${#sample} -lt 160 ]]; then
					vsyslog=175															# TODO find a logfile which meets this scenario
		    	    conv=$(awk -W source='/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					if [[ $? != 0 ]]; then
    			    	conv=$(awk -e '/ SIPMESSAGE: /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					fi
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
		lastfoundip="";	foundipaddr=""
		n=0;			nlines=0;		sipmaxlines=0
		sipyear=0;		sipmonth=0;		sipday=0
		siphour=0;		sipmin=0;		sipmsec=0
		siptime="";		prevsiptime=""
		sipmsg=0;		siptotalmsg=0; 	longestmsg=0
		sipbadmsg=0;	sipbadtimemsg=""
		sipbadmsgnum="";sipbadtime=0
		sipwordlist="";	longestsipword=""		
		sipmaxpart=0;	sipmaxpartmsg=0;sipmaxsplit=0; 		sipmaxpartsipword=""
		splitin=0; 		splitout=0; 	splitparts=0		
		firstmsg="";	lastmsg=""
		timefirst="";	timelast=""
		sipin=0;		sipout=0
		nPONG=0;		embedded=0
		callID="";		calltime="";	callDIR=0
		callidtime1="";	callmsgnum1=0;	callidword1=""
		callidtime2="";	callmsgnum2=0;	callidword2=""
		nINFO=0;		infoin=0;		infoout=0
		notpassed=0; 	notpassedin=0; 	notpassedout=0

		useragent="";	server=""; 		serverip=""; 	serverua="";
		scua="";		scip=""
		multimsg=0; 	multimsgin=0;	multimsgout=0
		notifyrefer=0; 	sipnotify=0;	prevline="notempty"

		prevINFOseq=""
		prevNOTIFYseq="";	prevNOTIFYcallid=""		
		prevPUBseq="";		prevPUBcallid=""
		prevSUBseq1=""; 	prevSUBcallid1=""
		prevSUBseq2="";		prevSUBcallid2=""
		prevSUBseq3="";		prevSUBcallid3=""
		prevSUBseq4="";		prevSUBcallid4=""				

		evdialog=0; evccinfo=0; evreg=0; evcmfeat=0; evmsgsum=0
		evunknown=0; evpush=0; evscrupd=0; evrefer=0; evccs=0; evconf=0; evuaprof=0

		reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then
			echo "Warning: about to convert a logfile with $rec SIP messages"
			echo -e "This may take a while... you may want to execute this script on a more powerful PC or server.\n"
		fi

		if [[ $bFilterSIP != 0 ]]; then
			line=""; tempfile="$file.sipmsg"
			touch "$tempfile"			
			echo Filtering SIPMESSAGE out from "$file" into "$tempfile" ...

			while IFS= read -r line
			do
			    if [[ $line =~ SIPMESSAGE: ]]; then
    	    		foundSIP=1
			        echo "$line" >> "$tempfile"
		    	elif [[ $foundSIP != 0 ]]; then
		        	if [[ $line =~ SIPMESSAGE: ]]; then
        		    	echo "$line" >> "$tempfile"        
		    	    elif [[ $line =~ \.TEL\ \| ]]; then
    		        	foundSIP=0
			        else
        		    echo "$line" >> "$tempfile"
        			fi
	    		fi
			done < "$file"
	
			line=""; file="$tempfile"; tmpfile=2
		fi

		check=$(egrep -c -e "<1[36][34567]>" "$file" 2>/dev/null)
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
		
		bakfile=""; output=""; 	bfile=""; xfile=""

		if [[ $basefile != "" ]] && [[ $basefile == *"."* ]]; then
			bfile=${basefile%.*}
		fi

		if [[ $var != $basefile ]] && [[ $basefile != $file ]]; then
#			xfile=$(echo "${var%%.*}")
#			xfile=${var%%.*}
			xfile=$(basename "$var")
#			xfile=${xfile%%.*}
#			zfile=${basefile%%.*}
			if [[ $bvar == $basefile ]]; then
				output="$basefile"
			elif [[ $xfile != "" ]] && [[ $xfile != $basefile ]]; then
				output="$xfile-$basefile"
			else
				output="$var"
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

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $output.asm\n" >> "$newfile"
		fi

# if [ -f oisjdfoisjdf ]; then
		case $((vsyslog)) in
 		1|20) 	convert_EndpointLog;;
		11|12)	convert_1xc;;
# 		20)		convert_syslog_mega;;					# KIWI syslog? 175?
		esac
# fi

		if [[ $((sipstart)) != 0 ]]; then
			explore_sipmsg
#			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi
		
		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error\n\n"

		elif [[ $((sipmsg)) -lt 1 ]]; then
			echo -e "\nError: No SIP messages have been found in $basefile. Contact developer."
			convlines=$(wc -l <<< "$conv")
			if [[ $((convlines)) -lt 2 ]]; then
				echo "\$conv variable has less than 2 lines.  Possibly run into Ubuntu 'awk' issue."
				echo "Use 'cygwin' or other linux environment instead of Ubuntu.  Contact developer."
			fi

        elif [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo -e "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm\n"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $bvar\n"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo -e "    have been converted for addr=$endptaddr into $output.asm\n"
				fi
			fi

			if [[ $useragent != "" ]]; then
				if [[ $useragent == *"Avaya Workplace VDI"* ]]; then
					xagent=""; xagent=$(egrep -m 1 "avaya.firmware=" "$file" | awk -F"avaya.firmware=" '{print $2}' | cut -d'"' -f2)
					if [[ ${#xagent} -lt 2 ]]; then
						xagent=$(egrep -m 1 "avaya.firmware\"> " "$file" | awk -F'avaya.firmware"> ' '{print $2}' | cut -d'"' -f2)
						if [[ ${#xagent} -gt 2 ]]; then
							useragent="User-Agent: $xagent"
						fi
					else
						useragent="User-Agent: $xagent"
					fi
				fi

				if [[ $lastfoundip != "" ]] && [[ $lastfoundip != "0.0.0.0" ]]; then
					lastfoundip=$(sed -e 's/\.$//g' <<< $lastfoundip)				
					printf "\t%-49s ip.addr == %s\n" "${useragent:0:49}" "$lastfoundip"
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
					serverip=""; server=$(egrep -m 1 -e "^Server:" "$newfile" | tr -d "\r\n")				
				fi
				if [[ $server != "" ]]; then
					serverip=$(sed -e 's/\.$//g' <<< $serverip)
#					if [[ $input != "" ]]; then								# && [[ ${#server} -lt 68 ]]; then
					if [[ $serverip != "" ]]; then
						printf "\t%-49s ip.addr == %s\n" "${server:0:49}" "$serverip"
					else
						printf "\t%-68s\n" "${server:0:68}"
					fi
				fi
			fi

			echo -e "\tTotal # of lines digested:\t\t\t  $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t  $siptotalmsg ($sipin/$sipout)"
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
					echo -e "\tPONG messages found:\t\t\t\t  $nPONG"
				fi				
				if [[ $((multimsg)) != 0 ]]; then
					echo -e "\tEmbedded SIP messages:\t\t\t\t  $multimsg ($multimsgin/$multimsgout)"
					echo -e "# Embedded SIP messages:\t\t\t  $multimsg ($multimsgin/$multimsgout)" >> "$newfile"					
				fi
				echo -e "\tLongest SIP message had:\t\t\t  $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had:\t\t\t  $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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
				if [[ $((sipmaxsplit)) != 0 ]]; then			# .log.sipmessages are already re-constructed - do not expect split stat
					echo -e "\tSplit SIP messages (with 2 or more parts):\t  $sipmaxsplit ($splitin/$splitout) parts: $splitparts maxpart: $sipmaxpart msg# $sipmaxpartmsg $sipmaxpartsipword"
					echo -e "\tSplit SIP messages (with 2 or more parts):\t  $sipmaxsplit ($splitin/$splitout) parts: $splitparts maxpart: $sipmaxpart msg# $sipmaxpartmsg $sipmaxpartsipword" >> "$newfile"
				fi
				if [[ $((base64decode)) != 0 ]] && [[ $((base64msg)) != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t  $base64msg"
				fi

				if [[ ${#firstmsg} -lt 11 ]] && [[ ${#lastmsg} -lt 11 ]]; then					
					printf "\tFirst msg: %-10s %s\t  Last msg: %-10s %s\n" "$firstmsg" "$timefirst" "$lastmsg" "$timelast"
				else
					printf "\tFirst msg: %-34s\t  %s\n" "${firstmsg:0:34}" "$timefirst"
					printf "\tLast msg: %-35s\t  %s\n"  "${lastmsg:0:35}"  "$timelast"
				fi

				if [[ $findANI != "" ]] && [[ $callID != "" ]] && [[ $calltime != "" ]]; then
					if [[ $callDIR == 1 ]]; then
					echo -e "\tIncoming call from $findANI at $calltime\t  $callID"
				elif [[ $callDIR == 2 ]]; then
					echo -e "\tOutgoing call to $findANI at $calltime\t  $callID"
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

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t $sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
		else
			echo "Conversion of $file has ended with error code: $error n=$n sipwords=$sipwordlist"
		fi	

		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.3f "$(($((n)) * 1000 / $tmpsec))e-3")
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t  Total spent: $SECONDS sec  Avg. SIP msg/sec: $avgmsg\n"
		else
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t  Time spent: $SECONDS sec\n"
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
  while getopts ":ae:i:hk:bdf:sv:D:FCAN:I:X:" options; do
	case "${options}" in
	h)
		usage; exit 0;;
	A)
		alllogs=1;;
	F)
		bFilterSIP=1;;
    I)
#		noINFO=1;;
		filterI=${OPTARG}
		explore_filters;;
	C)	
		bCAT=1;;
	D)
		filtdate=${OPTARG}
		if [[ -f "$filtdate" ]]; then
			echo "error: -D parameter \"$filtdate\" is an existing file.  Expecting a 4 digit string \"MMdd\" instead. Try again."
			exit 1
		elif [[ ${#filtdate} -ne 4 ]]; then
			echo "error: expecting a 4 digit string \"MMdd\" for -D option instead of \"$filtdate\". Try again."
			exit 1
		elif [[ $filtdate =~ 0[1-9][0-9]{2}|1[012][0-9]{2} ]]; then
			dummy=0
		else
			echo "error: \"MMdd\" for -D option has incorrect value \"$filtdate\". Try again."
			exit 1
		fi;;
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
	X)
		filterX=${OPTARG}
		explore_filters;;
	s)
		sipstat=0;;
	a)	
		conv2asm=1;;		
	b)
		base64decode=0;;
	d)
		bDebug=0;;
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
	v)
		vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 10 ]]; then
			vsyslog=1
		fi;;
    :)
		echo "Error: -${OPTARG} requires an argument."
		usage; exit 0;;
	*)
		echo "Error: -${OPTARG} is an unknown option."
		usage; exit 0;;
	esac
  done
fi

skipper=0
bUnzip=0
bGunzip=0
ctarget=""
origtarget=""
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
		elif [[ $var == "-X"* ]]; then
			skipper=7
		elif [[ $var == "-I"* ]]; then
			skipper=8
		elif [[ $var == "-D"* ]]; then
			skipper=9
		else
			skipper=0
			if [[ $var == "-A" ]]; then
				alllogs=1
			elif [[ $var == "-C" ]]; then
				bCAT=1
			elif [[ $var == "-s" ]]; then
				sipstat=0
			elif [[ $var == "-a" ]]; then	
				conv2asm=1
			elif [[ $var == "-b" ]]; then
				base64decode=0
			elif [[ $var == "-d" ]]; then
				bDebug=0
			fi
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
			smaddr="$var"
		elif [[ $((skipper)) == 4 ]]; then
			vsyslog=${OPTARG}												# TODO: vsyslog=INTEGER($var)
			if [[ $((vsyslog)) -lt 1 ]] || [[ $((vsyslog)) -gt 10 ]]; then
				vsyslog=0
			fi
		elif [[ $((skipper)) == 5 ]]; then
			enckey="$var"
		elif [[ $((skipper)) == 6 ]]; then
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
		elif [[ $((skipper)) == 7 ]] && [[ $filterX == "" ]]; then
			filterX=${OPTARG}
			explore_filters
		elif [[ $((skipper)) == 8 ]] && [[ $filterI == "" ]]; then
			filterI=${OPTARG}
			explore_filters
		elif [[ $((skipper)) == 9 ]] && [[ $filtdate == "" ]]; then
			filtdate=${OPTARG}
		fi
		skipper=0; var=""			
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
	origtarget="$target"

	if [ -d "$var" ]; then
		echo -en "\nExploring content in \"$bvar\" folder ... stand by\n"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
# folder names:  Windows %appdata%\Roaming\Avaya: Avaya Equinox VDI\logs		Avaya Workplace VDI/logs	Avaya VDI Communicator/logs
# .zip with all above
		explore_folders
		cd "$currdir"

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $bvar... stand by\n"
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
					error=7; cd "$currdir"; input=""; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"
				input=""; error=7; cd "$currdir"; continue
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
				cd "$currdir"; input=""; error=8; continue
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

				if [[ $input2 == $zfile ]]; then input2="$input2.uncompressed"; fi
				if [ -d "$input2" ]; then
					input2="$input2-tmp"
					if [ -f "$input2" ]; then
						rm "$input2" 2>/dev/null
					fi
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
						error=7; cd "$currdir"; input=""; continue
					fi
				fi

				mkdir "$input.tmp"
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd "$currdir"; input=""; continue
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
							error=8; cd "$currdir"; input=""; continue
						else
							tar xf $input 2>/dev/null										# TODO verify the exact new filename after gunzip
							if [[ $? != 0 ]]; then
								cd ..; rm -rf "$input.tmp"						
								echo -e "\nerror: failed to uncompress $bfile, using \"tar\" utility.\n"
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
				echo -e "\nerror: unable to uncompress $bvar, \"tar\" utility not found.\n"
				error=1; continue
			fi

		elif [[ $filetype =~ capture ]]; then
			if [[ $filetype =~ tcpdump|pcap ]]; then
		  		line=$(whereis tshark 2>&1)
				tshark --version >/dev/null 2>&1

				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then				
					echo -e "\nerror: unable to locate 'tshark' command."
					echo "'tshark' is required to extract syslog messages from $bvar into text file"
					echo -e "in Ubuntu, you can install it by typing: \"sudo apt install tshark\"\n"
					error=10; filecontent="error"; exit $error
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

	if [[ $((bCAT)) != 0 ]]; then
		if [[ $bSinglefile != 0 ]]; then
			if [[ $origctarget == "" ]]; then
				ctarget="$origtarget.casm"
				if  [ -f "$ctarget" ]; then
					mv "$ctarget" "$ctarget.bak"
				fi
				echo -e "# Concatenating for $var\n" > "$ctarget"
				origctarget="$ctarget"
			else
				ctarget="$origctarget"
			fi
		else
			ctarget="$origtarget.casm"
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
			echo -e "# Concatenating for $var\n" > "$ctarget"
		fi
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
				file="$filelist"
			fi
			IFS=$origIFS
			convert_siplog
		fi
		IFS=$origIFS

	elif [[ "$filelist" != "" ]]; then
#		file=$(awk '{print $1}' <<< "$filelist")		# head -1)
		file=${filelist%% *}
		convert_siplog
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
		if [[ $tmpfile == 2 ]] && [[ $var != $file ]]; then
			if [ -f "$file" ]; then
				rm "$file" 2>/dev/null
			fi
		fi
	fi
done

if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
elif [[ $((converted)) != 0 ]] && [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0