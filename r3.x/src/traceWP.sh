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
sipstat=1
error=0
bCAT=0
alllogs=0
converted=0
bDebug=1
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
bIgnoreMonth=0
filtdate=""
adjusthour=0
base64decode=1
enckey=""
alllogs=0
noINFO=0
findANI=""
findCALLID=""
filterI=""; filterX=""
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

## 0) vantage.log
## 1) from wireshark SYSLOG UDP stream - see ade_vdic_syslog1.txt
## <166>Jan 12 16:43:54 135.105.160.122 SIPMESSAGE: +01:00 2022 562 1 .TEL | 0 [Part 01 of 02]
## 2) created by KIWI Syslog r8.x, default ISO log file format - see EqVDI2-SyslogCatchAll.txt
## 2022-02-08 17:22:43	Local4.Info	135.123.66.134	Feb  8 17:22:43 135.123.66.134 SIPMESSAGE: +01:00 2022 338 1 .TEL | 0 [Part 02 of 02]<010>-id=1<013><010>Content-Length:     0<013>
## challenges: <013><010> } Length is bogus (666), Month is bogus (12)

## H175: 2021-01-29 12:22:32	Local4.Info	10.8.232.36	Jan 29 12:25:09 10.8.232.36 SIPMESSAGE: +01:00 2021 034 1 .TEL | 0 Outbound SIP message to 10.8.12.6:5061<010>TX INVITE sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook SIP/2.0<013><010>From: <sip:2470@smn.rosneft.ru>;tag=6013b855715502b6693p7t1r1q3l5f196nmh5h1k6j6l3o32_F247010.8.232.36<013><010>To: <sip:2470@smn.rosneft.ru;avaya-cm-fnu=off-hook><013><010>Call-ID: 217_6013b855-7fb11eab4692x5j163b5x70316n6p8336jx5m2c32_I247010.8.232.36<013><010>CSeq: 535 INVITE<013><010>Max-Forwards: 70<013><010>Via: SIP/2.0/TLS 10.8.232.36:1026;branch=z9hG4bK217_6013b8559dc2a981w724ais5q1n3k5x385pw2t4z76442_I247010.8.232.36<013><010>Supported: 100rel,eventlist,feature-ref,replaces,tdialog<013><010>Allow: INVITE,ACK,BYE,CANCEL,SUBSCRIBE,NOTIFY,MESSAGE,REFER,INFO,PRACK,PUBLISH,UPDATE<013><010>User-Agent: Avaya H175 Collaboration Station H1xx_SIP-R1_0_2_3_3050.tar<013><010>Contact: <sip:2470@10.8.232.36:1026;transport=tls>;+avaya-cm-line=1<013><010>Accept-Language: ru<013><010>Expires: 30<013><010>Content-Length:     0<013>
## Nov 15 10:41:56 localhost 192.168.202.19 ANDROID: +03:00 2021 000 0 | 11-15 13:41:55.866 D/DeskPhoneServiceAdaptor( 2432): [SIP]:RECEIVED 970 bytes from 192.168.70.104:5061 { - see vantage.log
## 1) Customer Interaction Express (CIE) : chap.log
## 2) Avaya Device Adapter (ADA) : dsa.log
## 3) Experience/Voice Portal : SessionManager.log
## 4) Breeze debug ams.log
## 5) AAC SIP Message Trace : AAC-sipmcDebug.log
## 6) AAC SIP Message Trace : AAC-sip.txt
## 7) AAC SIP Message Trace : AACtraceForWin.log
## 8) iView
## 9) K1xx 
#N ov 15 10:41:56 localhost 192.168.202.19 ANDROID: +03:00 2021 000 0 | 11-15 13:41:55.866 D/DeskPhoneServiceAdaptor( 2432): [SIP]:RECEIVED 970 bytes from 192.168.70.104:5061 { - see vantage.log
## 10) AAM
## 12) Workplace Attendant Server
## 13) Workplace Attendant ClientSDKLog
## 14) MX rolling.sip.log
## 15) CES
## 16) AAWG
## 17) IMX
## 18) SES
## 19) AMS
## 41) MEGA opensipslog/siptrace.log: too dumb - no direction, no keyword
## 42) MEGA debug log (either ProcessSIPMsg > Rx SIP From, or AfSIPProcessor::ProcessNetPacket > Rx SIP From)
## 51) Workplace Windows / EqLync
## 52) Workplace MAC
## 53) Workplace Android - User-Agent: Avaya Communicator Android/3.23.0 (FA-RELEASE68-BUILD.20; CLT-L29)
## 54) AC Android - no empty line after header - User-Agent: Avaya Aura Communicator Android/2.0.0 (FA-GRIZZLYINT-JOB1.218; Nexus 7)
## 55) Workplace iOS Workplace.log
## 56-->65) Workplace iOS SIPMessages, 56=EqiOS 3.0, 65=ACiOS 2.1 [cpcorevt])
## 41) Workplace ClientSDK TestRunner Windows 	: Windows_testapp-log.txt
## 42) ClientPlatform TestRunner				: testrunnerlog.txt
## 43) ClientPlatform TestRunner Android		: testapp_Windows_2023_01_12_17_45.txt
## 44) TestApp Windows: 'testapp-log WIN(1).txt'
## 45) ClientPlatform TestApp Windows			: testapp.txt
## 46) osxSdkTest app							: osxTestAppp_logs.txt
## 47) iosSdkTestApp							: iOSTestApp_logs.txt
## 48) Equinox for MAC  3.2						: userB.zip in test2_logs.zip
## 58) ACios Communicator.log
## 59) 1XC MAC
## 60) Flare Experience (iPad, )
## 63) 1XC Windows
## 64) ACLync
## 65) 1xMobile SIP iOS

function usage ()  {
    echo "traceWP.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceWP.sh [OPTIONS] [<LOG_FILE> | <logReport> | <folder>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the log file for a Communicator/Equinox/Workplace client (any platform)"
	echo -e "\t<logReport>\tor, the logreport itself collected from a softclient (encrypted or unencrypted)"
	echo -e "\t<folder>\ta folder or path including above files eg. \"Avaya\", \"logs\", \"Avaya IX Workplace\""		
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage information (this screen)"
	echo -e "\t-k \t\tset decryption key for debugreport decoding"							
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"	
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converted multiple logfiles)"		
#	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"	
#	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-N ANI|id:CallID       find a call with From/To header matching to ANI (digit string) or to CallID"	
	echo -e "\t-I str1,str2,str3,...  Include only SIP requests matching with string, eg. -I INFO,ev:reg,ev:pres"	
	echo -e "\t-X str1,str2,str3,...  eXclude SIP requests matching with string eg. -X ev:pres,OPTIONS,ev:ccs-pro"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
#	echo -e "\t-v X:\t\t enforce input format to X"
	echo ''
	echo -e " Note: -I/-X option supports these SIP methods: INFO,NOTIFY,OPTIONS,PONG,PUBLISH,REGISTER,SUBSCRIBE,UPDATE"
	echo -e "\tas well as events for PUBLISH/NOTIFY messages: ev:pres(ence), ev:dia(log), ev:reg, ev:ccs(-profile),"
	echo -e "\tev:cm-feat(ure-status), ev:cc-info, ev:message(-summary), ev:conf(erence), ev:ref(er), ev:scr(een),"
	echo -e "\tev:ua(-profile) and ev:push(-notification)"
	echo ''	
} # usage()

function reset_sipmsg () {
	insidesip=0;	sipstart=0;		dirdefined=0
	siplines=0;   	base64found=0;  badmsg=0
	ip="";			ip1="";			ip2=""
	sipdate="";		siptime="";		sipyear=""	
	linebuf=""; 	linebuf64="";	embedded=0
	prevcseq=$currcseq;	prevsipword=$sipword
	sipword="";		cseqword="";	currcseq=0
	notifyrefer=0;	sipnotify=0;	prevline="notempty"	
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
			if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then
				sipmaxlines=$siplines
				longestmsg=$sipmsg
				longestsipword="RX $sipword"
			fi;;
		2)	sipout=$((sipout+1))
			if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then
				sipmaxlines=$siplines
				longestmsg=$sipmsg
				longestsipword="TX $sipword"
			fi;;
		esac

		if [[ $voutput != 3 ]] || [[ $prevsipword != "PONG" && $sipword != "PONG" ]]; then
			if [[ $base64found != 0 ]]; then
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

		if [[ $((vsyslog)) -gt 60 ]] && [[ $((sipstart)) == 1 ]]; then
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
					echo -e "$lineX"    >> "$newfile"	
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
		reset_sipmsg
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
		echo "line=$line"; echo "Contact developer"; exit 1
	else	
		sipstart=0;	n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted                                    \r"
			else
				echo -en "$var => $n/$rec Msgs converted                                         \r"
			fi
		fi
	fi
elif [[ $bDebug == 0 ]]; then
	echo -e "error: sipmsg_header() was called with \$dirdefined=0 at msgno: $sipmsg at $sipdate $siptime. Contact developer.\n"
	exit 1	
fi
} # sipmsg_header() 

function sip_direction () {
# WIN: 2022-04-14 09:01:12.328 D [21480] [CSDK::SIP] SENDING 806 bytes to 62.245.230.55:5061 {
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line =~ \ RECEIVED\  ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED";  dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line =~ \ SENT|\ SENDING ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--";		dirstring2="egress";;
		esac
	else
		sipstream=0
		insidesip=0
		dirdefined=0
	fi

# WIN: 2022-04-14 09:01:12.328 D [21480] [CSDK::SIP] SENDING 806 bytes to 62.245.230.55:5061 {
# WIN: 2022-04-14 09:01:12.437 D [21480] [CSDK::SIP] RECEIVED 308 bytes from 62.245.230.55:5061 {
# MAC: 2021-05-19 20:21:55.431 D [197063044/csdkloop] [CSDK::SIP] SENDING 1807 bytes to 10.200.97.110:5061 {	
# EqA: 2022-01-21 10:35:54,262 DEBUG [CSDKEventLoop] - [SIP] > SENDING 843 bytes to 103.125.140.250:32123 {	
# ACAndroid: 2013-10-02 18:36:00,358 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING: 698 bytes to: 135.124.168.107:5061 {
# ACiOS: V 2016-09-26 14:03:48:423 [cpcorevt] SENDING 1329 bytes to 198.152.66.100:5061 {
# ExpertClient: 2020-04-28 09:29:44.742 D [CSDK::SIP] [TID: 56732]: SENDING 1168 bytes to 135.64.253.72:5061 {	    		

	if [[ $((dirdefined)) != 0 ]]; then
		case $vsyslog in
		50) # ExpertClient exception
   	    	ip=$(cut -d' ' -f11 <<< "$line"); siplength=$(cut -d' ' -f8 <<< "$line");;

# AC 2.1:
# 2013-10-02 18:36:00,358 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING: 698 bytes to: 135.124.168.107:5061 {
# 2013-10-02 18:36:00,525 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > RECEIVED 618 bytes from: tls://135.124.168.107:5061 {
# AC2.0
# 2016-12-02 01:20:40,420 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > RECEIVED 1335 bytes from 212.11.168.145:5061 {
# 2016-12-02 01:20:40,428 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING 1115 bytes to 212.11.168.145:5061 {
	   	53|54) # Android exception
	    if [[ $((vsyslog)) == 54 ]] && [[ $line =~ from: ]]; then			# TODO: verify / find an Android log file for this condition - does not apply for ACAdnroid/logs_app.1.log
            ip=$(awk -F'://' '{print $2}' <<< "$line" | cut -d' ' -f1)		# FOUND: ACAndroid/logs_app.log BINGO
		else
			ip=$(cut -d' ' -f12 <<< "$line"); siplength=$(cut -d' ' -f9 <<< "$line")
		fi;;

		56)	 # EqiOS 3.0
# 2017-02-14 00:05:03:252 [cpcorevt] SENDING 783 bytes to 94.56.88.55:5061 {		
			ip=$(awk '{print $8}' <<< "$line")
		 	siplength=$(cut -d' ' -f5 <<< "$line");;

		41)	# ClientSDK TestRunner Windows
# 2019-07-17 15:47:44.649 [ 6880] Debug SIP: SENDING 993 bytes to 35.194.31.131:5061 {
# 2019-07-17 15:47:44.648 [ 6880] Debug SIP: RECEIVED 658 bytes from 35.194.31.131:5061 {
			if [[ $line =~ \ \[\  ]]; then
				ip=$(awk '{print $11}' <<< "$line")
				siplength=$(cut -d' ' -f8 <<< "$line")
			elif [[ $line =~ \ \[[0-9] ]]; then
				ip=$(awk '{print $10}' <<< "$line")
				siplength=$(cut -d' ' -f7 <<< "$line")
			fi;;

		42)	# ClientPlatform Core TestRunner
			ip=$(awk '{print $10}' <<< "$line")
		 	siplength=$(awk '{print $7}' <<< "$line")
			if [[ $((dirdefined)) == 2 ]] && [[ ! $ip =~ : ]]; then
				ip="$ip:5666"
			fi;;

		43) # Android TestRunner Client SDK
# 17:45:19 DEBUG [SIP] RECEIVED 651 bytes from 10.133.67.24:5061 {
# 12:50:42 PM DEBUG [SIP] RECEIVED 659 bytes from 100.20.91.143:5060 {
# 12:50:42 PM DEBUG [SIP] SENDING 1078 bytes to 100.20.91.143:5060 {
			str=$(cut -d' ' -f3 <<< "$line")
			if [[ $str == "DEBUG" ]]; then
				ip=$(cut -d' ' -f9 <<< "$line")
			 	siplength=$(cut -d' ' -f6 <<< "$line")
			else
				ip=$(cut -d' ' -f8 <<< "$line")
			 	siplength=$(cut -d' ' -f5 <<< "$line")
			fi;;

		44) # Windows TestRunner Client SDK
# 2022-01-24 16:24:41.670 D [26636] [CSDK:SIP] SENDING 830 bytes to 10.133.127.15:5061 {
# 2022-01-24 16:24:41.859 D [26636] [CSDK:SIP] RECEIVED 796 bytes from 10.133.127.15:5061 {
			ip=$(cut -d' ' -f10 <<< "$line")
		 	siplength=$(cut -d' ' -f7 <<< "$line");;

		45) # Windows TestApp Client SDK
# [Jul 22 18:55:07]: RECEIVED 624 bytes from 135.60.87.86:5061 {
# [Jul 22 18:55:07]: SENDING 983 bytes to 135.60.87.86:5061 {
			ip=$(cut -d' ' -f8 <<< "$line")
		 	siplength=$(cut -d' ' -f5 <<< "$line");;

		46) # OSX TestApp Client SDK
# 2016-08-08 12:44:00.888 osxSdkTest[1109:50068] Client log: SIP level=3:  RECEIVED 660 bytes from 100.20.91.143:5060 {
# 2016-08-08 12:44:00.925 osxSdkTest[1109:50068] Client log: SIP level=3:  SENDING 1056 bytes to 100.20.91.143:5060 {
			ip=$(awk '{print $12}' <<< "$line")								# cut -d' ' -f12 <<< "$line")
		 	siplength=$(awk '{print $9}' <<< "$line");;						# cut -d' ' -f9 <<< "$line");;

		47) # iOS TestApp Client SDK
# 12:55:40.977: SIP SdkLogDebug: SENDING 826 bytes to 100.20.91.143:5060 {
# 12:55:41.073: SIP SdkLogDebug: RECEIVED 833 bytes from 100.20.91.143:5060 {
			ip=$(cut -d' ' -f8 <<< "$line")
		 	siplength=$(cut -d' ' -f5 <<< "$line");;

		48) # Equinox for MAC r3.2
# 2017-07-07 17:06:45:658 [com.apple.root.default-qos.overcommit] [CSDK][SIP] SENDING 738 bytes to 135.60.87.85:5061 {
# 2017-07-07 17:06:46:303 [com.apple.root.default-qos.overcommit] [CSDK][SIP] RECEIVED 620 bytes from 135.60.87.85:5061 {
			ip=$(cut -d' ' -f9 <<< "$line")
		 	siplength=$(cut -d' ' -f6 <<< "$line");;

	   	65)  # ACiOS Communicator
# V 2016-09-26 14:03:48:423 [cpcorevt] SENDING 1329 bytes to 198.152.66.100:5061 {		
	     # ip=$(cut -d' ' -f9 <<< "$line")
		 ip=$(awk '{print $9}' <<< "$line")
		 siplength=$(cut -d' ' -f6 <<< "$line");;
#		66)  # 1XSIPIOS
#			ip=$(awk '{print $8}' <<< "$line")								# cut -d' ' -f10)
#			siplength=$(awk '{printf "%i",$NF}' <<< "$line");;
		61|62|63|64|66|67|68|69)  # 1XC, 1XSIPIOS=66
			ip=$(awk '{print $8}' <<< "$line" | sed -e 's/\.$//g')								# cut -d' ' -f10)
			siplength=$(awk '{printf "%i",$NF}' <<< "$line");;
	   	*)	if [[ $line =~ CSDK::SIP ]]; then
				linex=$(cut -d']' -f3 <<< "$line")
	        	ip=$(cut -d' ' -f6 <<< "$linex"); siplength=$(cut -d' ' -f3 <<< "$linex")
	   		else
         		ip=$(cut -d' ' -f10 <<< "$line"); siplength=$(cut -d' ' -f7 <<< "$line")
	   		fi;;
		esac
	elif [[ $bDebug == 0 ]]; then
		echo -e "error: sip_direction() was called where \$dirdefined=$dirdefined. Contact developer.\n"
	fi
fi
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
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

function get_sipmonth () {
   sipmonth="666"  
   case $month in
  "Jan"|"January")	sipmonth="01";;
  "Feb"|"February") sipmonth="02";;
  "Mar"|"March") 	sipmonth="03";;
  "Apr"|"April") 	sipmonth="04";;
  "May") 			sipmonth="05";;
  "Jun"|"June")		sipmonth="06";;
  "Jul"|"July")		sipmonth="07";;
  "Aug"|"August")	sipmonth="08";;
  "Sep"|"September") sipmonth="09";;
  "Oct"|"October")	sipmonth="10";;
  "Nov"|"November") sipmonth="11";;
  "Dec"|"December") sipmonth="12";;
   esac
	if [[ $sipmonth == "666" ]]; then
		echo -e "\nerror: found non-english MONTH: $month - contact developer.\n"
		echo -e "month=$month in line=$line\n"; exit 1
	fi
} # get_sipmonth()

function get_sip_datetime () {
# WIN: 2022-04-14 09:01:12.328 D [21480] [CSDK::SIP] SENDING 806 bytes to 62.245.230.55:5061 {
# MAC: 2021-05-19 20:21:55.431 D [197063044/csdkloop] [CSDK::SIP] SENDING 1807 bytes to 10.200.97.110:5061 {
# EqA: 2022-01-21 10:35:54,262 DEBUG [CSDKEventLoop] - [SIP] > SENDING 843 bytes to 103.125.140.250:32123 {
# iOS: 2021-06-04 15:25:32.169 D [csdkloop] [CSDK::SIP] SENDING 833 bytes to 135.64.253.72:5061 {
# iOS 3.0 2017-02-14 00:05:03:252 [cpcorevt] SENDING 783 bytes to 94.56.88.55:5061 {	
# ACAndroid: 2013-10-02 18:36:00,358 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING: 698 bytes to: 135.124.168.107:5061 {
# ACiOS: V 2016-09-26 14:03:48:423 [cpcorevt] SENDING 1329 bytes to 198.152.66.100:5061 {	
if [[ $line != "" ]]; then
    if [[ $((vsyslog)) == 65 ]]; then 																	# ACiOS exception
		sipday=$(cut -d' ' -f2   <<< "$line")
		sipmsec=$(cut -d' ' -f3  <<< "$line")

		sipyear=$(cut -d'-' -f1  <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
		sipday=$(cut -d'-' -f3   <<< "$sipday")
									
		siphour=$(cut -d':' -f1  <<< "$sipmsec")
		sipmin=$(cut -d':' -f2   <<< "$sipmsec")
		sipsec=$(cut -d':' -f3   <<< "$sipmsec")
		sipmsec=$(cut -d':' -f4  <<< "$sipmsec")

	elif [[ $line =~ SIP\ SdkLogDebug: ]]; then															# ClientPlatform Core Testrunner
# 12:55:40.977: SIP SdkLogDebug: SENDING 826 bytes to 100.20.91.143:5060 {
# 12:55:41.073: SIP SdkLogDebug: RECEIVED 833 bytes from 100.20.91.143:5060 {

		sipmsec=$(cut -d' ' -f1 <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")	
		sipsec=$(cut -d'.' -f1  <<< "$sipsec")			

		sipyear=$(cut -d'/' -f3  <<< "$today")
    	sipday=$(cut -d'/' -f2   <<< "$today")
		sipmonth=$(cut -d'/' -f1 <<< "$today")
	
	elif [[ $line =~ DBG:\ SIP ]] && [[ ${line:0:1} == '[' ]]; then											# ClientPlatform Core Testrunner
# [Mar 12 13:06:23]: DBG: SIP SENDING: 553 bytes to: 99.99.99.99 {
# [Mar 12 13:06:23]: DBG: SIP RECEIVED 569 bytes from: 99.99.99.99:5060 {

	    sipday=$(cut -d']' -f1     <<< "$line" | cut -d'[' -f2)
		month=$(cut -d' ' -f1      <<< "$sipday")

		sipmsec=$(awk '{print $3}' <<< "$sipday")
		siphour=$(cut -d':' -f1    <<< "$sipmsec")
		sipmin=$(cut -d':' -f2     <<< "$sipmsec")
		sipsec=$(cut -d':' -f3     <<< "$sipmsec")

		sipyear=$(cut -d'/' -f3    <<< "$today")
    	sipday=$(awk '{print $2}'  <<< "$sipday")
		sipmsec="000"		
		get_sipmonth		

	elif [[ $line =~ \]:\ [RS]E[CN] ]] && [[ ${line:0:1} == '[' ]]; then											# ClientPlatform Core Testrunner
# [Jul 22 18:55:07]: RECEIVED 624 bytes from 135.60.87.86:5061 {
# [Jul 22 18:55:07]: SENDING 983 bytes to 135.60.87.86:5061 {

	    sipday=$(cut -d']' -f1   <<< "$line" | cut -d'[' -f2)
		month=$(cut -d' ' -f1    <<< "$sipday")

		sipmsec=$(awk '{print $3}' <<< "$sipday")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")

		sipyear=$(cut -d'/' -f3 <<< "$today")
    	sipday=$(awk '{print $2}'  <<< "$sipday")
		sipmsec="000"		
		get_sipmonth		

	elif [[ $line =~ DEBUG\ \[SIP\] ]]; then																# ClientPlatform Core Testrunner Android
# 17:45:18 DEBUG [SIP] SENDING 861 bytes to 10.133.67.24:5061 {
# 17:45:19 DEBUG [SIP] RECEIVED 651 bytes from 10.133.67.24:5061 {

		sipmsec=$(cut -d' ' -f1 <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec="000"		

		sipyear=$(cut -d'/' -f3   <<< "$today")
    	sipday=$(cut -d'/' -f2    <<< "$today")
		sipmonth=$(cut -d'/' -f1  <<< "$today")

	elif [[ $((vsyslog)) -lt 61 ]]; then
# 55: 2024-02-19 11:53:33:724 D [csdkloop] [CSDK::SIP] RECEIVED 454 bytes from 83.68.132.202:5061 {			WP iOS
# 55: 2017-02-10 18:20:39:384 [cpcorevt] RECEIVED 294 bytes from 94.56.88.55:5061 {
# 55: 2022-03-21 08:17:32.669 D [csdkloop] [CSDK::SIP] SENDING 858 bytes to 195.189.232.134:5061 {			WP iOS
		sipday=$(cut -d' ' -f1   <<< "$line")
		sipmsec=$(cut -d' ' -f2  <<< "$line")

		sipyear=$(cut -d'-' -f1  <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
		sipday=$(cut -d'-' -f3   <<< "$sipday")
									
		siphour=$(cut -d':' -f1  <<< "$sipmsec")
		sipmin=$(cut -d':' -f2   <<< "$sipmsec")
		sipsec=$(cut -d':' -f3   <<< "$sipmsec")

		if [[ ${sipmsec:8:1} == '.' ]]; then																		# WP iOS sometime use . sometimes : for msec separation
			sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
			sipsec=$(cut -d'.' -f1  <<< "$sipsec")
		else
			sipmsec=$(cut -d':' -f4  <<< "$sipmsec")
		fi

# 1XC:	 [04/27/2022 20:21:23:545] DBH:     SIGNAL: [be84] SENT to 135.64.253.72:5061. Length= 696.
	elif [[ $line =~ DBH: ]] && [[ ${line:0:1} == '[' ]]; then												# 1XC
	    sipday=$(cut -d' ' -f1   <<< "$line" | cut -d'[' -f2)
		sipyear=$(cut -d'/' -f3  <<< "$sipday")
		sipmonth=$(cut -d'/' -f1 <<< "$sipday")
    	sipday=$(cut -d'/' -f2   <<< "$sipday")
									
		sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d']' -f1)
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d':' -f4 <<< "$sipmsec")

# ACIOS: [2016/09/26 11:37:16:715] SENDING 740 bytes to 198.152.66.101:5061 {
	elif [[ $line =~ DBH ]]; then
	    sipday=$(cut -d' ' -f1   <<< "$line")
		sipyear=$(cut -d'-' -f1  <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
    	sipday=$(cut -d'-' -f3   <<< "$sipday")
									
		sipmsec=$(cut -d' ' -f2 <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1  <<< "$sipsec")

	elif [[ $line =~ \]\ R|SE ]]; then																		# ACiOS
	    sipday=$(cut -d' ' -f1   <<< "$line" | cut -d'[' -f2)
		sipyear=$(cut -d'/' -f1  <<< "$sipday")
		sipmonth=$(cut -d'/' -f2 <<< "$sipday")
    	sipday=$(cut -d'/' -f3   <<< "$sipday")
									
		sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d']' -f1)
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d':' -f4 <<< "$sipmsec")
	fi

	case $vsyslog in
	53|54) # Android exception
		sipmsec=$(cut -d',' -f2 <<< "$sipsec"); 	  sipsec=$(cut -d',' -f1 <<< "$sipsec");;
	56|65)  # ACiOS exception
		sipmsec=$(cut -d':' -f2 <<< "$sipsec"); 	  sipsec=$(cut -d':' -f1 <<< "$sipsec");;
#    *)	if [[ $((vsyslog)) -le 60 ]]; then
#			if [[ $sipmsec != "000" ]]; then
#				sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
#				sipsec=$(cut -d'.' -f1  <<< "$sipsec")
#			fi
#		fi;;
    esac

	case $voutput in
	1)	sipdate="$sipmonth/$sipday/$sipyear"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	2)	sipdate="$sipyear/$sipmonth/$sipday"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	3)	sipdate="$sipday/$sipmonth/$sipyear"
		siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
	esac
else
	echo -e "\nABORT: get_sip_datetime() was called with null string - contact developer.\n"
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

function explore_softclient2 () {
if [[ $file != "" ]] && [ -f "$file" ]; then 
#   sample=$(egrep -m 1 -e "\[CSDK::SIP\]\ " "$file")
    rec2=0; sample=$(egrep -m 1 -e "\[CSDK::SIP\]" "$file" 2>/dev/null)	
    if [[ $sample != "" ]] && [[ $sample =~ \]\ \[TID: ]]; then
# ExpertClient Windows
		vsyslog=50
		rec2=$(egrep -ce "\[CSDK::SIP\]" "$file" 2>/dev/null)	
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		if [[ $? != 0 ]]; then
			conv=$(awk -e '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		fi										

    elif [[ $sample != "" ]] && [[ $sample =~ \[csdkloop\] ]]; then
# EqiOS 3.x  
        vsyslog=55
		rec2=$(egrep -ce "\[CSDK::SIP\]" "$file" 2>/dev/null)
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		if [[ $? != 0 ]]; then
			conv=$(awk -e '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		fi										

    elif [[ $sample != "" ]] && [[ $sample =~ \/csdkloop\] ]]; then
# EqMac 3.x
		vsyslog=52
		rec2=$(egrep -ce "\[CSDK::SIP\]" "$file" 2>/dev/null)		
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		if [[ $? != 0 ]]; then
			conv=$(awk -e '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		fi										

    elif [[ $sample != "" ]] && [[ $sample =~ \[CSDK::SIP\]\ [SR]E ]]; then
# EqWin    
        vsyslog=51
		rec2=$(egrep -ce "\[CSDK::SIP\]" "$file" 2>/dev/null)		
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		if [[ $? != 0 ]]; then
			conv=$(awk -e '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
		fi										

    else
        sample=$(egrep -m 1 -e "\[CSDKEventLoop\]\ \-\ \[SIP\]\ >\ [RS]E" "$file" 2>/dev/null)
#		sample=$(egrep -m 1 -e "\[CSDKEventLoop\]\ \-\ \[SIP\]\ " "$file" 2>/dev/null)						# not sufficient see Workplace/FA-CARRERAINT-JOB1.328_20170111_FlareA-workingndroid_logs.tmp/logs_app.2.log
        if [[ $sample != "" ]] && [[ $sample =~ \[CSDKEventLoop\]\ \-\ \[SIP\]\  ]]; then
# EqA 3.X
            vsyslog=53
			rec2=$(egrep -ce "\[CSDK::SIP\]|\[CSDKEventLoop\]\ \- \[SIP\]\ >\ [RS]E" "$file" 2>/dev/null)			
			conv=$(awk -W source='/\[CSDK::SIP\]|\[CSDKEventLoop\]\ \- \[SIP\]\ >\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			if [[ $? != 0 ]]; then
				conv=$(awk -e '/\[CSDK::SIP\]|\[CSDKEventLoop\]\ \- \[SIP\]\ >\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			fi										

        else
            sample=$(egrep -m 1 -e "\[onLogMessage\]\ >\ [RS]E" "$file" 2>/dev/null)
            if [[ $sample != "" ]] && [[ $sample =~ \[onLogMessage\]\ \>\ [RS]E ]]; then
# AcAndroid 2.0    
          		vsyslog=54
				rec2=$(egrep -ce "\[onLogMessage\]\ >\ [RS]E" "$file" 2>/dev/null)						
				conv=$(awk -W source='/\[onLogMessage\]\ >\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				if [[ $? != 0 ]]; then
					conv=$(awk -e '/\[onLogMessage\]\ >\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
				fi										

            else
                sample=$(egrep -m 1 -e "\[cpcorevt\]\ [RS]E" "$file" 2>/dev/null)
                if [[ $sample != "" ]] && [[ $sample =~ \[cpcorevt\]\ [RS]E ]]; then
# ACiPhone 2.1.x
					if [[ $sample =~ ^V\  ]]; then
                    	vsyslog=65
					else
# EqiOS 3.0					
						vsyslog=56
					fi
					rec2=$(egrep -ce "\[cpcorevt\]\ [RS]E" "$file" 2>/dev/null)																	
					conv=$(awk -W source='/\[cpcorevt\]\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					if [[ $? != 0 ]]; then
						conv=$(awk -e '/\[cpcorevt\]\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
					fi										

                else
					sample=$(egrep -m 1 -e "Debug\ SIP:\ [RS]E" "$file" 2>/dev/null)
					if [[ $sample != "" ]] && [[ $sample =~ SIP: ]]; then
# Windows TestRunner
# User-Agent: Client SDK C++ Test App/4.4 (309.0.0 Build 5595) (BuildNumber; Avaya CSDK; Windows)
                        vsyslog=41
						rec2=$(egrep -ce "Debug\ SIP:\ [RS]E" "$file" 2>/dev/null)						
						conv=$(awk -W source='/\]\ Debug\ SIP:\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
						if [[ $? != 0 ]]; then
							conv=$(awk -e '/\]\ Debug\ SIP:\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
						fi
					else
						sample=$(egrep -m 1 -e "DBG:\ SIP\ [RS]E" "$file" 2>/dev/null)
						if [[ $sample != "" ]] && [[ $sample =~ DBG: ]]; then
# ClientPlatform Core TestRunner
# User-Agent: Avaya Client Platform Core
   	                        vsyslog=42
							rec2=$(egrep -ce "DBG:\ SIP\ [RS]E" "$file" 2>/dev/null)							
							conv=$(awk -W source='/\]:\ DBG:\ SIP\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
							if [[ $? != 0 ]]; then
								conv=$(awk -e '/\]:\ DBG:\ SIP\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
							fi										

						else
							sample=$(egrep -m 1 -e "DEBUG\ \[SIP\]\ [RS]E" "$file" 2>/dev/null)
							if [[ $sample != "" ]] && [[ $sample =~ DEBUG ]]; then
# ClientPlatform TestRunner Android
# User-Agent: Client SDK C++ Test App/4.30 (477.0.0 Build 820) (; Avaya CSDK; Windows)
	   	                        vsyslog=43
								rec2=$(egrep -ce "DEBUG\ \[SIP\]\ [RS]E" "$file" 2>/dev/null)								
								conv=$(awk -W source='/\ DEBUG\ \[SIP\]\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
								if [[ $? != 0 ]]; then
									conv=$(awk -e '/\ DEBUG\ \[SIP\]\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
								fi										

							else
								sample=$(egrep -m 1 -e "\[CSDK:SIP\]\ [RS]E" "$file" 2>/dev/null)
								if [[ $sample != "" ]] && [[ $sample =~ CSDK:SIP ]]; then
# ClientPlatform TestApp Windows
# User-Agent: Client SDK C++ Test App/4.22 (421.0.0 Build 162) (BuildNumber; Avaya CSDK; Windows)
		   	                        vsyslog=44
									rec2=$(egrep -ce "\[CSDK:SIP\]\ [RS]E" "$file" 2>/dev/null)									
									conv=$(awk -W source='/\ \[CSDK:SIP\]\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
									if [[ $? != 0 ]]; then
										conv=$(awk -e '/\ \[CSDK:SIP\]\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
									fi										

								else
									sample=$(egrep -m 1 -e "\]:\ [RS]E" "$file" 2>/dev/null)
									if [[ $sample != "" ]] && [[ ${sample:0:1} == "[" ]] && [[ $sample =~ SENDING|RECEIVED ]]; then
# ClientPlatform TestApp Windows
# User-Agent: Avaya Communicator/Version (BuildNumber; Platform)
		   	                        	vsyslog=45
										rec2=$(egrep -ce "\]:\ [RS]E[CN]" "$file" 2>/dev/null)
										conv=$(awk -W source='/\]:\ [RS]E[CN]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
										if [[ $? != 0 ]]; then
											conv=$(awk -e '/\]:\ [RS]E[CN]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
										fi										

									else
										sample=$(egrep -m 1 -e "log:\ SIP\ level=" "$file" 2>/dev/null)
										if [[ $sample != "" ]] && [[ $sample =~ osxSdkTest ]] && [[ $sample =~ SENDING|RECEIVED ]]; then
# OSX TestApp macos
# User-Agent: Client SDK C++ Test App/3.0 (Custom Build; Windows)
		   	                        	vsyslog=46
										rec2=$(egrep -ce "log:\ SIP\ level=" "$file" 2>/dev/null)										
										conv=$(awk -W source='/log:\ SIP\ level=/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
										if [[ $? != 0 ]]; then
											conv=$(awk -e '/log:\ SIP\ level=/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
										fi										

										else
											sample=$(egrep -m 1 -e "SIP\ SdkLogDebug:" "$file" 2>/dev/null)
											if [[ $sample != "" ]] && [[ $sample =~ SdkLogDebug ]] && [[ $sample =~ SENDING|RECEIVED ]]; then
# iOS TestApp 
# User-Agent: Client SDK C++ Test App/3.0 (Client SDK; Windows)
			   	                        	vsyslog=47
											rec2=$(egrep -ce "SIP\ SdkLogDebug:" "$file" 2>/dev/null)											
											conv=$(awk -W source='/SIP\ SdkLogDebug:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
											if [[ $? != 0 ]]; then
												conv=$(awk -e '/SIP\ SdkLogDebug:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
											fi										

											else
												sample=$(egrep -m 1 -e "\CSDK\]\[SIP\]" "$file" 2>/dev/null)
												if [[ $sample != "" ]] && [[ $sample =~ apple ]] && [[ $sample =~ SENDING|RECEIVED ]]; then
# Equinox for MAC
# User-Agent: Avaya Communicator for Mac/3.2.0.20 (ACMACOS-CAN151-20; MAC OS X)
					   	                        	vsyslog=48
													rec2=$(egrep -ce "\CSDK\]\[SIP\]" "$file" 2>/dev/null)													
													conv=$(awk -W source='/\[CSDK\]\[SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
													if [[ $? != 0 ]]; then
														conv=$(awk -e '/\[CSDK\]\[SIP\]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
													fi										
												else
													sample=$(egrep -m 1 -e "\]\ SENT\ to\ |\]\ RECEIVED\ from\ |\]\ SENDING\ " "$file" 2>/dev/null)
													if [[ $sample != "" ]] && [[ $sample != *"DBH:"* ]]; then
    			     	        						rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for i" "$file" 2>/dev/null)
						                	        	if [[ $rec2 != 0 ]]; then 
# AC iPhone/iPad
   	        						        	        	vsyslog=67
															rec2=$(egrep -ce "\]\ SENT\ to\ |\]\ RECEIVED\ from\ |\]\ SENDING\ " "$file" 2>/dev/null)
															conv=$(awk -W source='/\]\ [RS]E[NC]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
															if [[ $? != 0 ]]; then
																conv=$(awk -e '/\]\ [RS]E[NC]/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
															fi										
														fi
								
													else
				            	    	    			rec2=$(egrep -m 1 -c -e "^User-Agent:.*SIP Communicator" "$file" 2>/dev/null)
		   				                				if [[ $rec2 != 0 ]]; then
# Avaya SIP Communicator/1xSIPIOS
		    		    			                		vsyslog=66													
															rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)
															conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
															if [[ $? != 0 ]]; then
																conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
															fi										

		    	    	    		    		    	else
    		    	    	    		    				rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for MAC" "$file" 2>/dev/null)
	    				    	    		    		    if [[ $rec2 != 0 ]]; then 
# 1XC MAC
    	        			    	    		    		    vsyslog=68
																rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)																
																conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																if [[ $? != 0 ]]; then
   																	conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																fi										

															else
    					        	            	    		rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for Microsoft Lync" "$file" 2>/dev/null)
	    					        	    	    	    	if [[ $rec2 != 0 ]]; then 
# ACLync
    	    					        	    	    	    	vsyslog=64
																	rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)																	
																	conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																	if [[ $? != 0 ]]; then
    																	conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																	fi										

	    	    		            				    		else
#	        	    		            				    		rec2=$(egrep -m 1 -c -e "^User-Agent:.*one-X Communicator.*Windows" "$file" 2>/dev/null)
																	rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)																																			
			            			        				        if [[ $rec2 != 0 ]]; then
# 1XC
	    		            			        				        vsyslog=63
																		conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																		if [[ $? != 0 ]]; then
	    																	conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																		fi										
					        	        			    	        else
    					        	        				            rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Engine.*Windows" "$file" 2>/dev/null)
        					        	        				        if [[ $rec2 != 0 ]]; then
# FlareWin
            					    	            				        vsyslog=62
																			rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)																			
																			conv=$(awk -W source='/DBH:.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																			if [[ $? != 0 ]]; then
	    																		conv=$(awk -e '/DBH:.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																			fi										

    				                			    		        	else
    		    		                			    		        	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Experience.*" "$file" 2>/dev/null)
	        				                		    			        if [[ $rec2 != 0 ]]; then
# FlareExp
	            				                		    			        vsyslog=61
																				rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)																				
																				conv=$(awk -W source='/DBH:.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																				if [[ $? != 0 ]]; then
	    																			conv=$(awk -e '/DBH:.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																				fi										

    			    	                    		    	        		else
        			    	                    		    	    			rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Communicator.*" "$file" 2>/dev/null)
				        		    	                    		    	    if [[ $rec2 != 0 ]]; then 
# FlareComm
    				        		    	    	            		    	    vsyslog=69
																					rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)																					
																					conv=$(awk -W source='/DBH:.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																					if [[ $? != 0 ]]; then
		    																			conv=$(awk -e '/DBH:.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
																					fi
																				fi
																			fi
																		fi
																	fi
																fi
															fi
            	                    	            	fi
													fi
	            	                            fi
											fi
    	                                fi
        	                        fi
                                fi
            	            fi
						fi
                    fi
                fi
            fi
        fi
    fi
else
	echo -e "\nABORT: explore_softclient() was called with invalid file. Contact develoepr.\n"
fi
} # explore_softclient2()

function explore_logfolder() {
	targetfiles=""

	targetX=""; targetX=$(ls -t1 UccLog?.log 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetX != "" ]]; then
		targetfiles="$targetX"
	fi

	targetX=""; targetX=$(ls -t1 UccLog.*.log 2>/dev/null | sort)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")
		else
			targetfiles="$targetX"
		fi
	fi

	sipMSG=1
	targetX=""; targetX=$(ls -t1 Workplace*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		sipMSG=0	
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")
		else
			targetfiles="$targetX"
		fi
	fi

	if [[ $sipMSG != 0 ]]; then
		targetX=""; targetX=$(ls -t1 S[iI][pP]Messages*.log 2>/dev/null)			# ACAndroid r2.1
		if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
			if [[ $targetfiles != "" ]]; then
#				targetfiles="$targetfiles $targetX"
				targetfiles=$(echo -e "$targetfiles\n$targetX")
			else
				targetfiles="$targetX"
			fi
		fi
	fi

	targetX=""; targetX=$(ls -t1 S[iI][pP]Messages?.txt 2>/dev/null)			# ACWin r2.1
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 S[iI][pP]Messages.bak.* 2>/dev/null)			# 1XSIPiOS
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -r -t1 logs_app?.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -r -t1 logs_app.?.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 Equinox*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 Communicator\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 Avaya\ Communicator\ for\ Mac\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 Avaya\ Equinox\ for\ Mac\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 Avaya\ IX\ Workplace\ for\ Mac\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi	

	targetX=""; targetX=$(ls -t1 S[iI][pP]Messages.txt 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles=$(echo -e "$targetfiles\n$targetX")
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 logs_app.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	targetX=""; targetX=$(ls -t1 UccLog.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
#			targetfiles="$targetfiles $targetX"
			targetfiles=$(echo -e "$targetfiles\n$targetX")			
		else
			targetfiles="$targetX"
		fi
	fi

	if [[ $((alllogs)) == 0 ]]; then
		if [[ "$targetfiles" != "" ]]; then
			targetfiles=$(tail -1 <<< "$targetfiles")
#			targetfiles=${targetfiles##* }							# last word	
		else
			targetfiles="$targetX"
		fi
	fi

# echo targetlist=$targetfiles file=$file IFS=$IFS---
	xfile=""; file=""; filelist=""
	while IFS= read -r xfile
#	while read -r xfile	
	do
# echo xfile=$xfile
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
	done <<< "$targetfiles"
#	if [[ $xfile != "" ]] && [ -s "$xfile" ]; then
#		file="$destdir/$xfile"
#	fi
echo file=$file filelist=$filelist	
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
#		destdir="$destdir/$folder"
		cd "$folder"
	fi
	if [ -d "Avaya" ]; then
		destdir="$destdir/Avaya"
		cd "Avaya"
	fi

	if [ -d "Avaya Equinox" ]; then
		destdir="$destdir/Avaya Equinox"
		target="$target-Equinox"		
		cd "Avaya Equinox"
	elif [ -d "Avaya Workplace" ]; then
		destdir="$destdir/Avaya Workplace"
		target="$target-WP"		
		cd "Avaya Workplace"
	elif [ -d "Avaya IX Workplace" ]; then
		destdir="$destdir/Avaya IX Workplace"
		target="$target-IXWP"
		cd "Avaya IX Workplace"
	elif [ -d "Avaya Communicator" ]; then
		destdir="$destdir/Avaya Communicator"
		target="$target/ACWin"
		cd "Avaya Communicator"
	elif [ -d "Flare Communicator" ]; then
		destdir="$destdir/Flare Communicator"
		target="$target-FlareComm"
		cd "Flare Communicator"
	elif [ -d "Flare Experience" ]; then
		destdir="$destdir/Flare Experience"
		target="$target-FlareExp"
		cd "Flare Experience"		
	elif [[ -d "Avaya one-X Communicator" ]]; then
		destdir="$destdir/Avaya one-X Communicator"
		target="$target-1XC"
		cd "Avaya one-X Communicator"
	elif [[ -d "Communicator for Microsoft Lync" ]]; then
		destdir="$destdir/Communicator for Microsoft Lync"
		target="$target-ACLync"
		cd "Communicator for Microsoft Lync"
	elif [[ -d "Avaya Communicator for Microsoft Lync" ]]; then
		destdir="$destdir/Avaya Communicator for Microsoft Lync"
		target="$target-ACLync"
		cd "Avaya Communicator for Microsoft Lync"
	fi

	if [ -d "Log Files" ]; then
		destdir="$destdir/Log Files"	
		target="$target-LogFiles"		
		cd "Log Files"
	elif [ -d "log" ]; then
		destdir="$destdir/log"
		target="$target-log"
		cd "log"
	elif [ -d "logs" ]; then
		destdir="$destdir/logs"
		target="$target-logs"
		cd "logs"
	elif [ -d "Logs" ]; then
		destdir="$destdir/Logs"
		target="$target-Logs"
		cd "Logs"			
	fi

	explore_logfolder
#	destdir="$PWD"	

	if [[ $file == "" ]]; then
		if [ -d "Backup" ]; then
			destdir="$destdir/Backup"
			target="$target-backup"
			cd Backup
			explore_logfolder			
		elif [ -d "backup" ]; then
			destdir="$destdir/backup"
			target="$target-backup"
			cd backup
			explore_logfolder			
		fi
	fi

	if [[ $file == "" ]]; then	
		filelist=""; error=1
		echo -e "\nerror: could not find any Communicator/Equinox/Workplace/ClientSDK related logs in $folder\n"
		if [[ $((bDebug)) == 0 ]]; then ls -l; fi
		ls -l
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

		elif [[ $((sipstart)) == 1 ]]; then
			if [[ ${line:0:1} == "[" ]]; then
				if [[ $((vsyslog)) == 63 ]] || [[ $((vsyslog)) == 66 ]]; then
					line=$(cut -d' ' -f2- <<< "$line")
				fi
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
# echo -e "\n\ndebug: convert_EndpointLog() multiple SIP message found at line#$nlines at $siptime\n"
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

function convert_WP () {
	while IFS= read -r line
	do
#		linelength=${#line}
		nlines=$((nlines+1))

		if [[ $((insidesip)) == 0 ]]; then
#       if [[ $line == *"[CSDK::SIP]"* ]] || [[ $line == *"[CSDKEventLoop] - [SIP]"* ]] || [[ $line == *"[onLogMessage] > SENDING"* ]] || [[ $line == *"[onLogMessage] > RECEIVED"* ]] || [[ $line == *"[cpcorevt] SENDING"* ]] || [[ $line == *"[cpcorevt] RECEIVED"* ]]; then
	        if [[ $line =~ \[CSDK::SIP\] ]] || [[ $line =~ CSDKEventLoop\]\ -\ \[SIP\]\ \>\ [RS]E ]] || [[ $line =~ onLogMessage\]\ \>\ [RS]E ]] || [[ $line =~ cpcorevt\]\ [RS]E ]] || [[ $line =~ Debug\ SIP: ]] || [[ $line =~ DBG:\ SIP ]] || [[ $line =~ DEBUG\ \[SIP\] ]] || [[ $line =~ \[CSDK:SIP\] ]] || [[ $line =~ \]:\ [RS]E[CN] ]] || [[ $line =~ log:\ SIP\ level= ]] || [[ $line =~ SIP\ SdkLogDebug: ]] || [[ $line =~ \[CSDK\]\[SIP\] ]]; then
				if [[ $((sipstart)) != 0 ]]; then
					explore_sipmsg
#				   	complete_sipmsg				
				fi

			    insidesip=1
				siptotalmsg=$((siptotalmsg+1))	
				sip_direction
				get_sip_datetime
			fi

#		elif [[ $((insidesip)) == 0 ]]; then
#			continue

#        elif [[ $vsyslog =~ 50|51|52|53|54|55|65 ]] && [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then			 # 54=ACAndroid 2.1 has an emptyline in headset, + 55=EqiOS &  +65=ACiOS likewise
		elif [[ $((sipstart)) == 0 ]]; then													 # optimized - TODO: test for all vsyslog scenario
			if [[ ${#line} -lt 2 ]]; then
				insidesip=2
			else
			    sipmsg_header										
				start_sipmsg
			fi
				
		elif [[ $((sipstart)) == 1 ]]; then
		    if [[ $line =~ ^\} ]] && [[ ${#line} -lt 3 ]]; then
				explore_sipmsg
#				complete_sipmsg
			elif [[ $line =~ ^2[0-9]{3}- ]] || [[ $line =~ ^\[2[0-9]{3}- ]]; then
# <attributeList>
# <att... too large log size
# 2024-01-25 15:06:11.542 D [  812] [CSDK] CSIPStack::getTransactionContext. Transaction context= 23E260C0			
				explore_sipmsg
			else			
				if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
					base64found=1
					line=$(awk -F"Base64 dump" '{print $1}' <<< "$line")
					save_sipline

				elif [[ $((base64found)) != 0 ]]; then
					if [[ $linebuf64 == "" ]] && [[ $line != "" ]]; then
						linebuf64="$line"
					elif [[ $line != "" ]]; then
						linebuf64="$linebuf64$line"
					fi
				
				elif [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then												# due to multiple SIP msg in the same RX SIPMESSAGE				
#				elif [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then								# due to multiple SIP msg in the same RX SIPMESSAGE
#				elif [[ $dirdefined == 1 ]] && [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then	# it can occur only in RX direction
# echo -e "\n\ndebug: convert_EndpointLog() multiple SIP message found at line#$nlines at $siptime\n"
					if [[ ! $line =~ ^GUID= ]]; then
						multi_sipmsg
					fi
				else
					save_sipline			
#					prevline="$line"
				fi
			fi
		fi
	done <<< "$conv"
#	done < "$file"
} # convert_WP()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; basefile=""
#	rec2=0

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile="$file"
	fi

# 50) User-Agent: Avaya Communicator/3.0 (1.1.0.35.1974-3e404219; Avaya CSDK; Microsoft Windows NT 6.2.9200.0) - ExpertClient modify header! [TID: 36312]
### 2020-09-11 08:06:25.638 D [CSDK::SIP] [TID: 36312]: SENDING 831 bytes to 135.64.252.242:5061 {
# 51) User-Agent: Avaya Communicator/3.0 (3.25.0.73.27; Avaya CSDK; Microsoft Windows NT 6.2.9200.0)
# 51) User-Agent: Avaya Communicator/3.0 (8.0.1.0.10; Avaya CSDK; Microsoft Windows NT 6.2.9200.0)
# 52) User-Agent: Avaya Communicator for Mac/3.18.0.64.4 ((null)-(null); Avaya CSDK; MAC OS X)
# 53) User-Agent: Avaya Communicator Android/3.23.0 (FA-RELEASE68-BUILD.20; M2010J19CG)
### 2022-01-21 10:35:54,262 DEBUG [CSDKEventLoop] - [SIP] > SENDING 843 bytes to 103.125.140.250:32123 {
###
### REGISTER sips:sip-avaya.kesc.com.pk SIP/2.0
# 54) User-Agent: Avaya Aura Communicator Android/2.0.0 (FA-GRIZZLYINT-JOB1.218; Nexus 7)
### 2013-10-02 18:36:00,358 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING: 698 bytes to: 135.124.168.107:5061 {
### REGISTER sips:avayasip.com SIP/2.0
# 55/65) User-Agent: Avaya Communicator for iPhone/3.18.0 (3.18.0.65.21; Avaya CSDK; iPhone6,2)
# 56) User-Agent: Avaya Communicator for iPhone/3.0.2 (3.0.2.10; iPhone7,2)
# 57/67) User-Agent: Avaya Communicator for iPhone/2.1.2 (2.1.2.6; iPhone7,2)

# 60) User-Agent: Avaya Flare Communicator - need to replace all "SIGNAL-VIDEO:" with "    SIGNAL:"
# 61) User-Agent: Avaya Flare Experience/2.0.1 (Custom; iPad2,1)
# 62) User-Agent: Avaya Flare Engine/1.1.0 (Avaya 1.2 0; Windows NT 6.1, 64-bit)
# 62) User-Agent: Avaya Flare Engine/2.0.0 (Engine GA-2.0.0.41; Windows NT 6.2, 64-bit)
# 63) User-Agent: Avaya one-X Communicator/6.2.10.03 (Engine GA-2.2.0.3; Windows NT 6.2, 64-bit)
# 64) User-Agent: Avaya Communicator for Microsoft Lync/6.4.0.3.12 (Engine GA-2.1.0.18; Windows NT 6.1, 64-bit)
# 65) User-Agent: Avaya Communicator for iPhone/3.26.0 (3.26.0.64.18; Avaya CSDK; iPhone6,2)
# 66) User-Agent: Avaya SIP Communicator
# 67) User-Agent: Avaya Communicator for iPhone/2.1.2 (2.1.2.6; iPhone7,2)
# 68) User-Agent: Avaya one-X Communicator for MAC 2.0.2.1 (ASC2.0.2.1-1) 
# 69) SIP Softclient 2.1 - no capture yet

	echo -e "\nConverting $basefile ..."

	explore_softclient2

	footprint=0
	rec=$(egrep -c -e "^CSeq:*" "$file" 2>/dev/null)

	if [[ $((rec2)) == 0 ]]; then
		rec2=$(egrep -c -e "DBH:.*SIGNAL" "$file" 2>/dev/null)
		if [[ $((rec2)) == 0 ]]; then
   			rec2=$(egrep -c -e ".*\[CSDK::SIP\].*|.*\[CSDKEventLoop\] \- \[SIP\].*|.*\[onLogMessage\] > RECEIVED.*|.*\[onLogMessage\] > SENDING.*|.*\[cpcorevt\] SENDING.*|.*\[cpcorevt\] RECEIVED.*|\] SENDING |\] RECEIVED |Debug SIP:|DBG: SIP|DEBUG \[SIP\]|\[CSDK:SIP\]|\]:\ [RS]E[CN]|log:\ SIP\ level=|SIP\ SdkLogDebug:|\[CSDK\]\[SIP\]" "$file" 2>/dev/null)
		fi
	fi

	if [[ $rec2 == 0 ]] || [[ $rec == 0 ]]; then
		error=1
		if [[ $var != $file ]]; then
			echo -e "\nerror: no SIP messages have been found in $bvar -> $basefile."
		else
			echo -e "\nerror: no SIP messages have been found in $bvar."
		fi

		if [[ $file =~ StartupInfo ]]; then
			footprint=$(egrep -c -m 1 "^Avaya.ClientServices.Util.Logging" "$file" 2>/dev/null)
			if [[ $footprint == 1 ]]; then
				echo "$file appears to be a Workplace StartupInfo logfile."
				echo "This file never includes any SIP messages. Ignored."
			fi
		elif [[ $file =~ Exceptions ]]; then
			footprint=$(egrep -c -m 1 "^Exception:" "$file" 2>/dev/null)
			if [[ $footprint == 1 ]]; then
				echo "$file appears to be a Workplace Exception logfile."
				echo "This file never includes any SIP messages. Ignored."
			fi
		elif [[ $file =~ Console ]]; then
			echo "$basefile appears to be a Workplace Console logfile."
			echo "This file never includes any SIP messages. Ignored."
		else
#		echo "Perhaps this file is not a Communicator/Equinox/Workplace/ClientSDK log file..."
			echo -e "Possible that debug/verbose diagnostic mode was not enabled in $bvar."
			egrep -m 1 "VERBOSITY" "$file" 2>/dev/null
			egrep -m 1 "LogLevel" "$file" 2>/dev/null
		fi

	elif [[ $((vsyslog)) == 0 ]]; then
		if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
			footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
			if [[ $footprint == 1 ]]; then
				echo -e "\n$basefile appears to be an .asm file created by SIPlog2traceSM tool."
			fi
		else
   			echo -e "\nerror: $basefile does not appear to be a Communicator/Equinox/Workplace/ClientSDK log file."
			echo -e "Or, debug/verbose diagnostic mode was not enabled during the capture."
			egrep -m 1 "VERBOSITY" "$file" 2>/dev/null
			egrep -m 1 "LogLevel" "$file" 2>/dev/null
#			if [[ $((bDebug)) == 0 ]]; then echo vsyslog=$vsyslog; fi
		fi
		error=2

   	elif [[ $((vsyslog)) -gt 60 ]] && [[ $((voutput)) == 1 ]]; then
	    siptotalmsg=$(egrep -c -e "^CSeq:.*" "$file" 2>/dev/null)
		sipin=$(egrep -ce "] SENDING |] SENT " "$file" 2>/dev/null)
		sipout=$(egrep -ce "] RECEIVED " "$file" 2>/dev/null)
		if [[ $((vsyslog)) == 60 ]]; then
   	        sed 's/SIGNAL-VIDEO:/    SIGNAL:/g' "$file" > "$basefile.novideo"
			file="$basefile.novideo"; tmpfile=2
			basefile="$file"
#      	    echo -e "\n==> $siptotalmsg out of $rec SIP messages has been converted into $basefile.asm file." 			 # on test ipad SIPMessages.txt, sipin+sipoout=2084 but 2122
	    else
			sample=""; sample=$(egrep -m 1 "\[cpcorevt\]" "$file" 2>/dev/null)
			if [[ $sample == "" ]]; then
				if [[ $bINC == 0 ]] && [[ $bEXC == 0 ]]; then
       		    	echo "Warning: no conversion would be really required on $basefile."
					echo "You could use this file along with \"traceSM\" as it is."
				fi
#				error=20
			fi
		fi
	fi

	if [[ $((rec)) == 0 ]] || [[ $((error)) != 0 ]]; then
		return
	elif [[ $((rec)) -lt $((rec2)) ]]; then
		rec=$rec2
	fi
# echo 3 rec=$rec -- rec2=$rec2

    line="";	linebuf=""; linebuf64=""
    sipyear=$(cut -d'/' -f3 <<< "$today")			  
	logsec=$SECONDS
	base64msg=0
	lastfoundip="";	foundipaddr=""
	insidesip=0;	sipstart=0;		dirdefined=0		
	sipmsg=0;		siptotalmsg=0
	nlines=0;		siplines=0;		sipmaxlines=0
	sipword="";		sipwordlist="";	longestsipword=""; prevsipword=""
	firstmsg="";	lastmsg="";		longestmsg=0
	timefirst="";	timelast=""
	siptime="";		prevsiptime=""
	sipin=0;		sipout=0		
	callID="";		calltime="";	callDIR=0;
	callidtime1="";	callmsgnum1=0;	callidword1=""
	callidtime2="";	callmsgnum2=0;	callidword2=""
	nINFO=0;		infoin=0;		infoout=0
	notpassed=0;	notpassedin=0; 	notpassedout=0		
	currcseq=0;		prevcseq=0;		cseqword=""
	sipbadmsg=0;	sipbadmsgnum=0
	sipbadtime=0;	sipbadtimemsg=""
	nPONG=0;		embedded=0;		n=0
	useragent="";	server=""; 		serverip=""; serverua=""
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
	prevline="notempty"	

	evdialog=0; evccinfo=0; evreg=0; evcmfeat=0; evmsgsum=0
	evunknown=0; evpush=0; evscrupd=0; evrefer=0; evccs=0; evconf=0; evuaprof=0		

	reset_sipmsg

	if [[ $rec -gt 500 ]]; then 
		echo "Warning: about to convert a large file ($rec x SIP messages), this may take a while... "
		echo "You may want to execute this script on a more powerful PC or server."
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
		output=$basefile
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
	if [ -d "$var" ]; then
		echo "# Input: $var (folder)" >> "$newfile"
	else
		echo "# Input: $var" >> "$newfile"
	fi

	if [[ $var != $file ]]; then
		echo -e "# Input/output file: $var --> $file -> $output.asm\n" >> "$newfile"
	else 
		echo -e "# Input/output file: $var -> $output.asm\n" >> "$newfile"
	fi

#	conv=$(awk -e '/\[CSDK::SIP\]|\[CSDKEventLoop\] \- \[SIP\]|\[onLogMessage\] > SENDING|\[onLogMessage\] > RECEIVED|\[cpcorevt\] SENDING|\[cpcorevt\] RECEIVED/{flag=1} flag; /}/{flag=0}' "$file")
#	conv=$(awk -W source='/\[CSDK::SIP\]|\[CSDKEventLoop\] \- \[SIP\]|\[onLogMessage\] > SENDING|\[onLogMessage\] > RECEIVED|\[cpcorevt\] SENDING|\[cpcorevt\] RECEIVED/{flag=1} flag; /}/{flag=0}' "$file")

	echo ''
	if [[ $((vsyslog)) -gt 60 ]]; then
		convert_1xc
	elif [[ $((vsyslog)) != 0 ]]; then
		convert_WP
	fi

	if [[ $((sipstart)) != 0 ]]; then
		explore_sipmsg
#		complete_sipmsg
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
		elif [[ $((sipmsg)) == 0 ]]; then 
			echo "==> no SIP messages were found for addr=$endptaddr in $bvar"
		else
			echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
			echo "    have been converted for addr=$endptaddr into $output.asm"
		fi
		
		if [[ $useragent != "" ]]; then
			if [[ $lastfoundip != "" ]] && [[ $lastfoundip != "0.0.0.0" ]]; then
				lastfoundip=$(sed -e 's/\.$//g' <<< $lastfoundip)
				printf "\t%-48s ip.addr == %s\n" "${useragent:0:48}" "$lastfoundip"
			else
				printf "\t%-73s\n" "${useragent:0:73}"
			fi
			if [[ $useragent =~ VDI|Communicator ]]; then
				checkvdi=""; checkinfo=""; vdifw=""; vdiaddr=""
				checkvdi=$(egrep -m 1 -e "firmware=\".*avaya-sc-enabled" "$newfile" 2>/dev/null)
				checkinfo=$(egrep -m 1 -e "^CSeq:.*INFO" "$newfile" 2>/dev/null)
				if [[ $checkvdi == "" ]]; then
					checkvdi=$(egrep -m 1 -e "firmware=\".*avaya-sc-enabled" "$file" 2>/dev/null)
				fi

				if [[ $checkvdi != "" ]] && [[ $checkinfo != "" ]]; then
					vdifw=$(awk -F "firmware=" '{ print $2 }' <<< "$checkvdi")
					if [[ $vdifw != "" ]]; then
						vdiaddr=$(cut -d ';' -f2 <<< "$vdifw" | cut -d '@' -f2)					
						vdifw=$(cut -d '"' -f2 <<< "$vdifw")
						if [[ $vdiaddr != "" ]]; then
							echo -e "\tSCmode with $vdifw\t\tip.addr == $vdiaddr"
						else
							echo -e "\tFound SCmode session with $vdifw"
						fi
					fi
				fi
			fi
			if [[ $server == "" ]]; then
				serverip=""; server=$(egrep -m 1 -e "^Server:(?!.*Presence).*$" "$newfile" | tr -d "\r\n")				
			fi
			if [[ $server != "" ]]; then
				if [[ $serverip != "" ]]; then
					serverip=$(sed -e 's/\.$//g' <<< "$serverip")
				fi
#				if [[ $input != "" ]]; then								# && [[ ${#server} -lt 68 ]]; then
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
				echo -e "\tBase64 encoded SIP messages:\t\t\t $base64msg"
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

		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.3f "$(($((n)) * 1000 / $tmpsec))e-3")
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t  Total spent: $SECONDS sec   Avg. SIP msg/sec: $avgmsg\n"
		else
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t  Avg. SIP msg/sec: N/A\t  Time spent: $SECONDS sec\n"
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
		echo ''

		if [[ $((error)) == 0 ]] && [[ $((bCAT)) != 0 ]] && [[ $((n)) != 0 ]]; then
			echo -e "\n# ///////////////////////////////////////////////////////////////////////////////////////" >> "$ctarget"
			echo -e "# CAT $basefile into $ctarget" >> "$ctarget"
			echo -e "# ///////////////////////////////////////////////////////////////////////////////////////\n" >> "$ctarget"			
			cat "$output.asm" >> "$ctarget"
			echo "Converted $basefile into $output.asm, and concatenated it into $ctarget."
			echo ''; ls -l "$ctarget"; echo ''
		fi
	fi
elif [[ $file != "" ]]; then
	echo -e "\nerror: $basefile was not found in the current folder: $PWD"
	error=9
else
	echo -e "\nerror: convert_siplog() received null string for input. Contact developer."
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
  while getopts ":hbdf:k:sv:ACN:I:X:" options; do
	case "${options}" in
	h)
		usage; exit 0;;
	A)
		alllogs=1;;
    I)
		noINFO=1;;
	C)
		bCAT=1;;	
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
    I)
#		noINFO=1;;
		filterI=${OPTARG}
		explore_filters;;
	X)
		filterX=${OPTARG}
		explore_filters;;		
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	d)
		bDebug=0;;
	k)
		enckey=${OPTARG};;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	v)  vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 50 ]] || [[ $((vsyslog)) -gt 69 ]]; then
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

let ignoretmp=0
ignoretmp=$(ls -l | awk $AWKSRCFLAG"test" 2>&1 | grep -c "awk:")
#awk: warning: option -W is ignored
if [[ $ignoretmp != 0 ]]; then
	AWKSRCFLAG="-e"
	ignoretmp=$(ls -l | awk $AWKSRCFLAG "test" 2>&1 | grep -c "awk:")
	if [[ $ignoretmp != 0 ]]; then
		echo -e "\nerror: problem with "awk" - either command not found (missing), or does not to support "-e/W source" option."
		echo "Cannot continue execution. Verify your linux environment.  Aborting...\n"
	fi
fi

for var in "$@"
do
	if [[ $var == "-"* ]]; then
  		if [[ $var == "-f"* ]]; then
			skipper=1
		elif [[ $var == "-v"* ]]; then
			skipper=2
		elif [[ $var == "-k"* ]]; then
			skipper=3
		elif [[ $var == "-N"* ]]; then
			skipper=4
		elif [[ $var == "-X"* ]]; then
			skipper=5
		elif [[ $var == "-I"* ]]; then
			skipper=6			
		else
			skipper=0
		fi
		var="": continue
	elif [[ $skipper != 0 ]]; then
		if [[ $((skipper)) == 1 ]]; then
			voutput="$var"
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
				voutput=1
			fi
		elif [[ $((skipper)) == 2 ]]; then
			vsyslog="$var"
			if [[ $((vsyslog)) -lt 50 ]] || [[ $((vsyslog)) -gt 69 ]]; then
				vsyslog=1
			fi
		elif [[ $((skipper)) == 3 ]]; then
			enckey=$var
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
		fi
		skipper=0; var=""
		continue
	fi

	n=0; 		error=0;	vsyslog=0
	bdir="";	bvar="";	folder=""
	target=""; 	destdir="";	input=""; input2=""
	file=""; 	filelist="";basefile=""
	currtime=$(date +%R:%S);currdir=$PWD	
	bSinglefile=0; tmpfile=0
	filetype2=""; filecontent="WP"

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
		target="WP"
	else
		target="$bvar"	
	fi

#	target=${target%%.*}				# TODO: what about ../folder or ../filename - note the leading ".."	
	if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
		target=${target%.*}
		if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
			target=${target%.*}
		fi
	fi

#  - d:\Avaya\LogFiles\TTLogfiles\ACM-IPO\2016_05_16_tt_[chap@mss-avayacie].log
	if [ -d "$var" ]; then
		echo -en "\nExploring content in $bvar folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders
		cd "$currdir"		
	
	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $bvar ... stand by\r"
		file="$var"

		if [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."
		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype =~ text ]] || [[ $filetype == "data" ]]; then
			filelist=""
			filecontent="ASCII"
			bSinglefile=1			

		elif [[ $filetype == *"data"* ]] && [[ ! $filetype =~ archive|compressed ]]; then
			filecontent=$(egrep -m 1 "ANDROID:" "$file" 2>/dev/null)
			recX=0; recX=$(egrep -a -c -m 1 "CSeq:" "$file" 2>/dev/null)
			if [[ $filecontent =~ ANDROID ]]; then
				filecontent="ANDROID"		
			elif [[ $((recX)) == 0 ]] && [[ $enckey != "" ]]; then
				openssl version >/dev/null 2>&1
				if [[ $? == 0 ]]; then
					if [[ $bvar == *"."* ]]; then
						input=${bvar%.*}
					else
						input="$bvar"
					fi

					fext=${file#*.}
					input=$input"-decrypted.$fext"
					inputtype=""
#					openssl aes-128-cbc -d -salt -k $enckey -in $file -out "$outfile"
					openssl aes-256-ctr -md sha256 -d -salt -k $enckey -in "$file" -out "$input"
	
					if [[ $? != 0 ]] || [[ $(file -b "$input") == "data" ]]; then
#						openssl aes-256-ctr -md sha256 -salt -k $enckey -in "$file" -out "$outfile"
#						if [[ $? == 0 ]]; then
							echo "error: Could not decode $bvar using \"openssl\""
							echo -e "Verify encryption key ($enckey) with your provider.\n"
							filecontent="error"; error=6; exit $error
					else
						file="$input"; tmpfile=2
						basefile=$(basename "$file")
						filecontent="OPENSSL"
						filetype=$(file -b "$file")
						echo "Decoded $bvar into $basefile successfully using \"openssl\"."
					fi
				else
					echo -e "error: "openssl" was not found, required for decoding $bvar - need to decode this file manually.\n"
					error=5; exit $error
				fi
			else
				sample=""; sample=$(egrep -m 1 -e "CSeq:" "$file" 2>/dev/null)	
				if [[ $sample != "" ]]; then
					sample=$(basename $0)
					echo -e "\n$bvar appears to be a logfile for a different product. Unable to decode this file with $sample script."
					echo "Try to find out which traceXXX.sh script can convert this file."
					echo "Hint: look up User-Agent string in SIP TX messages."
				elif [[ $endkey == "" ]]; then
					echo -e "\n$var appears to be an encrypted logreport."
					echo "error: missing encryption key.  Re-try with -k option."
				fi
				error=4; exit $error
			fi
		fi

		if [[ $filetype == "Zip archive"* ]] && [[ $filecontent != "error" ]]; then
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
					echo -e "Unable to unzip $basefile into a temp folder. Skipping this file...\n"
					error=7; cd "$currdir"; input=""; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $basefile into a temp folder. Skipping this file...\n"
				input=""; error=7; cd "$currdir"; continue
			fi

			if [[ $bUnzip != 0 ]] && [ -d "$input.tmp" ]; then
				cd "$input.tmp"
				echo -e "\nUncompressing $basefile into $input.tmp ...                                                  "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "error: failed to uncompress $basefile, using \"unzip\" utility. Skipping this file..."
					echo -e "Suggesting to validate \"unzip -qq $basefile\" command manually.\n"
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
						echo -e "\nerror: failed to uncompress $bfile, using \"gunzip\" utility."
						echo -e "Tip: could this file be an encrypted debugreport? Try with \"-k key\" option.\n"						
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
			echo "Warning: about to convert multiple files ($nfiles x UccLog/logs_app/Workplace/Equinox/Communicator*.log)."
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
				ls -l "$ctarget"
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
#		file=$(awk '{print $1}' <<< "$filelist")						# == head -1)
		file=${filelist% *}												# first word
		convert_siplog
	elif [[ $file != "" ]]; then
		convert_siplog	
	fi

	if [[ $bDebug != 0 ]]; then
		if [[ $input2 != "" ]] && [ -d "$input2.tmp" ]; then
#			rm -rf "$input2.tmp" 2>/dev/null
			rm -rf "$input2.tmp"			
		fi
		if [[ $input != "" ]]; then 
			if [ -d "$input.tmp" ]; then
#				rm -rf "$input.tmp" 2>/dev/null
				rm -rf "$input.tmp"				
			fi
			if [ -f "$input" ]; then
#				rm "$input" 2>/dev/null
				rm "$input"				
			fi
		fi
		if [[ $tmpfile == 2 ]] && [ -f "$file" ]; then
#			rm "$file" 2>/dev/null
			rm "$file"			
		fi		
	fi
done

if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
elif [[ $converted != 0 ]] && [[ $bCAT != 0 ]] && [ -s "$ctarget" ]; then
	echo "All ($converted) converted files have been concatenated into $ctarget"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo "No files have been converted."
fi
exit 0