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
error=0
bCAT=0
alllogs=0
bDelTemp=1
converted=0
adjusthour=0
base64decode=1
enckey=""
alllogs=0
noINFO=0
findANI=""
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
## 57) 1xMobile SIP iOS  --> 65
## 58) ACios Communicator.log
## 59) 1XC MAC
## 60) Flare Experience (iPad, )
## 61) 1XC Windows + AXLync

function usage ()  {
    echo "traceWP.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceWP.sh <options> [<LOG_FILE> | <folder>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the log file for a Communicator/Equinox/Workplace client (any platform)"
	echo -e "\t\t\tor, the logreport itself collected from a Workplace client (encrypted or unencrypted)"
	echo -e "\t<folder>\ta folder or path including above files eg. \"Avaya\", \"logs\", \"Avaya IX Workplace\""		
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage information (this screen)"
	echo -e "\t-k \t\tset decryption key for debugreport decoding"							
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"	
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converted multiple logfiles)"		
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"	
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
#	echo -e "\t-v X:\t\t enforce input format to X"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	sipyear=""
	dirdefined=0
	base64found=0
	sipword=""
	ip1=""; ip2=""; ip=""
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
	if [[ $sipword == "" ]]; then
		echo -e "\nALERT: sipword in start_sipmsg() is null string ($vsyslog) - contact developer.\n"
	elif [[ $sipword == "SIP/2.0" ]]; then
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
		firstmsg="$lastmsg"
		timefirst="$timelast"
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

	case $voutput in
	1)	if [[ $((vsyslog)) == 2 ]]; then
			echo -e "$NL[$sipstream] }\x0d$NL" >> "$newfile"
		else
			echo -e "[$sipstream] }\x0d$NL" >> "$newfile"
		fi;;
	2)	echo -e "$NL}$NL" >> "$newfile";;
	3)	echo -e "--------------------" >> "$newfile";;
	esac

	reset_sipmsg
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
		case $voutput in
		1)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
		2)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
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

	elif [[ $line =~ \ SENDING ]]; then
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
            ip=$(awk -F'://' '{print $2}' <<< "$line" | cut -d' ' -f1)						# FOUND: ACAndroid/logs_app.log BINGO
		else
			ip=$(cut -d' ' -f12 <<< "$line"); siplength=$(cut -d' ' -f9 <<< "$line")
		fi;;

		56)	 # EqiOS 3.0
# 2017-02-14 00:05:03:252 [cpcorevt] SENDING 783 bytes to 94.56.88.55:5061 {		
			ip=$(awk '{print $8}' <<< "$line")
		 	siplength=$(cut -d' ' -f5 <<< "$line");;

	   	65)  # ACiOS Communicator
# V 2016-09-26 14:03:48:423 [cpcorevt] SENDING 1329 bytes to 198.152.66.100:5061 {		
	     # ip=$(cut -d' ' -f9 <<< "$line")
		 ip=$(awk '{print $9}' <<< "$line")
		 siplength=$(cut -d' ' -f6 <<< "$line");;

	   	*)	if [[ $line =~ CSDK::SIP ]]; then
				linex=$(cut -d']' -f3 <<< "$line")
	        	ip=$(cut -d' ' -f6 <<< "$linex"); siplength=$(cut -d' ' -f3 <<< "$linex")
	   		else
         		ip=$(cut -d' ' -f10 <<< "$line"); siplength=$(cut -d' ' -f7 <<< "$line")
	   		fi;;
		esac
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

function get_sip_datetime () {
# WIN: 2022-04-14 09:01:12.328 D [21480] [CSDK::SIP] SENDING 806 bytes to 62.245.230.55:5061 {
# MAC: 2021-05-19 20:21:55.431 D [197063044/csdkloop] [CSDK::SIP] SENDING 1807 bytes to 10.200.97.110:5061 {
# EqA: 2022-01-21 10:35:54,262 DEBUG [CSDKEventLoop] - [SIP] > SENDING 843 bytes to 103.125.140.250:32123 {
# iOS: 2021-06-04 15:25:32.169 D [csdkloop] [CSDK::SIP] SENDING 833 bytes to 135.64.253.72:5061 {
# iOS 3.0 2017-02-14 00:05:03:252 [cpcorevt] SENDING 783 bytes to 94.56.88.55:5061 {	
# ACAndroid: 2013-10-02 18:36:00,358 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING: 698 bytes to: 135.124.168.107:5061 {
# ACiOS: V 2016-09-26 14:03:48:423 [cpcorevt] SENDING 1329 bytes to 198.152.66.100:5061 {	
if [[ $line != "" ]]; then
    if [[ $((vsyslog)) == 65 ]]; then # ACiOS exception
		sipday=$(cut -d' ' -f2 <<< "$line")
		sipmsec=$(cut -d' ' -f3 <<< "$line")
	else
		sipday=$(cut -d' ' -f1 <<< "$line")
		sipmsec=$(cut -d' ' -f2 <<< "$line")
	fi

	sipyear=$(cut -d'-' -f1 <<< "$sipday")
	sipmonth=$(cut -d'-' -f2 <<< "$sipday")
	sipday=$(cut -d'-' -f3 <<< "$sipday")
									
	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")

	case $vsyslog in
	53|54) # Android exception
		sipmsec=$(cut -d',' -f2 <<< "$sipsec"); 	  sipsec=$(cut -d',' -f1 <<< "$sipsec");;
	56|65)  # ACiOS exception
		sipmsec=$(cut -d':' -f2 <<< "$sipsec"); 	  sipsec=$(cut -d':' -f1 <<< "$sipsec");;
    *)
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec"); 	  sipsec=$(cut -d'.' -f1 <<< "$sipsec");;
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

function explore_softclient2 () {
if [[ $file != "" ]] && [ -f "$file" ]; then 
#   sample=$(egrep -m 1 -e "\[CSDK::SIP\]\ " "$file")
    sample=$(egrep -m 1 -e "\[CSDK::SIP\]" "$file" 2>/dev/null)	
    if [[ $sample != "" ]] && [[ $sample =~ \]\ \[TID: ]]; then
# ExpertClient Windows
		vsyslog=50
		conv=$(awk '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")
    elif [[ $sample != "" ]] && [[ $sample =~ \[csdkloop\] ]]; then
# EqiOS 3.x  
        vsyslog=55
		conv=$(awk '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")
    elif [[ $sample != "" ]] && [[ $sample =~ \/csdkloop\] ]]; then
# EqMac 3.x 
		vsyslog=52
		conv=$(awk '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")
    elif [[ $sample != "" ]] && [[ $sample =~ \[CSDK::SIP\]\ [SR]E ]]; then
# EqWin    
        vsyslog=51
		conv=$(awk '/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")
    else
        sample=$(egrep -m 1 -e "\[CSDKEventLoop\]\ \-\ \[SIP\]\ >\ [RS]E" "$file" 2>/dev/null)
#		sample=$(egrep -m 1 -e "\[CSDKEventLoop\]\ \-\ \[SIP\]\ " "$file" 2>/dev/null)						# not sufficient see Workplace/FA-CARRERAINT-JOB1.328_20170111_FlareA-workingndroid_logs.tmp/logs_app.2.log
        if [[ $sample != "" ]] && [[ $sample =~ \[CSDKEventLoop\]\ \-\ \[SIP\]\  ]]; then
# EqA 3.X
            vsyslog=53	
			conv=$(awk '/\[CSDK::SIP\]|\[CSDKEventLoop\] \- \[SIP\]\ >\ [RS]E/{flag=1} flag; /}/{flag=0}' "$file")
        else
            sample=$(egrep -m 1 -e "\[onLogMessage\]\ >\ [RS]E" "$file" 2>/dev/null)
            if [[ $sample != "" ]] && [[ $sample =~ \[onLogMessage\]\ \>\ [RS]E ]]; then
# AcAndroid 2.0    
          		vsyslog=54
				conv=$(awk '/\[onLogMessage\] > [RS]E/{flag=1} flag; /}/{flag=0}' "$file")
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
					conv=$(awk '/\[cpcorevt\] [RS]E/{flag=1} flag; /}/{flag=0}' "$file")
                else
					sample=$(egrep -m 1 -e "\]\ SENT\ to\ |\]\ RECEIVED\ from\ |\]\ SENDING\ " "$file" 2>/dev/null)
					if [[ $sample != "" ]] && [[ $sample != *"DBH:"* ]]; then
         	        	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for i" "$file" 2>/dev/null)
                        if [[ $rec2 != 0 ]]; then 
# AC iPhone/iPad								
   	                        vsyslog=67
						fi
					else
	                    rec2=$(egrep -m 1 -c -e "^User-Agent:.*SIP Communicator" "$file" 2>/dev/null)
                    	if [[ $rec2 != 0 ]]; then
# Avaya SIP Communicator/1xSIPIOS
                        	vsyslog=66
	                    else
    	                	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for MAC" "$file" 2>/dev/null)
    		                if [[ $rec2 != 0 ]]; then 
# 1XC MAC
            	                vsyslog=68
							else
                            	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for Microsoft Lync" "$file" 2>/dev/null)
	                	        if [[ $rec2 != 0 ]]; then 
# ACLync
    	                	        vsyslog=64
    	                    	else
        	                    	rec2=$(egrep -m 1 -c -e "^User-Agent:.*one-X Communicator.*Windows" "$file" 2>/dev/null)
	            	                if [[ $rec2 != 0 ]]; then
# 1XC
    	            	                vsyslog=63
        	            	        else
            	        	            rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Engine.*Windows" "$file" 2>/dev/null)
                	        	        if [[ $rec2 != 0 ]]; then
# FlareWin
                	            	        vsyslog=62
                    	            	else
                        	            	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Experience" "$file" 2>/dev/null)
	                            	        if [[ $rec2 != 0 ]]; then
# FlareExp
	                                	        vsyslog=61
        	                                else
            	                            	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Communicator" "$file" 2>/dev/null)
	            	                            if [[ $rec2 != 0 ]]; then 
# FlareComm
    	            	    	                    vsyslog=69
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
	echo -e "\nABORT: explore_softclient() was called with invalid file - contact develoepr.\n"
fi
} # explore_softclient2()

function explore_logfolder() {
	targetfiles=""

	targetX=""; targetX=$(ls -r UccLog?.log 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetX != "" ]]; then
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -r UccLog.*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 SipMessages*.log 2>/dev/null)			# ACAndroid r2.1
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 SipMessages?.txt 2>/dev/null)			# ACWin r2.1
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 SIPMessages?.txt 2>/dev/null)			# 1XCMAC
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -r logs_app?.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -r logs_app.?.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls Equinox*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls Workplace*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls Communicator\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls Avaya\ Equinox\ for\ Mac\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls Avaya\ IX\ Workplace\ for\ Mac\ 2*.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi	

	targetX=""; targetX=$(ls -t1 SIPMessages.txt 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 logs_app.log 2>/dev/null)
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi
	fi

	targetX=""; targetX=$(ls -t1 UccLog.log 2>/dev/null)
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
	while IFS= read -r xfile
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
	done <<< "$targetfiles"
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
		cd "Avaya Equinox"
	elif [ -d "Avaya Workplace" ]; then
		destdir="$destdir/Avaya Workplace"
		cd "Avaya Workplace"
	elif [ -d "Avaya IX Workplace" ]; then
		destdir="$destdir/Avaya IX Workplace"
		cd "Avaya IX Workplace"
	elif [ -d "Avaya Communicator" ]; then
		destdir="$destdir/Avaya Communicator"
		cd "Avaya Communicator"
	elif [ -d "Flare Communicator" ]; then
		destdir="$destdir/Flare Communicator"
		cd "Flare Communicator"
	elif [ -d "Flare Experience" ]; then
		destdir="$destdir/Flare Experience"
		cd "Flare Experience"
	fi

	if [ -d "Log Files" ]; then
		cd "Log Files"
	elif [ -d "log" ] || [ -d "logs" ] || [ -d Logs ]; then
		if [ -d "log" ]; then
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
	fi

	destdir="$PWD"
	explore_logfolder

	if [[ $file == "" ]]; then
		filelist=""; error=1
		echo -e "\nerror: could not find any Communicator/Equinox/Workplace/ClientSDK related logs in $folder\n"
	fi
	cd $currdir
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
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

	explore_softclient2

	footprint=0
	rec=$(egrep -c -e "^CSeq:*" "$file" 2>/dev/null)
   	rec2=$(egrep -c -e ".*\[CSDK::SIP\].*|.*\[CSDKEventLoop\] \- \[SIP\].*|.*\[onLogMessage\] > RECEIVED.*|.*\[onLogMessage\] > SENDING.*|.*\[cpcorevt\] SENDING.*|.*\[cpcorevt\] RECEIVED.*|\] SENDING |\] RECEIVED " "$file")

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
				echo "This file never includes any SIP messages. Ignoring..."
			fi
		elif [[ $file =~ Exceptions ]]; then
			footprint=$(egrep -c -m 1 "^Exception:" "$file" 2>/dev/null)
			if [[ $footprint == 1 ]]; then
				echo "$file appears to be a Workplace Exception logfile."
				echo "This file never includes any SIP messages. Ignoring..."
			fi
		elif [[ $file =~ Console ]]; then
			echo "$basefile appears to be a Workplace Console logfile."
			echo "This file never includes any SIP messages. Ignoring..."
		else
#		echo "Perhaps this file is not a Communicator/Equinox/Workplace/ClientSDK log file..."
			echo -e "Possible that debug/verbose diagnostic mode was not enabled in $bvar."
			egrep -m 1 "SET LOG_VERBOSITY" "$file" 2>/dev/null
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
			egrep -m 1 "SET LOG_VERBOSITY" "$file" 2>/dev/null
		fi
		error=2

   	elif [[ $((vsyslog)) -ge 60 ]] && [[ $((voutput)) == 1 ]]; then
	    siptotalmsg=$(egrep -c -e "^CSeq:.*" "$file" 2>/dev/null)
		sipin=$(egrep -c -e "] SENDING |] SENT " "$file" 2>/dev/null)
		sipout=$(egrep -c -e "] RECEIVED " "$file" 2>/dev/null)
		if [[ $((vsyslog)) == 60 ]]; then
   	        sed 's/SIGNAL-VIDEO:/    SIGNAL:/g' "$file" > "$basefile.asm"
       	    echo -e "\n==> $siptotalmsg out of $rec SIP messages has been converted into $basefile.asm file." 			 # on test ipad SIPMessages.txt, sipin+sipoout=2084 but 2122
	    else
			sample=""; sample=$(egrep -m 1 "\[cpcorevt\]" "$file" 2>/dev/null)
			if [[ $sample == "" ]]; then
       	    	echo -e "\nNo conversion required.  Use $basefile along with \"traceSM\" as it is."
				error=20
			fi
		fi
	fi

	if [[ $((rec)) == 0 ]] || [[ $((error)) != 0 ]]; then
		return
	fi

	logsec=$SECONDS
	base64msg=0
	foundipaddr=""
	useragent=""
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
	sipwordlist=""	
	longestsipword=""
	longestmsg=0
	firstmsg=""
	lastmsg=""
	timefirst=""
	timelast=""
	sipin=0
	sipout=0
	nINFO=0
	callID=""
	calltime=""
	callDIR=0

	reset_sipmsg

	if [[ $rec -gt 500 ]]; then 
		echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
		echo "You may want to execute this script on a more powerful PC or server."
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
	while IFS= read -r line
	do
#		linelength=${#line}
		nlines=$((nlines+1))

#       if [[ $line == *"[CSDK::SIP]"* ]] || [[ $line == *"[CSDKEventLoop] - [SIP]"* ]] || [[ $line == *"[onLogMessage] > SENDING"* ]] || [[ $line == *"[onLogMessage] > RECEIVED"* ]] || [[ $line == *"[cpcorevt] SENDING"* ]] || [[ $line == *"[cpcorevt] RECEIVED"* ]]; then
        if [[ $line == *"[CSDK::SIP]"* ]] || [[ $line =~ CSDKEventLoop\]\ -\ \[SIP\]\ \>\ [RS]E ]] || [[ $line =~ onLogMessage\]\ \>\ [RS]E ]] || [[ $line =~ cpcorevt\]\ [RS]E ]]; then
			if [[ $((sipstart)) != 0 ]]; then
			   	complete_sipmsg
			fi

		    insidesip=1
			siptotalmsg=$((siptotalmsg+1))	
			sip_direction
			get_sip_datetime

		elif [[ $((insidesip)) == 0 ]]; then
			continue

#        elif [[ $vsyslog =~ 50|51|52|53|54|55|65 ]] && [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then			 # 54=ACAndroid 2.1 has an emptyline in headset, + 55=EqiOS &  +65=ACiOS likewise
		elif [[ $((sipstart)) == 0 ]]; then			 # optimized - TODO: test for all vsyslog scenario
			if [[ ${#line} -lt 2 ]]; then
				insidesip=2
	        elif [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
				nINFO=$((nINFO+1))
			    reset_sipmsg
				continue
			else			
			    sipmsg_header										
				start_sipmsg
			fi
				
		elif [[ $((sipstart)) == 1 ]]; then
			if [[ $findANI != "" ]] && [[ $sipword =~ INVITE ]]; then
				if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
					calltime=$siptime
				elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
					callID=$line; callDIR=$dirdefined
				fi
			fi
		    if [[ $line =~ ^\} ]] && [[ ${#line} -lt 3 ]]; then
			   complete_sipmsg
			else			
				if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
					base64found=1
					echo "# Base64 dump found" >> "$newfile"
					if [ -f "$newfile.b64" ]; then
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
#	done < "$file"

	if [[ $((sipstart)) != 0 ]]; then
		complete_sipmsg
	fi
	echo '' >> "$newfile"

    if [[ $((sipstat)) != 0 ]]; then
		if [[ ${#endptaddr} == 0 ]]; then
			echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $var.asm file"
		else
			if [[ $((sipmsg)) == 0 ]]; then 
				echo "==> no SIP messages were found for addr=$endptaddr in $var file"
			else
				echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
				echo "    have been converted for addr=$endptaddr into $var.asm file"
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
			echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
			if [[ $((nINFO)) != 0 ]]; then
				echo -e "\tINFO messages ignored:\t\t\t\t $nINFO"
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
					echo -e "\tFirst msg: $firstmsg   $timefirst\t\t Last msg: $lastmsg   $timelast"
				else
					echo -e "\tFirst msg: $firstmsg   $timefirst\t Last msg: $lastmsg   $timelast"
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
		echo ''; ls -l "$ctarget"; echo ''
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
  while getopts ":hbdf:k:sv:ACN:I" options; do
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
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
    I)
		noINFO=1;;		
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;
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
			vsyslog="$var"
			if [[ $((vsyslog)) -lt 50 ]] || [[ $((vsyslog)) -gt 69 ]]; then
				vsyslog=1
			fi
		elif [[ $((skipper)) == 3 ]]; then
			enckey=$var
		elif [[ $((skipper)) == 4 ]]; then
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
		target=$bvar
		bvar=$(basename "$var")		
	elif [[ $var == "." ]]; then
		target="WP"
	else
		target=$bvar		
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
		echo -en "\nExploring content in $var folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders
	
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
					echo -e "\n$bvar appears to be a logfile for a different product. Unable to decode this file with $@ script."
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
					error=7; cd $currdir; input=""; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $basefile into a temp folder. Skipping this file...\n"
				input=""; error=7; cd $currdir; continue
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
				cd $currdir; input=""; error=8; continue
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
		file=$(awk '{print $1}' <<< "$filelist")		# == head -1)
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
			rm $file 2>/dev/null
		fi		
	fi
done

if [[ $converted != 0 ]] && [[ $bCAT != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0