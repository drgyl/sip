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
error=0
longestmsg=0
adjusthour=0
base64decode=1
enckey=""
alllogs=0
noINFO=0
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
## 56-->65) Workplace iOS SIPMessages
## 57) 1xMobile SIP iOS
## 58) ACios Communicator.log
## 59) 1XC MAC
## 60) Flare Experience (iPad, )
## 61) 1XC Windows + AXLync

function usage ()  {
    echo "traceWP.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t   created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceWP.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the log file for a Communicator/Equinox/Workplace client (any platform)"
	echo -e "\t\t\tor, the logreport from Workplace client (encrypted or unencrypted)"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-k:\t\tset decryption key for debugreport decoding"							
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
#	echo -e "\t-A:\t\tconvert all aditional logs in logreport where SIP message found (SIPMESSAGESx.txt)"
	echo -e "\t-I:\t\tignore all SIP INFO messages (used in sharedcontrol session)"	
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
	ip1=""
	ip2=""
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then	
	sipstart=1
	siplines=$((siplines+1))
	if [[ $((voutput)) == 1 ]]; then 
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		if [[ $((vsyslog)) == 1 ]]; then
			echo -en "$NL$line\0xd$NL" >> "$newfile"
		else
			echo -en "$NL$line$NL" >> "$newfile"
		fi
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
		if [[ $((vsyslog)) == 2 ]]; then
			echo -e "$NL[$sipstream] }\x0d$NL" >> "$newfile"
		else
			echo -e "[$sipstream] }\x0d$NL" >> "$newfile"
		fi
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
		sipstart=0
		n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$var => $n/$rec Msgs converted            \r"
		fi
		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >>"$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/TLS/ }${NL}--------------------" >>"$newfile"
		fi
	fi
} # sipmsg_header() 

function sip_direction () {
# WIN: 2022-04-14 09:01:12.328 D [21480] [CSDK::SIP] SENDING 806 bytes to 62.245.230.55:5061 {
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line == *" RECEIVED "* ]]; then
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

	elif [[ $line == *" SENDING"* ]]; then
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
	else
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
	   if [[ $((vsyslog)) == 50 ]]; then # ExpertClient exception
   	     ip=$(echo "$line"        | cut -d' ' -f11)
	     siplength=$(echo "$line" | cut -d' ' -f8)

	   elif [[ $((vsyslog)) == 53 ]] || [[ $((vsyslog)) == 54 ]]; then # Android exception
	     ip=$(echo "$line"        | cut -d' ' -f12)
	     siplength=$(echo "$line" | cut -d' ' -f9)
	     if [[ $((vsyslog)) == 54 ]] && [[ $((dirdefined)) == 1 ]]; then
            ip=$(echo $ip | awk -F'://' '{print $2}')  
		 fi

	   elif [[ $((vsyslog)) == 57 ]]; then # ACiOS Communicator
	     ip=$(echo "$line"        | cut -d' ' -f9)
	     siplength=$(echo "$line" | cut -d' ' -f6)

	   elif [[ $line =~ CSDK::SIP ]]; then
			linex=$(echo "$line"      | cut -d']' -f3)
	        ip=$(echo "$linex"        | cut -d' ' -f6)
		    siplength=$(echo "$linex" | cut -d' ' -f3)
	   else
         ip=$(echo "$line"        | cut -d' ' -f10)
	     siplength=$(echo "$line" | cut -d' ' -f7)
	   fi
	fi
fi
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
# WIN: 2022-04-14 09:01:12.328 D [21480] [CSDK::SIP] SENDING 806 bytes to 62.245.230.55:5061 {
# MAC: 2021-05-19 20:21:55.431 D [197063044/csdkloop] [CSDK::SIP] SENDING 1807 bytes to 10.200.97.110:5061 {
# EqA: 2022-01-21 10:35:54,262 DEBUG [CSDKEventLoop] - [SIP] > SENDING 843 bytes to 103.125.140.250:32123 {
# iOS: 2021-06-04 15:25:32.169 D [csdkloop] [CSDK::SIP] SENDING 833 bytes to 135.64.253.72:5061 {
# ACAndroid: 2013-10-02 18:36:00,358 DEBUG [ClientPlatformEventLoop] - [onLogMessage] > SENDING: 698 bytes to: 135.124.168.107:5061 {
# ACiOS: V 2016-09-26 14:03:48:423 [cpcorevt] SENDING 1329 bytes to 198.152.66.100:5061 {	

    if [[ $((vsyslog)) == 57 ]]; then # ACiOS exception
	  sipday=$(echo "$line"  | cut -d' ' -f2)
	  sipmsec=$(echo "$line" | cut -d' ' -f3)
	else
	  sipday=$(echo "$line"  | cut -d' ' -f1)
	  sipmsec=$(echo "$line" | cut -d' ' -f2)
	fi
	sipyear=$(echo $sipday  | cut -d'-' -f1)
	sipmonth=$(echo $sipday | cut -d'-' -f2)
	sipday=$(echo $sipday   | cut -d'-' -f3)
									
	siphour=$(echo $sipmsec | cut -d':' -f1)
	sipmin=$(echo $sipmsec  | cut -d':' -f2)
	sipsec=$(echo $sipmsec  | cut -d':' -f3)

	if [[ $((vsyslog)) == 53 ]] || [[ $((vsyslog)) == 54 ]]; then  # Android exception
	  sipmsec=$(echo $sipsec  | cut -d',' -f2)
	  sipsec=$(echo $sipsec   | cut -d',' -f1)
	elif [[ $((vsyslog)) == 57 ]]; then  # ACiOS exception
	  sipmsec=$(echo $sipsec  | cut -d':' -f2)
	  sipsec=$(echo $sipsec   | cut -d':' -f1)
    else
	  sipmsec=$(echo $sipsec  | cut -d'.' -f2)
	  sipsec=$(echo $sipsec   | cut -d'.' -f1)
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

function explore_softclient2 () {
    sample=$(egrep -m 1 -e "\[CSDK::SIP\]\ " "$file")
    if [[ $sample != "" ]] && [[ $sample =~ \]\ \[TID: ]]; then
# ExpertClient Windows
		vsyslog=50
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")		
    elif [[ $sample != "" ]] && [[ $sample =~ \[csdkloop\] ]]; then
# EqiOS 3.x  
        vsyslog=55
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")		
    elif [[ $sample != "" ]] && [[ $sample =~ \/csdkloop\] ]]; then
# EqMac 3.x 
		vsyslog=52
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")
    elif [[ $sample != "" ]] && [[ $sample =~ \[CSDK::SIP\]\ [SR]E ]]; then
# EqWin    
        vsyslog=51
		conv=$(awk -W source='/\[CSDK::SIP\]/{flag=1} flag; /}/{flag=0}' "$file")		
    else
        sample=$(egrep -m 1 -e "\[CSDKEventLoop\]\ \-\ \[SIP\]\ " "$file")
        if [[ $sample != "" ]] && [[ $sample =~ \[CSDKEventLoop\]\ \-\ \[SIP\]\  ]]; then
# EqA 3.X
            vsyslog=53
			conv=$(awk -W source='/\[CSDK::SIP\]|\[CSDKEventLoop\] \- \[SIP\]/{flag=1} flag; /}/{flag=0}' "$file")			
        else
            sample=$(egrep -m 1 -e "\[onLogMessage\]\ >\ [RS]E" "$file")
            if [[ $sample != "" ]] && [[ $sample =~ \[onLogMessage\]\ \>\ [RS]E ]]; then
# AcAndroid 2.0    
          		vsyslog=54
				conv=$(awk -W source='/\[onLogMessage\] > [RS]E/{flag=1} flag; /}/{flag=0}' "$file")				  
            else
                sample=$(egrep -m 1 -e "\[cpcorevt\]\ [RS]E" "$file")
                if [[ $sample != "" ]] && [[ $sample =~ \[cpcorevt\]\ [RS]E ]]; then
# ACiPhone 2.1.x
                    vsyslog=65
					conv=$(awk -W source='/\[cpcorevt\] [RS]E/{flag=1} flag; /}/{flag=0}' "$file")					
                else
					sample=$(egrep -m 1 -e "\]\ SENT\ to\ |\]\ RECEIVED\ from\ |\]\ SENDING\ " "$file")
					if [[ $sample != "" ]] && [[ $sample != *"DBH:"* ]]; then
         	        	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for i" "$file")
                        if [[ $rec2 != 0 ]]; then 
# AC iPhone/iPad								
   	                        vsyslog=67
						fi
					else
	                    rec2=$(egrep -m 1 -c -e "^User-Agent:.*SIP Communicator" "$file")
                    	if [[ $rec2 != 0 ]]; then
# Avaya SIP Communicator/1xSIPIOS                            
                        	vsyslog=66
	                    else
    	                	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for MAC" "$file")
    		                if [[ $rec2 != 0 ]]; then 
# 1XC MAC							
            	                vsyslog=68
							else
                            	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Communicator for Microsoft Lync" "$file")
	                	        if [[ $rec2 != 0 ]]; then 
# ACLync									
    	                	        vsyslog=64
    	                    	else
        	                    	rec2=$(egrep -m 1 -c -e "^User-Agent:.*one-X Communicator.*Windows" "$file")
	            	                if [[ $rec2 != 0 ]]; then 
# 1XC										
    	            	                vsyslog=63
        	            	        else
            	        	            rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Engine.*Windows" "$file")
                	        	        if [[ $rec2 != 0 ]]; then
# FlareWin											
                	            	        vsyslog=62
                    	            	else
                        	            	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Experience" "$file")
	                            	        if [[ $rec2 != 0 ]]; then
# FlareExp												 
	                                	        vsyslog=61
        	                                else
            	                            	rec2=$(egrep -m 1 -c -e "^User-Agent:.*Flare Communicator" "$file")
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
} # explore_softclient()

function convert_siplog () {
	base64found=0
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
	sipin=0
	sipout=0

	reset_sipmsg

	if [[ $outfile != "" ]]; then
		newfile="$outfile.asm.tmp"
	else 
		newfile="$var.asm.tmp"
	fi
	if [ -f "$newfile" ]; then
		rm "$newfile"
	fi
	echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

	if [[ $var != $file ]]; then
		echo -e "# Input/output file: $var --> $file\n" >> "$newfile"
	else 
		echo -e "# Input/output file: $var\n" >> "$newfile"
	fi

#	conv=$(awk -e '/\[CSDK::SIP\]|\[CSDKEventLoop\] \- \[SIP\]|\[onLogMessage\] > SENDING|\[onLogMessage\] > RECEIVED|\[cpcorevt\] SENDING|\[cpcorevt\] RECEIVED/{flag=1} flag; /}/{flag=0}' "$file")
#	conv=$(awk -W source='/\[CSDK::SIP\]|\[CSDKEventLoop\] \- \[SIP\]|\[onLogMessage\] > SENDING|\[onLogMessage\] > RECEIVED|\[cpcorevt\] SENDING|\[cpcorevt\] RECEIVED/{flag=1} flag; /}/{flag=0}' "$file")

	while IFS= read -r line
	do
		linelength=${#line}
		nlines=$((nlines+1))

        if [[ $line == *"[CSDK::SIP]"* ]] || [[ $line == *"[CSDKEventLoop] - [SIP]"* ]] || [[ $line == *"[onLogMessage] > SENDING"* ]] || [[ $line == *"[onLogMessage] > RECEIVED"* ]] || [[ $line == *"[cpcorevt] SENDING"* ]] || [[ $line == *"[cpcorevt] RECEIVED"* ]]; then
			if [[ $((sipstart)) != 0 ]]; then
			   	complete_sipmsg
			fi

		    insidesip=1
			siptotalmsg=$((siptotalmsg+1))	
			base64found=0
			sip_direction
			get_sip_datetime
				  
        elif [[ $((vsyslog)) != 54 ]] && [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -lt 2 ]]; then
			insidesip=2
#		  	sipmsg_header
        elif [[ $((vsyslog)) == 54 ]] && [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
#			sipmsg_header
            if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
			    reset_sipmsg
				continue
			else			
			    sipmsg_header										
				start_sipmsg
			fi

		elif [[ $((vsyslog)) != 54 ]] && [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
            if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then			
			    reset_sipmsg
				continue
			else			
			    sipmsg_header										
				start_sipmsg
			fi				
				
		elif [[ $((sipstart)) == 1 ]]; then
		    if [[ $line =~ ^\} ]] && [[ $((linelength)) -lt 3 ]]; then
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
#	done < "$file"

	if [[ $((sipstart)) != 0 ]]; then
		complete_sipmsg
	fi
	echo '' >> "$newfile"

	if [[ $outfile == "" ]]; then
		outfile=$var
	fi

    if [[ $((sipstat)) != 0 ]]; then
		if [[ ${#endptaddr} == 0 ]]; then
			echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $outfile.asm file"
		else
			if [[ $((sipmsg)) == 0 ]]; then 
				echo "==> no SIP messages were found for addr=$endptaddr in $var file"
			else
				echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
				echo "    have been converted for addr=$endptaddr into $outfile.asm file"
			fi
		fi

		if [[ $useragent != "" ]]; then
			echo -e "$NL\tUser-Agent: $useragent"
			if [[ $foundipaddr != "" ]]; then
				echo -e "\tusing ipaddr = $foundipaddr"
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
	echo -e "\tTask started: $currtime - completed: $(date +%R:%S)"
	echo ''
	if [ -f "$outfile.asm" ]; then
		mv "$outfile.asm" "$outfile.asm.bak"
	fi
	mv "$newfile" "$outfile.asm"
	pwd; ls -l "$outfile.asm"			
#	rm $file					# this is already a tmp file, can be removed
	echo ''
} # convert_siplog()

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":hbf:k:sv:AI" options; do
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
	b)
		base64decode=0;;
	k)
		enckey=${OPTARG};;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	v) vsyslog=${OPTARG}
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
		elif [[ $var == "-v"* ]]; then
			skipper=2
		elif [[ $var == "-k"* ]]; then
			skipper=3
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
			vsyslog=$var
			if [[ $((vsyslog)) -lt 50 ]] || [[ $((vsyslog)) -gt 69 ]]; then
				vsyslog=1
			fi
		elif [[ $((skipper)) == 3 ]]; then
			enckey=$var
		fi
		skipper=0
		continue
	fi

	file=$var
	currtime=$(date +%R:%S)
	currdir=$PWD
	error=0
	outfile=""
	
	if [ -f "$file" ]; then
		echo -en "Exploring content in $var... stand by\r"

		tmpfile=0
		filecontent=""
		filetype=$(file -b "$file")

		if [[ $filetype == *"data"* ]] && [[ $filetype != *"archive"* ]]; then
			filecontent=$(egrep -m 1 "ANDROID:" $file >/dev/null)
			if [[ $filecontent =~ ANDROID ]]; then
				filecontent="ANDROID"
			elif [[ $enckey != "" ]]; then
				openssl version >/dev/null
				if [[ $? != 0 ]]; then
					if [[ $file == *"."* ]]; then
						outfile=$(echo "${file%.*}")
					else
						outfile="$file"
					fi
					outfile=$outfile"-decrypted.tgz"
#					openssl aes-128-cbc -d -salt -k $enckey -in $file -out "$outfile"
					openssl aes-256-ctr -md sha256 -salt -k $enckey -in "$file" -out "$outfile"
					if [[ $? == 0 ]]; then
#						openssl aes-256-ctr -md sha256 -salt -k $enckey -in "$file" -out "$outfile"
#						if [[ $? == 0 ]]; then
							error=6
							echo "error: Could not decode $var using \"openssl\" - verify encryption key with provider"
							echo '';exit $error
					else
						tmpfile=2
						file=$outfile
						filecontent="OPENSSL"
						filetype=$(file -b "$file")
					fi
				else
					error=5
					echo 'error: "openssl" was not found, required for decoding '$var
					echo ''; exit $error
				fi
			else
				error=4
				echo "error: missing encryption key.  Re-try with -k option."
				echo '';exit $error
			fi
		fi

		if [[ $filetype == *"compressed data"* ]] || [[ $filetype == *"archive"* ]]; then
			if [[ $file == *"."* ]]; then
				outfile=$(echo "${file%.*}")
			else
				outfile="$file"
			fi
			if [ -d "$outfile.tmp" ]; then
				rm -rf "$outfile.tmp"
			fi
			mkdir "$outfile.tmp"
			cd "$outfile.tmp"			
			unzip -qq -v >/dev/null
			if [[ $? == 0 ]] ; then
				unzip -qq "../$file"
				if [[ $? -gt 1 ]]; then
					tar --version >/dev/null
					if [[ $? == 0 ]]; then
						tar xf "../$file"
						if [[ $? != 0 ]]; then
							error=8
							echo "error: unable to uncompress $var, using \"tar\" utility."
							echo '';exit $error
						fi
					else
						error=8
						echo "error: could not uncompress $var, using unzip.  Suggest to deploy \"unzip\" package"
						echo '';exit $error
					fi
				fi
			else
				tar --version >/dev/null
				if [[ $? == 0 ]]; then
					tar xf "../$file"
					if [[ $? != 0 ]]; then
						error=8
						echo "error: could not uncompress $var, using \"tar\" utility"
						echo '';exit $error
					fi
				fi
			fi
			file=""
			if [ -d "logs" ]; then
				if [ -f UccLog.log ]; then
					file="$outfile.tmp/logs/UccLog.log"
				elif [ -f logs_app.log ]; then
					file="$outfile.tmp/logs/logs_app.log"
				elif [[ $var == *"Mac"* ]] || [[ $file == *"mac"* ]]; then
					file=$(ls -t1 logs/*.log | tail -1)
					file="$outfile.tmp/$file"
				elif [[ $file == *"Workplace"* ]]; then
					file=$(ls -t1 logs/Workplace*.log | tail -1)
					file="$outfile.tmp/$file"
				fi
			elif [ -d "Logs" ]; then
				if [ -f UccLog.log ]; then
					file="$outfile.tmp/Logs/UccLog.log"
				elif [ -f logs_app.log ]; then
					file="$outfile.tmp/Logs/logs_app.log"
				elif [[ $var == *"Mac"* ]] || [[ $file == *"mac"* ]]; then
					file=$(ls -t1 Logs/*.log | tail -1)
					file="$outfile.tmp/$file"
				elif [[ $file == *"Workplace"* ]]; then
					file=$(ls -t1 Logs/Workplace*.log | tail -1)
					file="$outfile.tmp/$file"
				fi
			else
				if [ -f UccLog.log ]; then
					file="$outfile.tmp/UccLog.log"
				elif [ -f logs_app.log ]; then
					file="$outfile.tmp/logs_app.log"
				elif [[ $file == *"Mac"* ]] || [[ $file == *"mac"* ]]; then
					file=$(ls -t1 *.log | tail -1)
					file="$outfile.tmp/$file"
				elif [[ $file == *"Workplace"* ]]; then
					file=$(ls -t1 Workplace*.log | tail -1)
					file="$outfile.tmp/$file"					
				fi
			fi
			if [[ $file == "" ]]; then
				echo "error: extracted $var does not include UccLog.log, logs_app.log, or Workplace.log file"
				echo ''; error=9
			fi
			cd ..
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
# 56) User-Agent: Avaya one-X Communicator for MAC 2.0.2.1 (ASC2.0.2.1-1) 
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

		rec=$(egrep -c -e "^CSeq:*" "$file")
    	rec2=$(egrep -c -e ".*\[CSDK::SIP\].*|.*\[CSDKEventLoop\] \- \[SIP\].*|.*\[onLogMessage\] > RECEIVED.*|.*\[onLogMessage\] > SENDING.*|.*\[cpcorevt\] SENDING.*|.*\[cpcorevt\] RECEIVED.*|\] SENDING |\] RECEIVED " "$file")

		if [[ $rec2 == 0 ]] || [[ $rec == 0 ]]; then
			echo "error: no SIP messages have been found in $var."
			echo "Perhaps this file is not a Communicator/Equinox/Workplace/ClientSDK log file..."
			echo "Or, debug/verbose diagnostic mode was not enabled."
			echo ''; error=1
	
		elif [[ $vsyslog == 0 ]]; then
			error=2; echo ''
   			echo -e "error: this file does not appear to be a Communicator/Equinox/Workplace/ClientSDK log file."
			echo -e "Or, debug/verbose diagnostic mode was not enabled during the capture."
			echo rec=$rec rec2=$rec2 vsyslog=$vsyslog useragent=$useragent
			echo ''; continue

    	elif [[ $((vsyslog)) -ge 60 ]] && [[ $((voutput)) == 1 ]]; then
		    siptotalmsg=$(egrep -c -e "^CSeq:.*" "$file")
			sipin=$(egrep -c -e "] SENDING |] SENT " "$file")
			sipout=$(egrep -c -e "] RECEIVED " "$file")
			if [[ $((vsyslog)) == 60 ]]; then
    	        sed 's/SIGNAL-VIDEO:/    SIGNAL:/g' "$file" > "$file.asm"
        	    echo "==> $siptotalmsg out of $rec SIP messages has been converted into $file.asm file"  # on test ipad SIPMessages.txt, sipin+sipoout=2084 but 2122
				echo ''
		    else
        	    echo "$vsyslog: No conversion required.  Use $file along with \"traceSM\" as it is."
				echo '' 
			fi

			if [[ $((sipstat)) == 1 ]] && [[ $useragent != "" ]]; then
		  		echo -e "\n\t$useragent"			
			  	echo -e "\tTotal # of SIP messages processed (RX/TX):\t\t$siptotalmsg ($sipin/$sipout)"
			  	echo ''
        	fi
			exit 0
		else
			convert_siplog
		fi
	else
		echo "error: file $var was not found."
		echo ''	
		error=3
	fi
done