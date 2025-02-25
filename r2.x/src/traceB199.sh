#!/bin/bash
version="2.0.0.1"
NL=$'\n'
AWKSRCFLAG="-W source="
today=$(date +%m/%d/%Y)
year=$(date +%Y)
endptaddr="" # 135.105.129.203
localip="1.1.1.1:1111"
protocol="TLS"
siplength=666
sipstat=1
# longestmsg=0
adjusthour=0
base64decode=1
bCAT=0
bDelTemp=1
alllogs=0
converted=0
findANI=""
vsyslog=0
voutput=1

## 20) b199-siptraces-r10109.txt - taken from B199 SIP buffer
## 15:58:39.516   pjsua_core.c  ...TX 668 bytes Request msg REGISTER/cseq=61127 (tdta0xc9237c) to TLS 135.64.253.72:5061:
## 21) syslog_newB199.txt, or tftpd64-syslog.txt which was created by tftpd64, or from wireshark SYSLOG UDP stream
## <30>Dec  3 09:41:49 phoneapp[1033]: pjsip: 09:41:49.069   pjsua_core.c  ...TX 706 bytes Request msg REGISTER/cseq=65380 (tdta0xd501b4) to TLS 11.222.1.32:5061:
## 15:58:39.516   pjsua_core.c  ...TX 668 bytes Request msg REGISTER/cseq=61127 (tdta0xc9237c) to TLS 135.64.253.72:5061:
## 22) b199-iso-SyslogCatchAll.txt, created by KIWI Syslog r8.x, default ISO log file format
## 2022-02-07 19:01:46	Daemon.Info	135.105.129.203	Feb  7 19:01:46 phoneapp[1088]: pjsip: 19:01:46.418   pjsua_core.c  ....TX 1350 bytes Request msg INVITE/cseq=15118 (tdta0x53f345c) to TLS 135.64.253.72:5061:
## 2022-02-07 19:01:46	Daemon.Info	135.105.129.203	Feb  7 19:01:46 phoneapp[1088]: INVITE sip:1200@135.64.253.72;transport=tls SIP/2.0
## 23) Mega syslog rfc3614 or auto-detect: Mega-rfc3164-B199-Syslog.txt
## 2022-02-07 18:12:59	3	6	1	135.105.129.203				Feb  7 19:12:59 phoneapp[1088]: pjsip: 19:12:59.471   pjsua_core.c  ....TX 1346 bytes Request msg INVITE/cseq=21691 (tdta0x53b31d4) to TLS 135.64.253.72:5061:				
## 24) visualsyslog-B199.txt / not good because phoneapp[1088]  / there is no ]: in the line
## 135.105.129.203	Feb  7 19:14:29		daemon	info	phoneapp[1088]	pjsip: 19:14:29.838   pjsua_core.c  ....TX 1350 bytes Request msg INVITE/cseq=26302 (tdta0x551c104) to TLS 135.64.253.72:5061: 

function usage ()  {
    echo "traceB199.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceB199.sh <OPTIONS> [<LOG_FILE> | <logreport> | <folder> ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the SIP message buffer pulled from Konftel 800 or Avaya B199 conf phone,"
	echo -e "\t<logreport>\tis the Logs.zip downloaded from B199 phone (which includes \"siptraces\" logbuffer)"
	echo -e "\t<folder>\tincludes one or more of the log files extracted from logreport,"	
	echo -e "\t\tor a syslog capture taken using either a remote syslog server (KIWI, tftpd64, or MEGA),"
	echo -e "\t\tor a syslog txt stream collected from network packet trace (via Follow UDP stream),"
	echo -e "\t\tor a native pcap network trace including unsecure syslog traffic (requires \"tshark\")\n"
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"	
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
#	echo -e "\t-v X:\t\tenforce input format to X (=vsyslog)"
	echo ''
} # usage()

function reset_sipmsg () {
	dirdefined=0
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	siphour=0
	base64found=0
#	uptime=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1; siplines=$((siplines+1))
	siptotalmsg=$((siptotalmsg+1))

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

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile.b64" ]]; then
		blines=$(wc -l < "$newfile.b64")
		siplines=$((siplines+$blines))
		base64 -d "$newfile.b64" >> "$newfile"
		rm "$newfile.b64"
		base64found=0
		base64msg=$((base64msg+1))
	fi

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

	case $voutput in
	1)	echo -e "[$sipstream] }\x0d$NL" >> "$newfile";;
	2)	echo -e "$NL}$NL" >> "$newfile";;
	3)	echo -e "--------------------" >> "$newfile";;
	esac

	reset_sipmsg
fi
} #complete_sipmsg

function sipmsg_header () {
if [[ $((dirdefined)) != 0 ]]; then
	if [[ $foundipddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
		reset_sipmsg
	elif [[ $sipdate == "" ]] || [[ $siptime == "" ]] || [[ $ip == "" ]]; then
		echo -e "\nerror: failed to grab message header items at msg# $((n+1)) at line# $nlines of $basefile"
		echo "sipdate=$sipdate siptime=$siptime ip=$ip dirdefined=$dirdefined dirstring=$dirstring1 vsyslog=$vsyslog"
		echo "line=$line"; echo "Contact developer."; exit 1
	else	
		n=$((n+1)); 	sipstart=0
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted            \r"
			else
				echo -en "$var => $n/$rec Msgs converted            \r"
			fi
		fi
		case $voutput in
		1)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
		2)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi
} #sipmsg_header

function sip_partnum () {
	if [[ $line == *"[Part "* ]]; then
		partnum=$(awk -F "Part " '{print $2}' <<< "$line" | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
			maxpart=$(awk -F "Part " '{print $2}' <<< "$line" | cut -d' ' -f3 | cut -d']' -f1)            # awk '{print $3}' | awk -F ']' '{print $1}')
			# maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d ' ' -f 3)
		fi	
		sipsplit=1
	fi
} # sip_partnum ()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $((vsyslog)) -gt 19 ]]; then
		if [[ $line == *"Request"* ]]; then
			if [[ $line == *" to "* ]]; then
				dirdefined=2; sipstream=1474				
					## header=$(echo -e $direction "to" $ip1":"$ip2". Length=" $siplength".")
					## elif [[ $direction == 'Response' ]]; then
			elif [[ $line == *" from "* ]]; then
				dirdefined=1; sipstream=5f70				
			fi
		elif [[ $line == *"Response"* ]]; then
			if [[ $line == *" to "* ]]; then
				dirdefined=2; sipstream=1474				
					## header=$(echo -e $direction "to" $ip1":"$ip2". Length=" $siplength".")
					## elif [[ $direction == 'Response' ]]; then
			elif [[ $line == *" from "* ]]; then
				dirdefined=1; sipstream=5f70				
			fi
					## header=$(echo -e $direction "from" $ip1":"$ip2". Length=" $siplength".")
		fi
	fi

	if [[ $((dirdefined)) == 1 ]]; then	
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)	dirstring1="-->"; 	dirstring2="ingress";;
		esac
	elif [[ $((dirdefined)) == 2 ]]; then
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	fi

	if [[ $((vsyslog)) -gt 19 ]] && [[ $((dirdefined)) != 0 ]]; then
#		if [[ $((vsyslog)) == 20 ]]; then
#			ip=$(echo $line | cut -d' ' -f15)
		case $vsyslog in
		23)	ip=$(awk '{print $23}' <<< "$line");;
		24)	ip=$(awk '{print $20}' <<< "$line");;
		25)	ip=$(awk '{print $NF}' <<< "$line");;		
		*)	ip=$(awk '{print $(NF)}' <<< "$line");;
		esac

		ip1=$(cut -d':' -f1 <<< "$ip") 		# awk -F ":" '{print $1}')
		ip2=$(cut -d':' -f2 <<< "$ip")		# awk -F ":" '{print $2}')
		ip="$ip1:$ip2"

		case $vsyslog in
		20)
#			siplength=$(echo "$line" | cut -d' ' -f7) # awk '{print $9}')
			if [[ $line == *"AvayaB199-"* ]]; then
				siplength=$(awk '{print $11}' <<< "$line")
			else
				siplength=$(awk '{print $4}' <<< "$line")
			fi
			foundipaddr="";;
		21)
			siplength=$(awk '{print $9}' <<< "$line") 
			foundipaddr="";;		
		22)
			siplength=$(awk '{print $13}' <<< "$line")
			foundipaddr=$(cut -d' ' -f4 <<< "$line");;
		23)
			siplength=$(awk '{print $15}' <<< "$line")
			foundipaddr=$(cut -d' ' -f6 <<< "$line");;
		24)
			siplength=$(awk '{print $12}' <<< "$line")
			foundipaddr=$(cut -d' ' -f1 <<< "$line");;
		25)
			siplength=$(awk -F".TX |.RX " '{print $2}' <<< "$line" | cut -d' ' -f1);;		
#			siplength=$(echo "$line"   | cut -d' ' -f9) # awk '{print $12}')
# KT800 phoneapp:
# Jun 20 13:41:12 konftel800bp-C81FEAC9F98C daemon.info phoneapp[1095]: pjsip: 13:41:12.329   pjsua_core.c  .TX 591 bytes Request msg REGISTER/cseq=15466 (tdta0x10cdbc4) to UDP 10.134.117.194:5060:
#			siplength=$(awk '{print $9}' <<< "$line");;
#			siplength=$(echo "$line"   | awk -F"pjsua_core.c" '{print $2}' | awk '{print $2}')    #cut -d' ' -f3) # awk '{print $12}')
#			foundipaddr=$(echo "$line" | cut -d' ' -f6)
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
	case $vsyslog in
	20)
		sipyear=$(cut -d'/' -f3 <<< "$today")			
## 15:58:39.516   pjsua_core.c  ...TX 668 bytes Request msg REGISTER/cseq=61127 (tdta0xc9237c) to TLS 135.64.253.72:5061:
## Sep 28 14:48:16 AvayaB199-C81FEAA88DDE daemon.info phoneapp[7262]: pjsip: 14:48:16.470   pjsua_core.c  ....TX 1252 bytes Request msg INVITE/cseq=27165 (tdta0x539d99c) to TLS 10.134.117.194:5061:
		if [[ $line == *"AvayaB199-"* ]]; then						# this is a logs_phoneapp.log file
			sipday=$(awk '{print $2}' <<< "$line")				#cut -d' ' -f2)
			month=$(cut -d' ' -f1 <<< "$line")
			get_sipmonth
			convtime=$(awk '{print $8}' <<< "$line")				# cut -d' ' -f1)
		else			
			sipday=$(cut -d'/' -f2 <<< "$today")
			sipmonth=$(cut -d'/' -f1 <<< "$today")	
			convtime=$(cut -d' ' -f1 <<< "$line")
		fi;;
	21)
# <30>Dec  3 09:41:49 phoneapp[1033]: pjsip: 09:41:49.069   pjsua_core.c  ...TX 706 bytes Request msg REGISTER/cseq=65380 (tdta0xd501b4) to TLS 11.222.1.32:5061:	
		sipyear=$(cut -d'/' -f3 <<< "$today")
		sipday=$(awk '{print $2}' <<< "$line")					# cut -d' ' -f2)
		sipmonth=$(cut -d' ' -f1 <<< "$line")
		month=$(cut -d'>' -f2 <<< "$sipmonth")
		convtime=$(awk '{print $6}' <<< "$line")
		get_sipmonth;;		
	22)
# 2022-02-07 19:01:46     Daemon.Info     135.105.129.203 Feb  7 19:01:46 phoneapp[1088]: pjsip: 19:01:46.418   pjsua_core.c  ....TX 1350 bytes Request msg INVITE/cseq=15118 (tdta0x53f345c) to TLS 135.64.253.72:5061:	
		convdate=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d'-' -f1 <<< "$convdate")
		sipmonth=$(cut -d'-' -f2 <<< "$convdate")
		sipday=$(cut -d'-' -f3 <<< "$convdate")
		convtime=$(awk '{print $10}' <<< "$line");;
	23)
		convdate=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d'-' -f1 <<< "$convdate")
		sipmonth=$(cut -d'-' -f2 <<< "$convdate")
		sipday=$(cut -d'-' -f3 <<< "$convdate")
#		sipdate=$(echo $convdate | awk -F '-' '{print $2"/"$3"/"$1}')
		convtime=$(awk '{print $12}' <<< "$line");;
	24)
# 135.105.129.203 Feb  7 19:14:29         daemon  info    phoneapp[1088]  pjsip: 19:14:29.838   pjsua_core.c  ....TX 1350 bytes Request msg INVITE/cseq=26302 (tdta0x551c104) to TLS 135.64.253.72:5061:	
		sipyear=$(cut -d'/' -f3 <<< "$today")
		sipday=$(awk '{print $3}' <<< "$line")					# cut -d' ' -f3)
		month=$(awk '{print $2}' <<< "$line")
		convtime=$(awk '{print $9}' <<< "$line")
		get_sipmonth;;		
#		convtime=$(echo "$line" | awk -F"pjsip: " '{print $2}' | cut -d' ' -f1) 					# awk '{print $9}')
	25)															# syslog extracted via tshark
# KT800 phoneapp:
# Jun 20 13:41:12 konftel800bp-C81FEAC9F98C daemon.info phoneapp[1095]: pjsip: 13:41:12.329   pjsua_core.c  .TX 591 bytes Request msg REGISTER/cseq=15466 (tdta0x10cdbc4) to UDP 10.134.117.194:5060:

		sipyear=$(cut -d'/' -f3 <<< "$today")
		sipday=$(awk '{print $2}' <<< "$line")					# cut -d' ' -f2)
		month=$(cut -d' ' -f1 <<< "$line")
		convtime=$(awk -F"pjsip: " '{print $2}' <<< "$line" | cut -d' ' -f1) 					# awk '{print $9}')
		get_sipmonth;;
#		convtime=$(echo "$line" | cut -d' ' -f9) # awk '{print $9}')
	esac

	# foundipaddr=$(echo "$line" | cut -d' ' -f5)
	if [[ ${#sipmonth} -lt 2 ]]; then
		sipmonth="0$sipmonth"
	fi

	if [[ ${#sipday} -lt 2 ]]; then
		sipday="0$sipday"
	fi

	siphour=$(cut -d':' -f1 <<< "$convtime")
	sipmin=$(cut -d':' -f2 <<< "$convtime")	
	sipsec=$(cut -d':' -f3 <<< "$convtime"  | cut -d'.' -f1)	
	sipmsec=$(cut -d':' -f3 <<< "$convtime" | cut -d'.' -f2)

	if [[ $((adjusthour)) == 1 ]]; then
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) 	## TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) 		## TODO need to print 2 digits
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
	# siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec)
} # get_sip_datetime()

function explore_logfolder() {
	file=""; filelist=""
	targetfiles="siptraces siptraces.log logs_phoneapp.log logs_pjsip.log messages.log"

	for xfile in $targetfiles
	do
		if [ -d "tmp" ] && [ -s "tmp/$xfile" ]; then
			n=$(egrep -c "CSeq:" "tmp/$xfile" 2>/dev/null)	
			if [[ $((n)) -gt 0 ]]; then
				if [[ $file == "" ]]; then
					file="$destdir/tmp/$xfile"
				fi
				filelist="$filelist $destdir/tmp/$xfile"
			fi
		elif [ -s "$xfile" ]; then
			n=$(egrep -c "CSeq:" "$xfile" 2>/dev/null)
			if [[ $((n)) -gt 0 ]]; then
				if [[ $file == "" ]]; then								
					file="$destdir/$xfile"
				fi
				filelist="$filelist $destdir/$xfile"
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

	if [ -d "log" ] || [ -d "logs" ]; then
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
		echo -e "\nerror: could not find either \"siptraces.log\", \"logs_phoneapp.log\", \"logs_pjsip.log\" or \"messages.log\" files in $folder\n"
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

#	echo "                                                                                                                                                  "
	rec=$(egrep -c '\-\-end msg\-\-' "$file")
	rec2=$(egrep -m 1 -c -e "^CSeq:*" "$file")	

	if [[ $((rec)) == 0 ]]; then
		echo -e "\nerror: $file is not a valid B199/KT800 logfile."
		rec=$(egrep -c "CSeq:" "$file")
		if [[ $((rec)) != 0 ]]; then
			error=1
			echo "Though found $rec potential SIP messages within $basefile"
		else
			echo 'In fact, no sign of any "CSeq:" lines within '$basefile
			error=2
		fi

		rec=$(egrep "konfsip" "$file" | egrep -c -e ": RX|: TX")
		rec2=$(egrep "konfsip" "$file" | egrep "info" | egrep -c -e "RX |TX ")		
		if [[ $((rec)) != 0 ]] || [[ $((rec2)) != 0 ]]; then
			echo "$basefile may come from a B179 device.   Use 'traceB179.sh' script instead."
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

		rec=0; rec2=0

	elif [[ $((rec2)) != 0 ]]; then
		n=$(egrep -c -m 1 "pjsua_core" "$file")
		if [[ $((n)) == 1 ]]; then
			prevline=$(egrep -m 1 "phoneapp" "$file")

			if [[ $prevline =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then						# syslog extracted via tshark
				vsyslog=25
			elif [[ $prevline =~ ^\<[0-9]{2}\>[JFMASOND][[:lower:]][[:lower:]]\  ]]; then		# syslog out of pcap, see ade_b199-pcapsyslog.txt
				vsyslog=21
			else
				n=$(egrep -c -m 1 "Daemon\.Info" "$file")
				if [[ $((n)) == 1 ]]; then
					vsyslog=22																	# syslogCatchAll KIWI
				else
					n=$(egrep -m 1 "daemon" "$file" | egrep -c -m 1 "info")
					if [[ $((n)) == 1 ]]; then
						vsyslog=24
					else
						prevline=$(cut -d' ' -f5 <<< $prevline)									# cut -d' ' -f6)
						if [[ $prevline == "phoneapp"* ]]; then
							vsyslog=23
						else
							vsyslog=20						
						fi
		                prevline=""						
					fi
				fi
			fi
		else
			n=$(egrep -c -m 1 "^<[0-9]{2}>" "$file")
			if [[ $((n)) == 1 ]]; then
				vsyslog=21
			else
				n=$(egrep -c -m 1 "Daemon\.Info" "$file")
				if [[ $((n)) == 1 ]]; then
					vsyslog=22
				else
					n=$(egrep -m 1 "daemon" "$file" | egrep -c -m 1 "info")
					if [[ $((n)) == 1 ]]; then
						vsyslog=24
					else
						prevline=$(cut -d' ' -f5 <<< $prevline)							# cut -d' ' -f6)
						if [[ $prevline == "phoneapp"* ]]; then
							vsyslog=23
						fi
	        	        prevline=""						
					fi
				fi
			fi
		fi
	fi

	# rec=$(egrep "\-\-end msg\-\-" "$file" | wc -l)
	if [[ $((vsyslog)) == 0 ]]; then
		if [[ $file =~ \.asm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
			footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
			if [[ $footprint == 1 ]]; then
				echo -e "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
			fi
		elif [[ $var != $file ]]; then
	        error=4
		   	echo -e"\nerror: unknown file formwat - could not detect input file as a valid B199 log source."
			echo -e "Verify source and content of $var -> $basefile.\n"
		else
	        error=4
		   	echo -e"\nerror: unknown file formwat - could not detect input file as a valid B199 log source."
			echo -e "Verify source and content of $basefile\n"
		fi
	else
		logsec=$SECONDS
		base64msg=0
		foundipaddr=""
		useragent=""
		output=""
		newfile=""
		prevline=""
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
		sipmaxsplit=0
		sipwordlist=""
		longestsipword=""
		longestmsg=0
		firstmsg=""
		lastmsg=""
		timefirst=""
		timelast=""
		callID=""
		calltime=""
		callDIR=0
		nlines=0
		n=0
		sipin=0
		sipout=0
		sipmsg=0

        reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo -e "You may want to execute this script on a more powerful PC or server.\n"
		fi		

		##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
#    	conv=$(awk -e '/bytes R/{flag=1} flag; /}/{flag=0}' "$file")		# not good for AWK v3.1.7 on SM7.0.1
	   	conv=$(awk -W source='/bytes R/{flag=1} flag; /}/{flag=0}' "$file")			

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

		if [[ $var != $file ]]; then
			echo -e "# Input/output file history: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file history: $var -> $output.asm\n" >> "$newfile"
		fi

		while IFS= read -r line
		do
			nlines=$((nlines+1))
			if [[ $line == *" bytes R"* ]] && [[ $line != *"konfsip"* ]]; then 						# ignore konfsip from B179, in mixed syslog			
				if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
					 continue
				fi
				insidesip=1
				get_sip_datetime
				sip_direction
				sipmsg_header
			# elif [[ $line == *"]:"* ]] || [[ $line == *"]"* ]]; then
			elif [[ $((vsyslog)) == 20 ]] || [[ $line == *"]"* ]]; then
				if [[ $((vsyslog)) == 24 ]]; then
					line=$(awk -F ']' '{print $2}' <<< "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')
				elif [[ $((vsyslog)) != 20 ]] || [[ $line == *"AvayaB199-"* ]]; then
					line=$(awk -F ']: ' '{print $2}' <<< "$line")
				fi

				if [[ $line == "--end msg--"* ]]; then
					complete_sipmsg
				elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
						start_sipmsg
				elif [[ $((sipstart)) !=  0 ]];	then
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
						if [[ -f "$newfile.b64" ]]; then
							rm "$newfile.b64"
						fi
					elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
						echo "$line" >> "$newfile.b64"
					else
						if [[ $line == "^M" ]]; then
							line=""
						fi
						echo "$line" >> "$newfile"
						siplines=$((siplines+1))
						get_useragent
					fi
				fi				
			fi
		done <<< "$conv"

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
					echo "    has been converted for addr=$endptaddr into $output.asm file"
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
				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages: $base64msg"
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
  while getopts ":he:bf:sdv:ACN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	A)
		alllogs=1;;
	C)
		bCAT=1;;
	d)
		bDelTemp=0;;
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	e)
		endptaddr=${OPTARG};;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;

	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 20 ]] || [[ $((vsyslog)) -gt 24 ]]; then
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
		elif [[ $var == "-v"* ]]; then
			skipper=2
		elif [[ $var == "-e"* ]]; then
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
			vsyslog=$var
			if [[ $((vsyslog)) -lt 20 ]] || [[ $((vsyslog)) -gt 24 ]]; then
				vsyslog=1
			fi
		elif [[ $((skipper)) == 3 ]]; then
			endptaddr=$var
		elif [[ $((skipper)) == 4 ]]; then
			findANI=$findANI		# findANI=$var
		fi
		skipper=0
		continue
	fi

	file=""; filelist=""; folder=""
	filetype="";	filetype2=""
	currtime=$(date +%R:%S); currdir=$PWD
	bdir="";	bvar=""; basefile=""
	target="";	destdir=""; input=""
	tmpfile=0; 	n=0;	error=0; 	vsyslog=0

	bSinglefile=0;	filecontent="B199"
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
		target="B199"
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

	if [ -d "$var" ]; then
		echo -en "\nExploring content in $var folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"
		file="$var"

		if [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "B199" ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")			
			fi
	
			if [[ $bUnzip != 0 ]]; then			
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
						error=7; cd $currdir; input=""; continue
					fi
				fi

				mkdir "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not create $input.tmp folder in $PWD.\n"
					error=7; cd $currdir; input=""; continue
				fi

				cd "$input.tmp"			
				echo -e "\nUncompressing $var into $input.tmp ...                                                                          "			

				unzip -qq "../$file" 2>/dev/null
				if [[ $? != 0 ]]; then
					cd ..
					if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
						rm -rf "$input.tmp"	2>/dev/null
					fi
					echo -e "\nerror: could not uncompress $var, using unzip."
					echo -e "Suggesting to validate \"unzip\" manually on \"$bfile\".\n"
					error=8; cd $currdir; input=""; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
				fi
				cd $currdir
			else
				echo -e "\nerror: could not uncompress $var, \"unzip\" utility not found."
				echo -e "Suggesting to deploy \"unzip\" package. in Ubuntu, you can install it by typing: \"sudo apt install unzip\".\n"
				error=8; continue
			fi

		elif [[ $filetype == *"compressed data"* ]]; then
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
				if [[ $filetype2 =~ ASCII|text|data ]]; then
					if [[ $bfile == *"."* ]]; then
						input2=${bfile%.*}
					else
						input2="$bfile"
					fi

					if [[ $bGunzip != 0 ]]; then
						echo "Uncompressing $zfile into $input2 ...                                                                     "
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
						echo -e "\nerror: could not delete existing $input.tmp folder."
						echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
						error=7; cd $currdir; input=""; continue
					fi
				fi

				mkdir "$input.tmp" 2>/dev/null
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
			else
				echo -e "\nerror: unable to uncompress $bvar, \"tar\" utility not found.\n"
				error=1; continue
			fi


		elif [[ $filetype =~ capture ]]; then
			if [[ $filetype =~ tcpdump ]] || [[ $filetype =~ pcap ]]; then
		  		line=$(whereis tshark)
				tshark --version >/dev/null 2>&1

				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
		     		echo -e "\nerror: unable to locate 'tshark' command."
					echo -e "'tshark' is required to extract syslog messages from $var wireshark capture into text file.\n"
					error=10; continue
				else
					if [[ $endptaddr != "" ]]; then
				    	tshark -r $file -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi
					if [ -s "$file.syslog2" ]; then
						sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
					else
						echo -e "\nerror: could not extract any SYSLOG packets from $file using \"tshark\" command.\n"
						error=11; continue
					fi
					if [ -s "$file.syslog" ]; then
						input="$file"
#						rm "$file.syslog2"
						file="$file.syslog"; tmpfile=2
						filecontent="syslog"
						bSinglefile=1
#						vsyslog=25
					else
						echo -e "\nerror: problem occured transforming $file.syslog2 into $file.syslog. Contact developer.\n"
						error=12; continue						
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
		echo -e "\nerror: $bvar was not found or unable to open. Verify path and filename."
		error=3

	elif [[ $file == "" ]] && [[ $error == 0 ]]; then
		echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
		error=4

	elif [ -f "$var" ]; then
		echo -e "\nerror: $bvar is an empty file."
		ls -l "$var"; error=3
	fi

	if [[ $error != 0 ]]; then
		continue
	fi

	if [[ $filelist != "" ]] && [[ $file != $filelist ]]; then		
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
			echo -e "\nConcatenating for $var into $ctarget"
			echo -e "However, on B199/Konftel 800 phones, this means simply duplicating the SIP message flows multiple times...\n"
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
		echo -e "\nConcatenating for $var into $ctarget"
		echo -e "# Concatenating for $var\n" > "$ctarget"
	fi

	nfiles=0
	if [[ $((alllogs)) != 0 ]]; then
		if [[ $filelist != "" ]]; then
			nfiles=$(echo $filelist | wc -w)
		elif [[ $file != "" ]]; then
			nfiles=1
		fi

		if [[ $((nfiles)) -gt 1 ]] && [[ $filelist != "" ]]; then
			echo "Warning: about to convert multiple files ($nfiles x siptraces or logs_phoneapp) found in $var"
			echo "This may take a while... you may want to execute the script on a more powerful PC or server."
			echo -e "FYI: on B199/Konftel 800 phones all of the logfiles include the same SIP message flow ...\n"

			if [[ $((bCAT)) != 0 ]]; then
				if  [ -f "$ctarget" ]; then
					mv "$ctarget" "$ctarget.bak"
				fi
				echo -e "Concatenating $var into $ctarget\n"
				echo -e "# Concatenating for $var\n" > "$ctarget"
			fi

			let z=0; file=""
			for file in $filelist;
			do
				z=$(egrep -m 1 -c "CSeq:" "$file")
				if [[ $z != 0 ]]; then
					convert_siplog
				else
					echo -e "\n$file : No SIP messages have been found."
				fi
				currtime=$(date +%R:%S)
			done	

			if [[ $((bCAT)) != 0 ]] && [ -f "$ctarget" ]; then
				echo -e "All converted files found in $bvar have been concatenated into $ctarget\n"
				ls -l "$ctarget"; echo ''
			fi

		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			convert_siplog				
		fi

	elif [[ $file != "" ]]; then
		convert_siplog
	fi

	if [[ $bDelTemp != 0 ]]; then
		if [[ $tmpfile != 0 ]] && [[ $var != $file ]] && [ -f "$file" ]; then
			rm "$file"
		fi
		if [[ $input != "" ]]; then
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp"
			elif [ -f "$input" ]; then
				rm "$input"
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