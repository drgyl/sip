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
fidnANI=""
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
smaddr=""
voutput=3  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0
conv2asm=0

# TODO tshark extract SYSLOG + more syslog server formats

function usage ()  {
    echo "traceASM62.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t\tcreated by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceASM62.sh [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the SIP logfile (collected from ASM r6.2 server - using CallLogs INFO),"
	echo -e "\t\t\tor the SM TraceViewerExport file, or syslog sent by ASM server by itself."
	echo -e "\t\t\tSyslog can be either plain text (from remote Syslog srvr), or native pcap capture,"
	echo -e "\t\t\tor text extracted from Follow UDP stream within Wireshark."
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"						
	echo -e "\t-i \t\tconvert syslog messages only sent by SM IP addr: a.b.c.d"						
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"	
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	dirdefined=0	
	base64found=0
	ip=""; 	eip=""; elocalip=""; listenerip=""
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
	1)	echo -e "[$sipstream] }\x0d$NL" >> "$newfile";;
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
		echo "line=$line"; echo "Contact developer."; exit 1
	else	
		sipstart=0; n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then		
			echo -en "$var => $n/$rec Msgs converted            \r"
		fi

		case $voutput in
		1)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
		2)	echo -e "# msgno: $((sipmsg+1)){$NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi
} # sipmsg_header() 

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $((vsyslog)) == 1 ]] && [[ $line == *": Incoming "* ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)		dirstring1="-->"; 	dirstring2="ingress";;
		esac
	elif [[ $((vsyslog)) == 1 ]] && [[ $line == *": Outgoing "* ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	elif [[ $((vsyslog)) == 2 ]] && [[ $line == *"--> 	octets:"* ]]; then		
		sipstream=5f70;				dirdefined=1
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="RECEIVED";	dirstring2="from"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="RECEIVED";	dirstring2="from"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="-->";		dirstring2="ingress"
		fi
		siplength=$(awk -F"octets: " '{print $2}' <<< "$line"  | cut -d',' -f1)
		if [[ $line == *"ingress: {"* ]]; then		
			ingline=$(awk -F"ingress: { L" '{print $2}' <<< "$line" | cut -d'}' -f1)
			protocol=$(cut -d'/' -f3 <<< "$ingline")
			localip=$(cut -d'/' -f1 <<< "$ingline")
			ip=$(cut -d'R' -f2 <<< "$ingline" | cut -d'/' -f1)
		fi
		if [[ $line == *"egress: {"* ]]; then
			ingline=$(awk -F"egress: { L" '{print $2}' <<< "$line" | cut -d'}' -f1)
			elocalip=$(cut -d'/' -f1 <<< "$ingline")
			eip=$(cut -d'R' -f2 <<< "$ingline" | cut -d'/' -f1)
		fi
		if [[ $line == *" Listener: {"* ]]; then
			listenerip=$(awk -F" Listener: { " '{print $2}' <<< "$line" | cut -d' ' -f1)
		fi

	elif [[ $((vsyslog)) == 2 ]] && [[ $line == *"<-- 	octets:"* ]]; then			
		sipstream=1474;				dirdefined=2
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="SENT";		dirstring2="to"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="SENDING";	dirstring2="to"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="<--";		dirstring2="egress"			
		fi
		siplength=$(awk -F"octets: " '{print $2}' <<< "$line"  | cut -d',' -f1)
		if [[ $line == *"ingress: {"* ]]; then		
			ingline=$(awk -F"ingress: { L" '{print $2}' <<< "$line" | cut -d'}' -f1)
			protocol=$(cut -d'/' -f3 <<< "$ingline")
			localip=$(cut -d'/' -f1 <<< "$ingline")
			ip=$(cut -d'R' -f2 <<< "$ingline" | cut -d'/' -f1)
		fi
		if [[ $line == *"egress: {"* ]]; then
			ingline=$(awk -F"egress: { L" '{print $2}' <<< "$line" | cut -d'}' -f1)
			elocalip=$(cut -d'/' -f1 <<< "$ingline")
			eip=$(cut -d'R' -f2 <<< "$ingline" | cut -d'/' -f1)
		fi
		if [[ $line == *" Listener: {"* ]]; then
			listenerip=$(awk -F" Listener: { " '{print $2}' <<< "$line" | cut -d' ' -f1)
		fi

	elif [[ $((vsyslog)) == 4 ]] && [[ $line == *"-->"* ]]; then
		sipstream=5f70;				dirdefined=1
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="RECEIVED";	dirstring2="from"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="RECEIVED";	dirstring2="from"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="-->";		dirstring2="ingress"
		fi
	elif [[ $((vsyslog)) == 4 ]] && [[ $line == *"<--"* ]]; then
		sipstream=1474;				dirdefined=2
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="SENT";		dirstring2="to"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="SENDING";	dirstring2="to"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="<--";		dirstring2="egress"			
		fi	
	elif [[ $((vsyslog)) == 5 ]] && [[ $line == *" --> "* ]]; then
		sipstream=5f70;				dirdefined=1
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="RECEIVED";	dirstring2="from"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="RECEIVED";	dirstring2="from"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="-->";		dirstring2="ingress"
		fi
	elif [[ $((vsyslog)) == 5 ]] && [[ $line == *" <-- "* ]]; then
		sipstream=1474;				dirdefined=2
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="SENT";		dirstring2="to"
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="SENDING";	dirstring2="to"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="<--";		dirstring2="egress"			
		fi	
	else
		insidesip=0
		dirdefined=0
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
# 2012-10-01 15:43:14,862 CallLogs INFO - : Outgoing Message
	if [[ $((vsyslog)) == 1 ]]; then 			# ASM6.2 SipTrace CallLogs INFO
		sipmsec=$(cut -d' ' -f2 <<< "$line")	
		sipday=$(cut -d' ' -f1 <<< "$line")	
		sipyear=$(cut -d'-' -f1 <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
		sipday=$(cut -d'-' -f3 <<< "$sipday")
									
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d',' -f2 <<< "$sipsec")
		sipsec=$(cut -d',' -f1 <<< "$sipsec")
	elif [[ $((vsyslog)) == 2 ]]; then
		sipmsec=$(cut -d' ' -f13 <<< "$line")	
		sipday=$(cut -d' ' -f12 <<< "$line")
		sipyear=$(cut -d'/' -f3 <<< "$sipday")
		sipmonth=$(cut -d'/' -f2 <<< "$sipday")
		sipday=$(cut -d'/' -f1 <<< "$sipday")

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")
	elif [[ $((vsyslog)) == 3 ]]; then
		sipsec=""
	elif [[ $((vsyslog)) == 4 ]]; then
		sipmsec=$(cut -d' ' -f2 <<< "$line")	
		sipday=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d'/' -f3 <<< "$sipday")
		sipmonth=$(cut -d'/' -f2 <<< "$sipday")
		sipday=$(cut -d'/' -f1 <<< "$sipday")

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")

	elif [[ $((vsyslog)) == 5 ]]; then				# or, sipdate= | cut -d' ' -f16| cut -d'>' -f3 , siptime= | cut -d' ' -f17
		sipmsec=$(cut -d' ' -f4 <<< "$line")
		sipday=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d'-' -f1 <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
		sipday=$(cut -d'-' -f3 <<< "$sipday")

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")
		sipmsec=$(cut -d' ' -f9 <<< "$line")		
	fi

	case $voutput in
	1)	sipdate=$(echo $sipmonth/$sipday/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec);;
	2)	sipdate=$(echo $sipyear/$sipmonth/$sipday)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec);;
	3)	sipdate=$(echo $sipday/$sipmonth/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec.$sipmsec);;
	esac
} # get_sip_datetime()

function convert_asm () {
while IFS= read -r line
do
	if [[ $((vsyslog)) == 2 ]] && [[ $line =~ AasSipMgr ]]; then 
		insidesip=0
	fi
	if [[ $((vsyslog)) == 5 ]]; then
		if [[ $line =~ AasSipMgr ]]; then
			if [[ $smaddr != "" ]] && [[ $line != *$smaddr* ]]; then
				continue
			elif [[ $line == *"SIPMSGT+ "* ]] && [[ $((insidesip)) != 0 ]]; then
				line=$(awk -F"SIPMSGT+" '{print $2}' <<< "$line")
				sed 's/<013><010>/\n/g' <<< "$line" | sed 's/<010>//g' >> "$newfile"	
				if [[ $line == *"--------------------" ]]; then
					insidesip=0
				fi
			elif [[ $line == *"SIPMSGT "* ]]; then
				n=$((n+1))
				insidesip=1
				echo -en "$n => $rec Msgs converted            \r"
				line=$(awk -F"SIPMSGT " '{print $2}' <<< "$line")
				echo "com.avaya.asm  SIPMSGT " >> "$newfile"
				echo "--------------------" >> "$newfile"
				awk -F"--------------------" '{print $2}' <<< "$line" | sed 's/<010><009>/\n/g' | sed 's/<010>//g' >> "$newfile"
				echo "--------------------" >> "$newfile"							
				awk -F"--------------------" '{print $3}' <<< "$line" | tr -d "\r" | sed 's/<013><010>/\r\n/g' | sed 's/<010>//g' >> "$newfile"
				awk -F"--------------------" '{print $2}' <<< "$line" | sed 's/<010><009>/\n/g' | sed 's/<010>//g'	
				if [[ $line == *"--------------------" ]]; then
					insidesip=0
				fi
			fi
		else
			continue
		fi				

	elif [[ $((vsyslog)) == 4 ]] && [[ $line == *"com.avaya.asm"* ]]; then
		if [[ $line == *"SIPMSGT+"* ]]; then
			if [[ $((insidesip)) -lt 4 ]]; then 					
				line=$(awk -F"+ " '{print $2}' <<< "$line")
				prevline=$(tr -d "\r\n" <<< "$line")
				echo "$prevline$line" >> "$newfile"										# SURE???
				prevline=""
			else
				insidesip=0
			fi
		else
			insidesip=1
			prevline=""						
			echo "com.avaya.asm  SIPMSGT " >> "$newfile"
			n=$((n+1))				
			echo -e "# msgno: $n" >> "$newfile"
			echo -en "$n => $rec Msgs converted            \r"				
		fi

	elif [[ $((vsyslog)) == 2 ]] && [[ $line == *"com.avaya.asm"* ]]; then
		n=$((n+1))				
		echo -e "# msgno: $n" >> "$newfile"
		echo -en "$n => $rec Msgs converted            \r"				
#		if [[ $((insidesip)) == 1 ]]; then
#			echo -e "--------------------" >> "$newfile"
#		fi

		insidesip=1

		echo -e "com.avaya.asm  SIPMSGT " >> "$newfile"

#		if [[ $((vsyslog)) == 2 ]]; then
		echo -e "--------------------" >> "$newfile"					
		line=$(awk -F"-------------------- " '{print $2}' <<< "$line")
		awk -F"octets:" '{print $1}' <<< "$line" | awk '{print $1,$2,$3,""}' >> "$newfile"
		line=$(awk -F"octets: " '{print $2}' <<< "$line")
		siplength=$(cut -d"," -f1 <<< "$line")
		line=$(awk -F"Length: " '{print $2}' <<< "$line")
		blength=$(awk -F"ingress" '{print $1}' <<< "$line")
		echo "  octets: $siplength, Body Length: $blength" >> "$newfile"
		ingress=$(awk -F"ingress: " '{print $2}' <<< "$line" | awk -F"egress:" '{print $1}')
		line=$(awk -F"ingress: " '{print $2}' <<< "$line" | awk -F"egress:" '{print $2}')
		if [[ $line == *"SIPMsgContext:"* ]]; then					
			egress=$(awk -F"SIPMsgContext:" '{print $1}' <<< "$line")
			echo -e "\tingress: $ingress" >> "$newfile"
			echo -e "\tegress:$egress" >> "$newfile"
			if [[ $line == *"trace-seq"* ]]; then
				line2=$(awk -F"SIPMsgContext:" '{print $2}' <<< "$line" | awk -F"trace-seq" '{print $1}')
				echo -e "\tSIPMsgContext:$line2" >> "$newfile"
				line=$(awk -F"trace-seq:" '{print $2}' <<< "$line" | cut -d'-' -f1)
				echo -e "\ttrace-seq:$line" >> "$newfile"
			else
				line=$(awk -F"SIPMsgContext:" '{print $2}' <<< "$line" | cut -d'-' -f1)
				echo -e "\tSIPMsgContext:$line" >> "$newfile"								
			fi
		elif [[ $line == *"APMsgContext:"* ]]; then											
			egress=$(awk -F"APMsgContext:" '{print $1}' <<< "$line")
			echo -e "\tingress:$ingress" >> "$newfile"
			echo -e "\tegress:$egress" >> "$newfile"						
			if [[ $line == *"trace-seq"* ]]; then
				line2=$(awk -F"APMsgContext:" '{print $2}' <<< "$line" | awk -F"       trace-seq" '{print $1}')
				echo -e "\tAPMsgContext:$line2" >> "$newfile"
				line=$(awk -F"trace-seq:" '{print $2}' <<< "$line" | cut -d'-' -f1)
				echo -e "\ttrace-seq:$line" >> "$newfile"
			else
				line=$(awk -F"APMsgContext:" '{print $2}' <<< "$line" | awk -F"}---" '{print $1}')
				echo -e "\tAPMsgContext:$line" >> "$newfile"
			fi
		fi
		echo -e "--------------------" >> "$newfile"
#	fi
	elif [[ $((insidesip)) != 0 ]]; then
		if [[ $((vsyslog)) == 2 ]]; then
			if [[ ${#line} -gt 1 ]]; then			
				if [[ $line == "--------------------"* ]]; then
					insidesip=0
					echo '' >> "$newfile"
					echo "--------------------" >> "$newfile"							
				else
					echo "$line" >> "$newfile"
				fi
			fi
		elif [[ $((vsyslog)) == 4 ]]; then
			if [[ $line == "--------------------"* ]]; then
				insidesip=$((insidesip+1))
				line="--------------------"
				if [[ $((insidesip)) == 4 ]]; then
					if [[ $prevline != "" ]]; then
						echo "$prevline" >> "$newfile"
						echo "$line" >> "$newfile"
						prevline=""
					fi
				else
					echo "$line" >> "$newfile"							
				fi
			elif [[ $((insidesip)) -lt 3 ]]; then
				echo "$line" | tr -d "\r" >> "$newfile"
			elif [[ $((insidesip)) == 4 ]]; then
				if [[ $prevline != "" ]]; then
					echo "$prevline" >> "$newfile"
					echo "$line" >> "$newfile"								
				fi
			else
				if [[ $prevline != "" ]]; then
					echo "$prevline" >> "$newfile"
				fi
				prevline=$line
#				prevline=$(echo "$line" | tr -d "\r\n")
			fi
		fi
	fi
done < "$file"

if [[ $((vsyslog)) == 4 ]] && [[ $prevline != "" ]]; then
	echo "$prevline" >> "$newfile"
	echo '' >> "$newfile"
fi
mv "$newfile" "$var.asm2"

} # convert_asm()

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":ae:i:hbf:sN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
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
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 4 ]]; then
			voutput=1
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
		elif [[ $var == "-i"* ]]; then
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
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 4 ]]; then
				voutput=1
			fi
		elif [[ $((skipper)) == 2 ]]; then
			endptaddr=$var
		elif [[ $((skipper)) == 3 ]]; then
			smaddr=$var
		elif [[ $((skipper)) == 4 ]]; then
			findANI=$findANI		# findANI=$var
		fi
		skipper=0			
		continue
	fi

	file=$var
	bvar=$(basename "$var")
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0

	if [[ $((voutput)) == 4 ]]; then
		conv2asm=1
	fi
	
	if [ -s $file ]; then
		echo -en "\nExploring content in $bvar... stand by\r"
		##rec=$(grep -E "::SIP|\] PPM\:" $file| wc -l)
		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)

		rec=$(egrep -m 1 -c -e "^com.avaya.asm  SIPMSGT.*" "$file" 2>/dev/null)
		if [[ $rec != 0 ]]; then
			echo -e "\nNo conversion required. $var appears to be a native traceSM capture."
			echo -e "Use "traceSM" tool to open it.\n"
			continue
		fi
		rec=$(egrep -c -e "CallLogs INFO - :.*" "$file" 2>/dev/null)

		if [[ $rec == 0 ]];	then
			rec=$(egrep -c -e ".*AasSipMgr\[.*" "$file" 2>/dev/null)
			if [[ $rec == 0 ]]; then
				echo -e "\nerror: No SIP messages have been found in $bvar in the expected format."
				echo "This file may not be an ASMr6.2 SIP log file... or, not an exported SipTrace."
				error=1
			else
				xline=$(egrep -m 1 -e ".*AasSipMgr\[.*" $file 2>/dev/null)
				if [[ $xline == "DEBUG	LOCAL2"* ]]; then 			# syslog interactive
					vsyslog=4
					rec=$(egrep -c -e "^CSeq.*" $file 2>/dev/null)					
				elif [[ $xline == *"Local2.Debug"* ]]; then 		# syslog KIWI
					vsyslog=5
#				elif [[ $xline =~ ^[ADFMJSON][a-z][a-z].* ]] && [[ $xline =~ .*\]:\ $ ]]; then
				elif [[ $xline =~ ^[JFMASOND][[:lower:]][[:lower:]].* ]] && [[ $xline =~ .*\]:\ .* ]]; then				
					vsyslog=2										# SM TraceViewerExportDetails
				fi
			fi
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
				if [[ $footprint == 1 ]]; then
					echo "Actually, $bvar appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			elif [[ $((vsyslog)) == 0 ]]; then
				echo "error: unknown content in $bvar. Verify source of this file."			
			fi
		else 
			vsyslog=1												# ASM 6.2 CallLogs INFO - :
		fi

		if [[ $conv2asm == 1 ]]; then
			n=0
			blength=0
			ingress=""
			egress=""
			prevline=""
			reset_sipmsg

			newfile=$file.asm2.tmp
			if [ -f $newfile ]; then
				rm $newfile
			fi

			echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
			echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
			echo "# Command line: $args" >> "$newfile"
			echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
			echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
			echo -e "# Input/output file: $var -> $var.asm2" >> "$newfile"
			echo -e "# Converting from format=$vsyslog into native ASM\n" >> "$newfile"

			# echo -e -n "Searching for beginning of first SIP message in $file... stand by\r"
#            conv=$(awk -e '/^\-\-\-\-\-\-\-\-\-\-\-\-\-.*\-\-\-\-\-\-\-$/{flag=1} flag; /}/{flag=0}' "$file")
# ----------------------------------------------------------------------------------------			
#            conv=$(awk -e '/CallLogs INFO/{flag=1} flag; /}/{flag=0}' $file)
#            conv=$(awk -W source='/CallLogs INFO/{flag=1} flag; /}/{flag=0}' $file)

			convert_asm

		elif [[ $rec != 0 ]] && [[ $((vsyslog)) != 0 ]]; then
			logsec=$SECONDS
			base64msg=0
			foundipaddr=""
			useragent=""
			nlines=0
			sipyear=""
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
			sipin=0
			sipout=0

			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo -e "You may want to execute this script on a more powerful PC or server.\n"
			fi

			newfile="$file.asm.tmp"
			if [ -f $newfile ]; then
				rm $newfile
			fi

			echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
			echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
			echo "# Command line: $args" >> "$newfile"
			echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
			echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
			echo -e "# Input/output file: $var -> $var.asm" >> "$newfile"
			echo -e "# Converting from format=$vsyslog into native ASM\n" >> "$newfile"

			# echo -e -n "Searching for beginning of first SIP message in $file... stand by\r"
#            conv=$(awk -e '/^\-\-\-\-\-\-\-\-\-\-\-\-\-.*\-\-\-\-\-\-\-$/{flag=1} flag; /}/{flag=0}' "$file")
# ----------------------------------------------------------------------------------------			
#            conv=$(awk -e '/CallLogs INFO/{flag=1} flag; /}/{flag=0}' $file)

			while IFS= read -r line
			do
				linelength=${#line}
				nlines=$((nlines+1))

				if [[ $((vsyslog)) == 5 ]]; then									# syslog KIWI  SyslogCatchAll
					if [[ $line != *"Local2.Debug"* ]]; then
						continue
					elif [[ $smaddr != "" ]] && [[ $line != *$smaddr* ]]; then
						continue
					elif [[ $line == *"AasSipMgr["* ]]; then
						if [[ $line == *"SIPMSGT+"* ]]; then
							line=$(awk -F"+ " '{print $2}' <<< "$line")
#							line=$(echo "$line" | cut -d'+' -f3)					# TODO: strip off leading space
				   		elif [[ $((sipstart)) != 0 ]]; then
                      		complete_sipmsg
							insidesip=1
						elif [[ $line == *"SIPMSGT"* ]]; then
							insidesip=1							
				   		fi

						if [[ $((insidesip)) == 1 ]] && [[ $line == *"--------------------"* ]]; then
							insidesip=3
							sip_direction
			 		   		get_sip_datetime
						fi

						if [[ $((insidesip)) == 3 ]] && [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then

							if [[ $line == *"octets: "* ]]; then
								siplength=$(awk -F"octets: " '{print $2}' <<< "$line" | cut -d',' -f1)
							elif [[ $line == *"ingress: {"* ]]; then
								xline=$(awk -F"ingress: { " '{print $2}' <<< "$line" | cut -d'}' -f1)
								protocol=$(cut -d'/' -f3 <<< "$xline")
								localip=$(cut -d'/' -f1 <<< "$xline" | cut -d'L' -f2)
								ip=$(cut -d'/' -f2 <<< "$xline" | cut -d'R' -f2)
							elif [[ $line == *"egress: {"* ]]; then
								xline=$(awk -F"egress: { " '{print $2}' <<< "$line" | cut -d'}' -f1)
								protocol=$(cut -d'/' -f3 <<< "$xline")
								elocalip=$(cut -d'/' -f1 <<< "$xline" | cut -d'L' -f2)
								eip=$(cut -d'/' -f2 <<< "$xline" | cut -d'R' -f2)
							elif [[ $line == *" Listener: {"* ]]; then
								listenerip=$(awk -F" Listener: { " '{print $2}' <<< "$line" | cut -d' ' -f1)
							elif [[ $line == "--------------------"* ]]; then
								insidesip=4
							fi
						
#					elif [[ $((insidesip)) == 4 ]] && [[ $((sipstart)) == 0 ]]; then
							if [[ $ip == "127.0.0.2"* ]]; then
								if [[ $eip == "" ]]; then
									reset_sipmsg
									continue
								else
									ip=$eip
								fi
							fi
							if [[ $ip == "127.0.0.2"* ]] || [[ $listenerip == "127.0.0.2"* ]] || [[ $protocol == "NO_TRANSPORT" ]]; then
								reset_sipmsg
								continue
							elif [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
								if [[ $localip != "" ]] && [[ $endptaddr != "" ]] && [[ $localip != *$endptaddr* ]]; then
									reset_sipmsg
									continue
								fi
							fi

			 	   			siptotalmsg=$((siptotalmsg+1))	
				   			base64found=0
							xline=$(sed 's/<013><010>/\n/g' <<< "$line" | sed 's/<010>/\n/g' | sed 's/<013>//g')
#							xline=$(echo "$line" | awk -F"<010>" '{print $10}' | awk -F"<013>" '{print $1}')
							sipmsg_header
							start_sipmsg
						fi
						continue
					fi

				elif [[ $((vsyslog)) == 4 ]]; then							# syslog interactive
 
					if [[ $line == *"AasSipMgr["* ]]; then
						if [[ $smaddr != "" ]] && [[ $line != *$smaddr* ]]; then
							reset_sipmsg
						elif [[ $line == *"SIPMSGT+"* ]]; then
							line=$(awk -F"+ " '{print $2}' <<< "$line")
#							line=$(echo "$line" | cut -d'+' -f3)			# TODO: cut leading space
				   		elif [[ $((sipstart)) != 0 ]]; then
                      		complete_sipmsg
							insidesip=1
							continue
						elif [[ $line == *"SIPMSGT"* ]]; then
							insidesip=1
							continue
				   		fi
					elif [[ $((insidesip)) == 1 ]] && [[ $line == "--------------------"* ]]; then
						insidesip=2
						continue
					elif [[ $((insidesip)) == 2 ]]; then
						insidesip=3
						sip_direction
			 	   		get_sip_datetime
						continue
					elif [[ $((insidesip)) == 3 ]] && [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
						if [[ $line == *"octets: "* ]]; then
							siplength=$(cut -d' ' -f2 <<< "$line" | cut -d',' -f1)
						elif [[ $line == *"ingress: {"* ]]; then
							xline=$(cut -d' ' -f3 <<< "$line")
							protocol=$(cut -d'/' -f3 <<< "$xline")
							localip=$(cut -d'/' -f1 <<< "$xline" | cut -d'L' -f2)
							ip=$(cut -d'/' -f2 <<< "$xline" | cut -d'R' -f2)
						elif [[ $line == *"egress: {"* ]]; then
							xline=$(cut -d' ' -f3 <<< "$line")
							protocol=$(cut -d'/' -f3 <<< "$xline")
							elocalip=$(cut -d'/' -f1 <<< "$xline" | cut -d'L' -f2)
							eip=$(cut -d'/' -f2 <<< "$xline" | cut -d'R' -f2)
						elif [[ $line == *" Listener: {"* ]]; then
							listenerip=$(cut -d' ' -f5 <<< "$line")
						elif [[ $line == "--------------------"* ]]; then
							insidesip=4
						fi
						continue													
					elif [[ $((insidesip)) == 4 ]] && [[ $((sipstart)) == 0 ]]; then
						if [[ $ip == "127.0.0.2"* ]]; then
							if [[ $eip == "" ]]; then
								reset_sipmsg
								continue
							else
								ip=$eip
							fi
						fi
						if [[ $ip == "127.0.0.2"* ]] || [[ $listenerip == "127.0.0.2"* ]] || [[ $protocol == "NO_TRANSPORT" ]]; then
							reset_sipmsg
							continue
						elif [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
							if [[ $localip != "" ]] && [[ $endptaddr != "" ]] && [[ $localip != *$endptaddr* ]]; then
									reset_sipmsg
									continue
							fi
						fi

		 	   			siptotalmsg=$((siptotalmsg+1))	
			   			base64found=0
						sipmsg_header
						start_sipmsg
					fi

				elif [[ $((vsyslog)) == 3 ]]; then				# pcap syslog
					continue

				elif [[ $((vsyslog)) == 2 ]]; then				# SM TraceViewerExportDetails
					if [[ $line == *" AasSipMgr["* ]]; then
				   		if [[ $((sipstart)) != 0 ]]; then
                      		complete_sipmsg
				   		fi
						insidesip=1
					elif [[ $((insidesip)) == 1 ]]; then		# skip first empty line
						insidesip=2
					elif [[ $((insidesip)) == 2 ]] && [[ $line == *"SIPMSGT"* ]]; then
				   			sip_direction
#						if [[ $ip == "127.0.0.2"* ]] && [[ $line == *"egress: [NO TARGET]"* ]]; then
						if [[ $ip == "127.0.0.2"* ]] && [[ $eip == "" ]]; then						
#						if [[ $ip == "127.0.0.2"* ]]; then												
							reset_sipmsg
							continue
						else
							insidesip=3
			 	   			siptotalmsg=$((siptotalmsg+1))	
				   			base64found=0
				 	   		get_sip_datetime
						fi						
					elif [[ $((insidesip)) == 3 ]] && [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
						insidesip=4
					elif [[ $((insidesip)) == 4 ]] && [[ $((sipstart)) == 0 ]]; then
						if [[ $ip == "127.0.0.2"* ]] && [[ $eip != "" ]] && [[ $elocalip != "" ]]; then
#							if [[ $((dirdefined)) == 1 ]]; then
								ip=$eip
#							elif [[ $((dirdefined)) == 2 ]]; then
#								localip=$elocalip
#							fi
						fi
#						if [[ $localip == *"127.0.0.2"* ]] && [[ $eip != "" ]] && [[ $elocalip != "" ]]; then
#							if [[ $((dirdefined)) == 1 ]]; then
#								ip=$eip
#							elif [[ $((dirdefined)) == 2 ]]; then
#								localip=$elocalip
#							fi
#						fi
						if [[ $ip == "127.0.0.2"* ]] || [[ $listenerip == "127.0.0.2"* ]] || [[ $protocol == "NO_TRANSPORT" ]]; then
							reset_sipmsg
							continue
						elif [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
							if [[ $localip != "" ]] && [[ $endptaddr != "" ]] && [[ $localip != *$endptaddr* ]]; then
									reset_sipmsg
									continue
							fi
						fi
					
						sipmsg_header
						start_sipmsg
						continue
					fi
				elif [[ $((vsyslog)) == 1 ]]; then				# CallLogsINOF ASM r6.2
			    	if [[ $line == *" CallLogs "* ]]; then
				   		if [[ $((sipstart)) != 0 ]]; then
                      		complete_sipmsg
				   		fi
			 	   		insidesip=1
			 	   		siptotalmsg=$((siptotalmsg+1))	
				   		base64found=0
				   		sip_direction
			 	   		get_sip_datetime
                	elif [[ $((insidesip)) == 1 ]] && [[ $ip == "" ]] && [[ $line == "Transport:"* ]]; then				
	                	ip1=$(cut -d' ' -f4 <<< "$line" | cut -d'=' -f2 | cut -d',' -f1)
						ip2=$(cut -d' ' -f5 <<< "$line" | cut -d'=' -f2 | cut -d',' -f1)
	                	protocol=$(cut -d' ' -f2 <<< "$line")
                    	ip=$ip1:$ip2
						if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
							reset_sipmsg
							continue
						fi
					elif [[ $((insidesip)) == 1 ]] && [[ $ip != "" ]]; then
                    	insidesip=2
					elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
			   			sipmsg_header
               			start_sipmsg
						continue
					fi
				fi		   

				if [[ $((vsyslog)) != 5 ]] && [[ $((sipstart)) == 1 ]]; then
					if [[ $line == "--------------------"* ]]; then				
				       complete_sipmsg
					else
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
							echo "$line" >> "$newfile"
							siplines=$((siplines+1))
							get_useragent
						fi
					fi
				fi
#	    	done <<< "$conv"
    		done < "$file"

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
						echo "    has been converted for addr=$endptaddr into $var.asm file"
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
			
			    echo -e "\tTotal # of lines digested:\t\t\t\t $nlines"

			    if [[ $((sipmsg)) != 0 ]]; then
				    echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
				    echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				    echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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

			echo '' >> "$newfile"
	        if [[ $sipwordlist != "" ]]; then
		      echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
	        fi

			tmpsec=$((SECONDS-logsec))
			if [[ $((tmpsec)) != 0 ]]; then
				avgmsg=$(printf %.2f "$(($((n)) * 100 / $tmpsec))e-2")
				echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: $avgmsg\t Time spent: $SECONDS sec\n"
			else
				echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t Time spent: $SECONDS sec\n"
			fi
			currtime=$(date +%R:%S)	

			mv "$newfile" "$var.asm"
#			rm $file					# this is already a tmp file, can be removed
			pwd;ls -l "$var.asm"
			echo ''
		fi
	elif [ -f "$var" ]; then
		echo -e "\nerror: $bvar is an empty file."
		ls -l "$var"
		error=3; continue
	elif [ -d "$var" ]; then
		echo -e "\nerror: $bvar is a folder.  Folder is not a supported input."
		error=3; continue
	else
		echo -e "\nerror: $bvar was not found. Verify path and filename."
		error=3; continue		
	fi
done