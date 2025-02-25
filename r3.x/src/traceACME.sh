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
pattern2="^\-\-\-.*\-\-\-$"
sipstat=1
converted=0
adjusthour=0
noINFO=0
bCAT=0
findANI=""
base64decode=1
bDelTemp=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

# TODO: handle .zip multiple .log files

function usage ()  {
    echo "traceACME.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceACME.sh [OPTIONS] [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the log.sipd or sipmsg.log file from the ACME server"
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-C \t\tconcatenate output files (if converted multiple files)"	
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"	
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
	ip="";	ip1=""
	localip=""; localip1=""
	foundipadd=""
	siptime=""; sipdate=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then
	sipstart=1

	if [[ $((vsyslog)) == 10 ]]; then
		slines=$(wc -l <<< "$line")
		siplines=$((siplines+$slines))
		get_useragent
		xline=$(head -1 <<< "$line")
	else
		xline=$line	
		siplines=$((siplines+1))
	fi
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
		2)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
    fi
fi
} # sipmsg_header() 

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $line =~ RECEIVER|Recv:|received ]]; then
		sipstream=5f70;				 dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED";  dirstring2="from";;
		3)	 dirstring1="-->";   	 dirstring2="ingress";;
		esac

	elif [[ $line =~ SENDER|Send:|sent ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
#	else
#		reset_sipmsg
	fi
	if [[ $((dirdefined)) != 0 ]] && [[ $((vsyslog)) == 11 ]]; then
		ip=$(awk '{print $NF}' <<< "$line" | tr -d "\r")
		localip=$(awk '{print $5}' <<< "$line")
#		if [[ $((dirdefined)) == 2 ]]; then
#			ip2=$localip
#			localip=$ip
#			ip=$ip2
#		fi
	fi
fi	
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $((vsyslog)) == 10 ]] && [[ $xline != "" ]]; then
			useragent=$(egrep "^User-Agent:" <<< "$xline")
			if [[ $useragent != "" ]]; then
				useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$useragent")
			fi
		elif [[ $line =~ User\-Agent: ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

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
		echo -e "line=$line\n"; exit 1
	fi
} # get_sipmonth()

function get_sip_datetime () {
# Sep  9 11:21:46.171 [SIP] 	<startTime>2013-09-09 11:21:46.171</startTime>
# Sep  6 16:42:25.610 On 10.10.10.10:5061 sent to 10.10.12.115:16385

	case $vsyslog in
	10)
		sipyear=$(cut -d'>' -f2 <<< "$line" | cut -d '<' -f1)
		sipmsec=$(cut -d' ' -f2 <<< "$sipyear")
		sipmonth=$(cut -d' ' -f1 <<< "$sipyear")
		sipyear=$(cut -d'-' -f1 <<< "$sipmonth")
		sipday=$(cut -d'-' -f3 <<< "$sipmonth")
		sipmonth=$(cut -d'-' -f2 <<< "$sipmonth");;

	11)
		month=$(cut -d' ' -f1 <<< "$line")
		sipday=$(awk '{printf "%02i",$2}' <<< "$line")
		sipmsec=$(awk '{print $3}' <<< "$line")
		get_sipmonth;;		
	esac

	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")
	sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
	sipsec=$(cut -d'.' -f1 <<< "$sipsec")

	case $voutput in
	1)	sipdate="$sipmonth/$sipday/$sipyear"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	2)	sipdate="$sipyear/$sipmonth/$sipday"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	3)	sipdate="$sipday/$sipmonth/$sipyear"
		siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
	esac
} # get_sip_datetime()

function convert_logsipd () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

#   if [[ $line == *"[SIP] SMT ClientTrans"* ]] && [[ $line =~ Send:|Recv: ]]; then
	if [[ $line == *"[SIP] 	<eventEntry>" ]]; then
	    if [[ $((sipstart)) != 0 ]]; then
	    	complete_sipmsg
	    fi

		insidesip=1					
#		sip_direction
		siptotalmsg=$((siptotalmsg+1))							

	elif [[ $((insidesip)) == 1 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ startTime ]]; then
		insidesip=2
		get_sip_datetime

	elif [[ $((insidesip)) == 2 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ eventType ]]; then
		if [[ $line =~ sipEvent ]]; then
			insidesip=2						# dummy statement
		else
			echo -e "\n\nFound non-SIPEVENT at line#$nlines\n\n"
			reset_sipmsg
			continue
		fi
	elif [[ $((insidesip)) == 2 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ sourceAddress ]]; then
		insidesip=3
		localip1=$(cut -d'>' -f2 <<< "$line" | cut -d'<' -f1)

	elif [[ $((insidesip)) == 3 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ sourcePort ]]; then
		insidesip=4
		localip2=$(cut -d'>' -f2 <<< "$line" | cut -d'<' -f1)

	elif [[ $((insidesip)) == 4 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ destinationAddress ]]; then
		insidesip=5
		ip1=$(cut -d'>' -f2 <<< "$line" | cut -d'<' -f1)

	elif [[ $((insidesip)) == 5 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ destinationPort ]]; then
		insidesip=6
		ip2=$(cut -d'>' -f2 <<< "$line" | cut -d'<' -f1)

	elif [[ $((insidesip)) == 6 ]] && [[ $line =~ \[SIP\] ]] && [[ $line =~ direction ]]; then
		insidesip=7
		sip_direction

	elif [[ $((insidesip)) == 7 ]] && [[ $((sipstart)) == 0 ]] && [[ $line =~ \<SipMsgSection ]]; then
		if [[ $ip1 != "" ]]; then
			ip="$ip1:$ip2"
		fi
		if [[ $localip1 != "" ]]; then
			localip="$localip1:$localip2"
		fi

		if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
			reset_sipmsg
			continue
		else
			line=$(awk -F"<SipMsgSection>" '{print $2}' <<< "$line")
			if [[ $line =~ \/SipMsgSection ]]; then
				sipsplit=0
				line=$(awk -F"</SipMsgSection>" '{print $1}' <<< "$line")							
			else
				sipsplit=1
			fi
			line=$(sed 's/&quot;/\"/g' <<< "$line" | sed 's/&lt;/\</g' | sed 's/&gt;/\>/g' | sed 's/&#xD;&#xA;/\r\n/g' | sed 's/&#xA;/\r\n/g')  # | sed 's/&#xD;/\r/g')
			ignore=0
			if [[ $((noINFO)) == 1 ]]; then
				ignore=$(egrep -c "^INFO|^CSeq:.*INFO" <<< "$line")
			fi
			if [[ $((ignore)) == 0 ]]; then
				sipmsg_header
				start_sipmsg
				if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
					if [[ $calltime == "" ]] && [[ $line =~ From:|To: ]] && [[ $line =~ $findANI ]]; then
						calltime=$siptime
					elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ Call-ID: ]]; then
						callID=$(awk -F"Call-ID: " '{print $2}' <<< "$line" | cut -d' ' -f1)
						callID="Call-ID: $callID"; callDIR=$dirdefined
					fi
				fi

				if [[ $((sipsplit)) == 0 ]]; then
					complete_sipmsg
				fi
			else
				nINFO=$((nINFO+1))
				reset_sipmsg
				continue
			fi
		fi
	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ \[SIP\] ]] && [[ $line != *"<SipMsgSection>"* ]]; then
		if [[ $line =~ \/SipMsgSection ]]; then
			insidesip=8
			line=$(awk -F "[SIP] " '{print $2}' <<< "$line" | awk -F"</SipMsgSection>" '{print $1}')
		fi
		if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then		
		    base64found=1
		    echo "# Base64 dump found" >> "$newfile"
		    if [[ -f "$newfile.b64" ]]; then
			    rm "$newfile.b64"
		    fi
	    elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
			xline=$(awk -F"[SIP] " '{print $2}' <<< "$line" | sed 's/&quot;/\"/g' | sed 's/&lt;/\</g' | sed 's/&gt;/\>/g' | sed 's/&#xD;&#xA;/\r\n/g' | sed 's/&#xA;/\n/g')
			echo $xline >> "$newfile.b64"
	    else
			ignore=0
			xline=$(awk -F"[SIP] " '{print $2} <<< "$line"' | sed 's/&quot;/\"/g' | sed 's/&lt;/\</g' | sed 's/&gt;/\>/g' | sed 's/&#xD;&#xA;/\r\n/g' | sed 's/&#xA;/\n/g')
			if [[ $((noINFO)) == 1 ]]; then
				ignore=$(egrep -c "^CSeq:.*INFO" <<< "$line")
			fi
			if [[ $((ignore)) == 0 ]]; then
				if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
					if [[ $calltime == "" ]] && [[ $xline =~ ^From:|^To: ]] && [[ $xline =~ $findANI ]]; then
						calltime=$siptime
					elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $xline =~ ^Call-ID: ]]; then
						callID=$line; callDIR=$dirdefined
					fi
				fi

				echo $xline >> "$newfile"
				slines=$(wc -l <<< "$xline")
		    	siplines=$((siplines+$slines))
			    get_useragent
			else
				nINFO=$((nINFO+1))
				reset_sipmsg
				continue
			fi
		fi
		if [[ $((insidesip)) == 8 ]]; then 
			complete_sipmsg
		fi
	fi
#		done <<< "$conv"
done < "$file"		
} # convert_logsipd()

function convert_sipmsglog () {
while IFS= read -r line
do
	linelength=${#line}
	nlines=$((nlines+1))

    if [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]] ]] && [[ $line =~ sent|received ]]; then
	    if [[ $((sipstart)) != 0 ]]; then
	    	complete_sipmsg
	    fi

		insidesip=1					
		sip_direction
		siptotalmsg=$((siptotalmsg+1))
		get_sip_datetime
		sip_direction
		if [[ $ip == "127*" ]] && [[ $localip == "127"* ]]; then
			reset_sipmsg
			continue
		fi
	elif [[ $((insidesip)) == 0 ]]; then
		continue
	elif [[ $((sipstart)) == 0 ]]; then		
#	elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
		if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && $ip != *$endptaddr* ]]; then
			reset_sipmsg
			continue
		elif [[ $((noINFO)) != 0 ]] && [[ $line =~ ^INFO ]]; then					# 
			nINFO=$((nINFO+1))
			reset_sipmsg
			continue
		else
			sipmsg_header
			start_sipmsg
		fi
	elif [[ $((sipstart)) != 0 ]]; then
		if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
			if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
				calltime=$siptime
			elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
				callID=$line; callDIR=$dirdefined
			fi
		fi
		if [[ $line == "----------------------------------------" ]]; then
			complete_sipmsg
		else
	    	if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
		    	base64found=1
			    echo "# Base64 dump found" >> "$newfile"
			    if [[ -f "$newfile.b64" ]]; then
				    rm "$newfile.b64" 2>/dev/null
		    	fi
			elif [[ $((base64found)) != 0 ]]; then
			    echo "$line" >> "$newfile.b64"
	    	else					
		    	echo "$line" >> "$newfile"
			    siplines=$((siplines+1))
			    get_useragent
			fi
		fi
	fi
done < "$file"
} # convert_sipmsglog()


################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbdf:sCIN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
	C)
		bCAT=1;;
	I)	
		noINFO=1;;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	e)
		endptaddr=${OPTARG};;
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
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

skipper=0; var=""

if [[ $((base64decode)) != 0 ]]; then
	base64 --help >/dev/null 2>&1
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
		elif [[ $var == "-N"* ]]; then
			skipper=3
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
			endptaddr="$var"
		elif [[ $((skipper)) == 3 ]]; then
			findANI=$findANI		# findANI=$var
		fi
		skipper=0; var=""	
		continue
	fi
	
	file="$var"
	bvar=$(basename "$var")
	currtime=$(date +%R:%S)
	error=0;		vsyslog=0
	
	if [ -s "$file" ]; then
		echo -en "\nExploring content in $bvar... stand by\r"
		rec=$(egrep -c "\[SIP\] 	<eventEntry>" "$file" 2>/dev/null)
		rec2=$(egrep -c -e "CSeq:*" "$file" 2>/dev/null)

		if [[ $rec == 0 ]] || [[ $rec2 == 0 ]];	then
			rec=$(egrep -c "^[JFMASOND][a-z][a-z].*received from|^[JFMASOND][a-z][a-z].*sent to" "$file" 2>/dev/null)
			if [[ $rec == 0 ]]; then
				echo "error: no SIP messages have been found in $bvar in the expected format."
				echo "This file may not be an ACME log file... or, DEBUG/verbose logging was not enabled."
				error=1
#				rec=$(egrep -c -e "^CSeq:.*" "$file")
				if [[ $rec2 == 0 ]]; then
					echo "In fact, no sign of any "CSeq:" lines within $bvar"
					error=2
				else
					echo "Though, found $rec2 lines with \"CSeq:\" - so there might be some SIP messages within $bvar."
					rec=0; 	error=2
				fi
				asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
				if [[ $((asmfile)) != 0 ]]; then
					asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
					if [[ $((asmfile)) != 0 ]]; then
						echo "It appears $bvar is a traceSM file (or a converted file using 3rd output format)."
						echo "This kind of input is not (yet) supported by this tool."
					fi
				fi
				echo -e "Verify source and content of $bvar.\n"	
				continue
			else
				vsyslog=11
			fi
		else
			vsyslog=10
		fi

		if [[ $((vsyslog)) != 0 ]]; then
			logsec=$SECONDS
			base64msg=0
			foundipaddr=""
			useragent=""
			nlines=0
			sipyear=$(cut -d'/' -f3 <<< "$today")
			sipmonth=$(cut -d'/' -f1 <<< "$today")
			sipday=$(cut -d'/' -f2 <<< "$today")
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
			nINFO=0

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
			echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"

#			conv=$(awk -e '/CHAP_SIP_Message/{flag=1} flag; /}/{flag=0}' "$file")
#			conv=$(awk -W source='/CHAP_SIP_Message/{flag=1} flag; /}/{flag=0}' "$file")

			if [[ $((vsyslog)) == 10 ]]; then
				convert_logsipd
			elif [[ $((vsyslog)) == 11 ]]; then
				convert_sipmsglog
			fi

			if [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
			fi
			echo '' >> "$newfile"

			if [[ $output == "" ]]; then
				output=$var
			fi
		
			if [[ $((error)) != 0 ]]; then
				echo -e "\n\tError found: $error\n\n"

			elif [[ $((sipmsg)) -lt 1 ]]; then
				echo -e "\nError: No SIP messages have been found in $basefile. Contact developer."

        	elif [[ $((sipstat)) != 0 ]]; then

				if [[ ${#endptaddr} == 0 ]]; then
					echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm file"
				else
					if [[ $((sipmsg)) == 0 ]]; then 
						echo "==> no SIP messages were found for addr=$endptaddr in $bvar file"
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
					if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
						echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
					fi

					if [[ ${#firstmsg} -lt 11 ]] && [[ ${#lastmsg} -lt 11 ]]; then					
						printf "\tFirst msg: %-10s %s\t Last msg: %-10s %s\n" "$firstmsg" "$timefirst" "$lastmsg" "$timelast"
					else
						printf "\tFirst msg: %-30s\t %s\n" "${firstmsg:0:30}" "$timefirst"
						printf "\tLast msg: %-31s\t %s\n"  "${lastmsg:0:31}" "$timelast"
					fi

					if [[ $findANI != "" ]] && [[ $callID != "" ]] && [[ $calltime != "" ]]; then
						if [[ $callDIR == 1 ]]; then
						echo -e "\tIncoming call from $findANI at $calltime\t $callID"
					elif [[ $callDIR == 2 ]]; then
						echo -e "\tOutgoing call to $findANI at $calltime\t $callID"
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
			else
				echo "Conversion of $file has ended with error code: $error n=$n sipwords=$sipwordlist"
			fi	

			tmpsec=$((SECONDS-logsec))
			if [[ $((tmpsec)) != 0 ]]; then
				avgmsg=$(printf %.3f "$(($((n)) * 1000 / $tmpsec))e-3")
				echo -e "\n\tTask started:  $currtime  completed:  $(date +%R:%S)\t Total spent: $SECONDS sec  Avg. SIP msg/sec: $avgmsg\n"
			else
				echo -e "\n\tTask started:  $currtime  completed:  $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t  Time spent: $SECONDS sec\n"
			fi
			currtime=$(date +%R:%S)	

			if [ -f "$var.asm" ]; then
				mv "$var.asm" "$var.asm.bak"
			fi
			mv "$newfile" "$var.asm"
			if [[ $bDelTemp != 0 ]] && [[ $file != $var ]] && [ -f "$file" ]; then
				rm "$file" 2>/dev/null					# this is already a tmp file, can be removed
			fi
			pwd;ls -l "$var.asm"
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
if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
fi
exit 0