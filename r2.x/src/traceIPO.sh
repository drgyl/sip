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
pattern1=".*mS SIP [TR]x:.*"
pattern2=".*[0-9]{10}mS .*"
pattern3="^[a-z]: .*"
pattern4="^[0-9]{4}\-[0-9]{2}\-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.*"
pattern5="^\*\*\*.*"
findANI=""
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
endptaddr="" # 135.105.129.244"
voutput=3  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

function usage () {
    echo "traceIPO.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceIPO.sh [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the IPO Monitor log file collected from an IP Office server"
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"				
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
	sipyear=""
	dirdefined=0
	base64found=0
	localip=""
	ip=""	
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
		n=$((n+1)); sipstart=0
		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$file => $n/$rec Msgs converted            \r"
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
#1: 2022-04-26T10:19:58 2413009585mS SIP Rx: TCP 192.168.0.26:50755 -> 192.168.0.111:5060
#2: 3309492437mS SIP Rx: TCP 213.148.136.222:5060 -> 10.255.1.21:23588
#3: 12:15:06 1210484664mS SIP Rx: UDP 192.168.3.107:5060 -> 10.11.3.2:5060
	if [[ $line == *"SIP Rx:"* ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)		dirstring1="-->"; 	dirstring2="ingress";;
		esac

	elif [[ $line == *"SIP Tx:"* ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	else
		insidesip=0
		dirdefined=0
	fi

    if [[ $((dirdefined)) != 0 ]]; then
#		localip=$(echo "$line"  | cut -d' ' -f8 | sed 's/^M//g')   # because of trailing ^M / stripoff
        localip=$(awk '{print $NF}' <<< "$line")               # | sed 's/.*[[:blank:]]$//')
		localip1=$(cut -d':' -f1 <<< "$localip")
		localip2=$(awk -F':' '{printf "%i",$2}' <<< "$localip")
		localip=$localip1:$localip2

        if [[ $((ipotime)) == 1 ]]; then				# TODO strip off ^M
			protocol=$(cut -d' ' -f5 <<< "$line")
			ip=$(cut -d' ' -f6 <<< "$line")
		elif [[ $((ipotime)) == 2 ]]; then
			protocol=$(cut -d' ' -f4 <<< "$line")
			ip=$(cut -d' ' -f5 <<< "$line")
#		localip=$(echo "$line"  | cut -d' ' -f7 | sed 's/^M//g')   # because of trailing ^M / stripoff
		elif [[ $((ipotime)) == 3 ]]; then
			protocol=$(cut -d' ' -f6 <<< "$line")
			ip=$(cut -d' ' -f7 <<< "$line")
		fi
	fi

	if [[ $((dirdefined)) == 2 ]]; then
       iptmp=$localip; localip=$ip; ip=$iptmp
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
#1: 2022-04-26T10:19:58 2413009585mS SIP Rx: TCP 192.168.0.26:50755 -> 192.168.0.111:5060
# pattern4="^[0-9]{4}\-[0-9]{2}\-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}.*"
#2: 3309492437mS SIP Rx: TCP 213.148.136.222:5060 -> 10.255.1.21:23588
#3:  12:15:06 1210484664mS SIP Rx: UDP 192.168.3.107:5060 -> 10.11.3.2:5060
#	if [[ $((ipotime)) == 0 ]]; then
	    sipyear=$(cut -d' ' -f1 <<< "$line")
		if [[ $sipyear =~ .*mS$ ]]; then
			ipotime=2
		elif [[ $sipyear =~ $pattern4 ]]; then
			ipotime=1
		else
			ipotime=3
		fi
#	fi

	if [[ $((ipotime)) == 3 ]]; then
#	  sipmsec="000"
	  sipyear=$(cut -d' ' -f3 <<< "$line" | cut -d'm' -f1)
	  sipday=$(date -d @$sipyear +'%Y-%m-%d %H:%M:%S')
	  if [[ $? != 0 ]]; then
		echo -e "\nerror: IPO date/time could not be extracted - ipotime=$ipotime sipyear=$sipyear"
		echo "line=$line"; echo "Contact $0 developer.  Aborting..."; exit 1
	  fi
	  sipmsec=${sipyear:7}

	  sipyear=$(cut -d' ' -f1 <<< "$sipday"  | cut -d'-' -f1)
	  sipmonth=$(cut -d' ' -f1 <<< "$sipday" | cut -d'-' -f2)
	  sipday=$(cut -d' ' -f1 <<< "$sipday"   | cut -d'-' -f3)
	  
	  sipsec=$(cut -d' ' -f2 <<< "$line")
	  siphour=$(cut -d':' -f1 <<< "$sipsec")
	  sipmin=$(cut -d':' -f2 <<< "$sipsec")
	  sipsec=$(cut -d':' -f3 <<< "$sipsec")

	elif [[ $((ipotime)) == 2 ]]; then
	  sipyear=$(cut -d'm' -f1 <<< "$line")
	  sipday=$(date -d @$sipyear +'%Y-%m-%d %H:%M:%S')
	  if [[ $? != 0 ]]; then
		echo -e "\nerror: IPO date/time could not be extracted - ipotime=$ipotime sipyear=$sipyear"
		echo "line=$line"; echo "Contact $0 developer.  Aborting..."; exit 1
	  fi
	  sipmsec=${sipyear:7}	  
#	  sipmsec="000"

	  sipyear=$(cut -d' ' -f1 <<< "$sipday"  | cut -d'-' -f1)
	  sipmonth=$(cut -d' ' -f1 <<< "$sipday" | cut -d'-' -f2)
	  sipday=$(cut -d' ' -f1 <<< "$sipday"   | cut -d'-' -f3)

	  sipsec=$(cut -d' ' -f2 <<< "$sipday")
	  siphour=$(cut -d':' -f1 <<< "$sipsec")
	  sipmin=$(cut -d':' -f2 <<< "$sipsec")
	  sipsec=$(cut -d':' -f3 <<< "$sipsec")

  elif [[ $((ipotime)) == 1 ]]; then
	  sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d'm' -f1)  
	  sipmsec=${sipmsec:7}	  
#	  sipmsec="000"

	  sipsec=$(cut -d'T' -f2 <<< "$sipyear")
	  sipyear=$(cut -d'T' -f1 <<< "$sipyear")
	  sipmonth=$(cut -d'-' -f2 <<< "$sipyear")
	  sipday=$(cut -d'-' -f3 <<< "$sipyear")
	  sipyear=$(cut -d'-' -f1 <<< "$sipyear")

	  siphour=$(cut -d':' -f1 <<< "$sipsec")
	  sipmin=$(cut -d':' -f2 <<< "$sipsec")
	  sipsec=$(cut -d':' -f3 <<< "$sipsec")
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

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbf:sN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	e)
	    endptaddr=${OPTARG};;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
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
		elif [[ $var == "-e" ]]; then
		    skipper=2
		elif [[ $var == "-N"* ]]; then
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
           endptaddr=$var
		elif [[ $((skipper)) == 3 ]]; then
			findANI=$findANI		# findANI=$var
   
		fi
		skipper=0		
		continue
	fi
	
	file=$var
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0
	bvar=$(basename "$var")
	
	if [ -s $file ]; then
		echo -en "\nExploring content in $bvar... stand by\r"
		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -c -e ".*mS SIP [TR]x: .*" "$file" 2>/dev/null)

		if [[ $rec == 0 ]];	then
			echo -e "\nerror: No SIP messages have been found in $bvar in the expected format."
			error=1; rec=$(egrep -c -e ".*CSeq:.*" "$file" 2>/dev/null)

			if [[ $rec == 0 ]]; then
				echo "In fact, no sign of any "CSeq:" lines within $bvar"
				error=2
			else
				echo "Though, found $rec lines with "CSeq:" - so there might be some SIP messages within $bvar."
				rec=0
			fi
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
				if [[ $footprint == 1 ]]; then
					echo "Actually, $bvar appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			else
				echo "This file may not be an IPO Monitor log file... Verify source and content of $bvar."
			fi

		else
			vsyslog=4
			logsec=$SECONDS
			base64msg=0
			foundipaddr=""
			useragent=""
			ip1=""
			ip2=""
			localip1=""
			localip2=""
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
			ipotime=0

			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo -e "You may want to execute this script on a more powerful PC or server.\n"
			fi

			newfile="$file.asm.tmp"
			if [ -f $newfile ]; then
				rm "$newfile"
			fi

			echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
			echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
			echo "# Command line: $args" >> "$newfile"
			echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
			echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
			echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"

			while IFS= read -r line
			do
				nlines=$((nlines+1))

				if [[ $line =~ $pattern1 ]]; then
					if [[ $((sipstart)) != 0 ]]; then
						complete_sipmsg
					fi

					siptotalmsg=$((siptotalmsg+1))	                    # this is a new SIP msg
					insidesip=1 
					get_sip_datetime
					sip_direction							
				elif [[ $line =~ $pattern2 ]] || [[ $line =~ $pattern5 ]]; then
					if [[ $((sipstart)) != 0 ]]; then
						complete_sipmsg
					fi
					continue
				elif [[ $((insidesip)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
					sipmsg_header
					line=$(sed 's/^ *//g' <<< "$line")
					start_sipmsg
				elif [[ $((sipstart)) != 0 ]]; then
					if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
						if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
							calltime=$siptime
						elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
							callID=$line; callDIR=$dirdefined
						fi
					fi
					
					if [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then # TODO: handle content type : gzip
						base64found=1
						echo "# Base64 dump found" >> "$newfile"
						if [[ -f "$newfile.b64" ]]; then
							rm "$newfile.b64"
						fi
					elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
#						line=$(sed 's/^ *//g' <<< "$line")
						echo "$line" | sed 's/^ *//g' >> "$newfile.b64"
					else					
#						line=$(sed 's/^ *//g' <<< "$line")

#						if [[ $line =~ $pattern3 ]]; then
#							line=$(echo "$line" | sed 's/^[a-z]: //g')
#						fi
						echo "$line" | sed 's/^ *//g' >> "$newfile"
						siplines=$((siplines+1))
						get_useragent
					fi
				fi
			done < "$file"

			if [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
			fi
			echo '' >> "$newfile"

    	    if [[ $((sipstat)) != 0 ]]; then
				if [[ ${#endptaddr} == 0 ]]; then
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines) has been converted into $var.asm file"
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

				echo -e "\tTotal # of lines digested:\t\t\t $nlines"

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

			if [ -f $var.asm ]; then
				mv $var.asm $var.asm.bak
			fi
			mv "$newfile" "$var.asm"
			pwd; ls -l "$var.asm"
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
exit 0
