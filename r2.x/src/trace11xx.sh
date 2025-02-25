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
findANI=""
sipstat=1
adjusthour=0
base64decode=1
localip="1.1.1.1:1111"
protocol="TLS"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  

## 10) 11xx dbgshell - [SND] 10.100.1.61 5060
## 11) 11xx prtlog - Rec #1 ===============  NOTE: msec is not available!

function usage ()  {
    echo "trace11xx.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: trace11xx.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "    <LOG_FILE>\tis the SIP Log collected from a 11xxSIP/12xxSIP phone"
	echo -e "\t\tThis log file can be retrieved from either prtlog or dbgshell."
	echo -e "\t\t11xx/12xx SIP phones do not support remote SYSLOG."	
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"	
	echo -e "\t-s \t\tdo not provide statistics/progress on execution or result of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	siphour=0
	dirdefined=0
	base64found=0	
	uptime=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1;   siplines=$((siplines+1))
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
		echo -e "\nerror: failed to grab message header items at msg# $((n+1)) at line# $nlines of $file"
		echo "sipdate=$sipdate siptime=$siptime ip=$ip dirdefined=$dirdefined dirstring=$dirstring1 vsyslog=$vsyslog"
		echo "line=$line"
		error=10; echo -e "Contact developer."; exit $error
	else	
		n=$((n+1)); sipstart=0
		if [[ $((sipstat)) != 0 ]]; then		
			echo -en "$var => $n/$rec Msgs converted                \r"
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
#	if [[ $((vsyslog)) -lt 10 ]]; then
		if [[ $line == *"[SIP]:RECEIVED"* ]] || [[ $dirdefined == 1 ]]; then
			sipstream=5f70;				dirdefined=1
#	 		ip=$(echo "$line"        | cut -d' ' -f20)
#			siplength=$(echo "$line" | cut -d' ' -f17)
			case $voutput in
			1|2)	dirstring1="RECEIVED";  dirstring2="from";;
			3)		dirstring1="-->"; 	dirstring2="ingress";;
			esac
		elif [[ $line == *"[SIP]:SENDING"* ]] || [[ $dirdefined == 2 ]]; then
			sipstream=1474; 			dirdefined=2
#	 		ip=$(echo "$line"        | cut -d' ' -f20)
#			siplength=$(echo "$line" | cut -d' ' -f17)
			case $voutput in
			1)	dirstring1="SENT";		dirstring2="to";;
			2)	dirstring1="SENDING";	dirstring2="to";;
			3)	dirstring1="<--"; 		dirstring2="egress";;
			esac
		fi
#	fi
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
		echo -e "line=$line\n"; exit 1
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
	if [[ $((vsyslog)) == 10 ]] || [[ $((vsyslog)) == 11 ]]; then
		case $vsyslog in
		10)	sipyear=$(cut -d' ' -f2 <<< "$line")
			sipmsec=$(cut -d' ' -f3 <<< "$line");;
		11)	sipyear=$(cut -d' ' -f3 <<< "$line")
			sipmsec=$(cut -d' ' -f4 <<< "$line");;
		esac

		sipday=$(cut -d'/' -f2 <<< "$sipyear")
		sipmonth=$(cut -d'/' -f1 <<< "$sipyear")
		sipyear=$(cut -d'/' -f3 <<< "$sipyear")

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")

		if [[ $((vsyslog)) == 10 ]]; then
			sipmsec=$(awk -F'.' '{printf "%i",$2}' <<< "$sipsec") # need to use awk printf "5i" instead of "cut -d'.' -f2", in order to avoid inserting ^M to end of string
			sipsec=$(cut -d'.' -f1 <<< "$sipsec")
			if [[ $((sipmsec)) -lt 10 ]]; then
				sipsec=00$sipmsec
			elif [[ $((sipmsec)) -lt 100 ]]; then
				sipmsec=0$sipmsec
			fi
		elif [[ $((vsyslog)) == 11 ]]; then
			sipmsec="000"
		fi

	elif [[ $((vsyslog)) == 0 ]]; then 
		if [[ $((n)) == 0 ]]; then
			foundipaddr=$(cut -d' ' -f5 <<< "$line")
			sipyear=$(cut -d' ' -f8 <<< "$line")
			sipday=$(awk '{printf "%02i",$2}' <<< "$line")
			month=$(cut -d ' ' -f1 <<< "$line")
			get_sipmonth
		fi

		sipmsec=$(awk '{print $13}' <<< "$line") # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")  # TODO: sipsec/sipmsec modify in all other scripts at this point !!!				
	fi

	if [[ $((adjusthour)) == 1 ]]; then
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) ## TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) ## TODO need to print 2 digits
		fi
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
		elif [[ $var == "-e"* ]]; then
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
	bvar=$(basename "$var")
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0	
	
	if [ -f $file ]; then
		echo -en "\nExploring content in $var... stand by\r"

		##rec=$(grep -E "::SIP|\] PPM\:" $file| wc -l)
		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -c -e "^\[[SR][NC][DV]\] " "$file" 2>/dev/null)

		if [[ $rec == 0 ]];	then
			rec=$(egrep -c -e "^Rec #" "$file" 2>/dev/null)
			if [[ $rec != 0 ]]; then
				vsyslog=11
			else
				echo "error: No SIP messages have been found in $bvar in the expected format."
				echo "This file may not be a 11xx/12xx log file... or, DEBUG loglevel was not enabled."
				rec=$(egrep -c -e "^CSeq:*" < "$file" 2>/dev/null)
				error=1
				if [[ $rec == 0 ]]; then
					echo "In fact, no sign of any \"CSeq:\" lines within $bvar"
					error=2
				else
					echo "Though, found $rec lines with \"CSeq:\" - so there might be some SIP messages within $bvar"
					rec=0
				fi
				if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
					footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
					if [[ $footprint == 1 ]]; then
						echo "Actually, $file appears to be an .asm file created by SIPlog2traceSM tool."
				else 
					echo -e "Verify source and content of $bvar.\n"
				fi
			fi
		else
			vsyslog=10
		fi

		if [[ $((vsyslog)) == 0 ]]; then
			echo -e "\nCould not recognize source (product) in $bvar.\n"
		else	
			adjusthour=0 				## 11xx logs do not support TZ field
			logsec=$SECONDS
			base64msg=0
			foundipaddr=""
			useragent=""
			partnum="00"
			maxpart="99"
			nlines=0
			sipyear=0
#			siphour=0
			sipmin=0
			sipmsec=0
			sipmsg=0
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
			sipin=0
			sipout=0

			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo -e "You may want to execute this script on a more powerful PC or server.\n"
			fi			
			
			if [[ $((vsyslog)) == 11 ]]; then 
#				conv=$(awk -e '/^Rec #/{flag=1} flag; /}/{flag=0}' "$file")
				conv=$(awk -W source='/^Rec #/{flag=1} flag; /}/{flag=0}' "$file")				
			elif [[ $((vsyslog)) == 10 ]]; then
#    	    	conv=$(awk -e '/^\[[SR][NC][DV]\]/{flag=1} flag; /}/{flag=0}' "$file")
    	    	conv=$(awk -W source='/^\[[SR][NC][DV]\]/{flag=1} flag; /}/{flag=0}' "$file")				
			fi
##			check=$(egrep -e "<1[36][34567]>" <$file | wc -l)
			if [[ $((vsyslog)) == 1 ]] && [[ $((check)) == 0 ]]; then
				echo "ALERT: expecting SYSLOG extracted from Wireshark but did not find any lines with <166> pattern."
				echo "Could $var be a SYSLOG collected by KIWI or other tools instead of Wireshark?"
				echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
				exit 0
			elif [[ $((vsyslog)) != 1 ]] && [[ $((check)) != 0 ]]; then
				echo "ALERT: expecting ANDROID: and D/DeskPhoneServiceAdaptor lines but instead found some lines with <166> pattern."
				echo "Could $var be a SYSLOG extracted from Wireshark instead of vantage.log from a K1xx debugreport?"
				echo "Verify content of input file and/or launch parameters of this tool. Also refer to -help. ABORTing..."
				exit 0
			fi
		
			newfile="$file.asm.tmp"
			if [ -f "$newfile" ]; then
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

				if [[ $((insidesip)) == 1 ]] && [[ $((vsyslog)) == 11 ]]; then	
					if 	[[ $line == "Rec #"* ]]; then
						complete_sipmsg
						if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then	# IPADDR on [SND]/[RCV] line is server address, not endpoint !!  [SND] 10.100.1.61 506
							continue							
						fi
						insidesip=1														# this is a new SIP msg
					fi
				elif [[ $line == "[SND] "* ]] || [[ $line == "[RCV] "* ]] || [[ $line == "Rec #"* ]]; then
					if [[ $endptaddr != "" ]]  && [[ $line != *$endptaddr* ]]; then		# IPADDR on [SND]/[RCV] line is server address, not endpoint !!  [SND] 10.100.1.61 506
						insidesip=0				# reset_sipmsg
						continue					
					fi

					insidesip=1 # this is a new SIP msg

					if [[ $line == "[RCV] "* ]]; then
						dirdefined=1
					elif [[ $line == "[SND]"* ]]; then
						dirdefined=2
					fi

					if [[ $((dirdefined)) != 0 ]]; then
						ip1=$(cut -d' ' -f2 <<< "$line")
						ip2=$(awk -F' ' '{printf "%i",$3}' <<< "$line")  # grep -o '[^ ]*$') # need to use awk printf "5i" instead of cut -d' ' -f3, in order to avoid inserting ^M to end of string
						ip=$ip1:$ip2
					fi
				fi

				if [[ $((insidesip)) == 0 ]]; then
					continue;
				fi

				if [[ $((vsyslog)) == 10 ]] && [[ $line == "Logged "* ]]; then
					get_sip_datetime
					sip_direction
					sipmsg_header
				elif [[ $((vsyslog)) == 11 ]] && [[ $line == "Up time: "* ]]; then
					uptime=$(cut -d' ' -f3 <<< "$line")
					dirstring1=$(awk -F"Type: " '{print $2}' <<< "$line")
					if [[ $dirstring1 == "In"* ]]; then 
						dirdefined=1
					elif [[ $dirstring1 == "Out"* ]]; then
						dirdefined=2
					fi

				elif [[ $((vsyslog)) == 11 ]] && [[ $((dirdefined)) != 0 ]] && [[ $line == "Real time:"* ]];then
					ip="6.6.6.6:6666"
					get_sip_datetime
					sip_direction
					sipmsg_header
				elif [[ $siphour == 0 ]]; then
					continue

				elif [[ $((vsyslog)) == 10 ]] || [[ $((vsyslog)) == 11 ]]; then
					if [[ $line == "[ + 0"* ]]; then
						complete_sipmsg
					elif [[ $((sipstart)) == 0 ]]; then
						start_sipmsg
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
							if [[ -f $newfile.b64 ]]; then
								rm "$newfile.b64"
							fi
						elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
							echo "$line" >> "$newfile.b64"
						elif [[ $((vsyslog)) == 11 ]] && [[ $line == *"================"* ]]; then #  ================== is used for terminating INFO records in prtlog
							complete_sipmsg
						else
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

			if [ -f "$var.asm" ]; then
				mv "$var.asm" "$var.asm.bak"
			fi
			mv "$newfile" "$var.asm"
#		rm $file					# this is already a tmp file, can be removed
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
exit 0