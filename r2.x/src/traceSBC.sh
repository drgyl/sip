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
protocol="TLS"
endptaddr="" # 135.105.129.244"
voutput=3  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=3

function usage ()  {
    echo "traceSBC.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceSBC.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the SIP logfile collected from Avaya SBC server"
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"
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
	if [[ $line == "SIP IN: "* ]]; then
		sipstream=5f70; 			dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)		dirstring1="-->"; 	dirstring2="ingress";;
		esac
	elif [[ $line == "SIP OUT: "* ]]; then
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

	if [[ $((dirdefined)) == 2 ]]; then
       ip=$(cut -d' ' -f5 <<< "$line")
	   localip=$(cut -d' ' -f3 <<< "$line")
	   protocol=$(awk '{printf substr($6,2,3)}' <<< "$line")   # cut -d' ' -f6 | cut -d'(' -f2 | cut -d')' -f1)
#	   protocol=$(echo "$line" | cut -d' ' -f6 | cut -d'(' -f2 | cut -d')' -f1)	   
	elif [[ $((dirdefined)) == 1 ]]; then
       localip=$(cut -d' ' -f5 <<< "$line")
	   ip=$(cut -d' ' -f3 <<< "$line")
	   protocol=$(awk '{printf substr($6,2,3)}' <<< "$line")   # cut -d' ' -f6 | cut -d'(' -f2 | cut -d')' -f1)	   
#	   protocol=$(echo "$line" | cut -d' ' -f6 | cut -d'(' -f2 | cut -d')' -f1)
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
# @2022-01-18 10:26:22,699||FINEST|SIP|539122|FileName=sip/SIPTCP.cpp,LineNumber=426|RCV sock=136:0 src=10.134.48.67:5060 dst=10.134.142.36:31000 <SIP/2.0 200 OK
# ----------------------------------------------------------------------------------------
# [09-07-2022:06.31.02.173944]
# SIP OUT: 204.2.132.9:5061 --> 223.190.80.74:2206 (TLS)

	sipmsec=$(cut -d':' -f2  <<< "$prevline" | cut -d']' -f1) 
	sipday=$(cut -d':' -f1 <<< "$prevline"   | cut -d'[' -f2)
	sipyear=$(cut -d'-' -f3 <<< "$sipday")
	sipmonth=$(cut -d'-' -f2 <<< "$sipday")
	sipday=$(cut -d'-' -f1 <<< "$sipday")
									
	siphour=$(cut -d'.' -f1 <<< "$sipmsec")
	sipmin=$(cut -d'.' -f2 <<< "$sipmsec")
	sipsec=$(cut -d'.' -f3 <<< "$sipmsec")
#	sipmsec=$(echo $sipmsec    | cut -d'.' -f4)
    sipmsec=$(awk -F'.' '{printf "%03i",$4/1000}' <<< "$sipmsec")

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
  while getopts ":hbf:sN:e:" options; do
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
			if [[ $((vsyslog)) -lt 5 ]] || [[ $((vsyslog)) -gt 7 ]]; then
				vsyslog=7
			fi
		elif [[ $((skipper)) == 3 ]]; then
			endptaddr=$var
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
	
	if [ -s "$file" ]; then
		echo -e -n "\nExploring content in $bvar... stand by\r"
		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -c -e "^SIP IN:.*|^SIP OUT:.*" "$file" 2>/dev/null)

		if [[ $rec == 0 ]];	then
			echo "error: No SIP messages have been found in $bvar in the expected format."
			echo "This file may not be an SBC SIP log file... or, FINEST debug was not enabled."
			error=1; rec=$(egrep -c -e "^CSeq:.*" "$file" 2>/dev/null)
			if [[ $rec == 0 ]]; then
				echo "In fact, no sign of any \"CSeq:\" lines within $bvar"
				error=2
			else
				echo "Though, found $rec lines with \"CSeq:\" - so there might be some SIP messages within $bvar"
				rec=0; error=2
			fi
			echo "Verify source and content of $bvar."
			continue
		else
			vsyslog=3
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
			echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"

			# echo -e -n "Searching for beginning of first SIP message in $file... stand by\r"
#            conv=$(awk -e '/^\-\-\-\-\-\-\-\-\-\-\-\-\-.*\-\-\-\-\-\-\-$/{flag=1} flag; /}/{flag=0}' "$file")
# ----------------------------------------------------------------------------------------			

			while IFS= read -r line
			do
				nlines=$((nlines+1))
			    if [[ $line == "SIP IN: "* ]] || [[ $line == "SIP OUT: "* ]]; then
				    sip_direction
					if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
						if [[ $localip != "" ]] && [[ $endptaddr != "" ]] && [[ $localip != *$endptaddr* ]]; then
							reset_sipmsg
							continue
						fi
				  	else
			 	   		insidesip=1
			 	   		siptotalmsg=$((siptotalmsg+1))	
			 	   		get_sip_datetime
				   	fi				
            
				elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
				   sipmsg_header
	               start_sipmsg
				elif [[ $((sipstart)) == 1 ]]; then
#				    if [[ $line =~ ^\-\-\-\-\-\-\-\-\.*\-\-\-\-\-\-\-\$ ]]; then
#					if [[ $line == "----------------------------------------------------------------------------------------" ]]; then
					if [[ $line == *"---------------------------------------------------------------"* ]]; then
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
							echo "$line" >> "$newfile.b64					"
						else					
							echo "$line" >> "$newfile"
							siplines=$((siplines+1))
							get_useragent
						fi
					fi
				fi
				prevline=$line
#	  	  done <<< "$conv"
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

			if [ -f "$var.asm" ]; then
				mv "$var.asm" "$var.asm.bak"
			fi
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