#!/bin/bash
version="2.0.0.3"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
AWKSRCFLAG="-W source="
year=$(date +%Y)
today=$(date +%m/%d/%Y)
pattern1='-----------------------------------------------------------------'
pattern2='<I,sip.*INCOMING|<I,sip.*OUTGOING'
# pattern2='^FINE.*% $'
# pattern3='^% '
# pattern4='^INFO|^FINE|^FINER|^FINEST'
findANI=""
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

## 18) SES - siptracer.txt

function usage ()  {
    echo "traceSES.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"
#	echo ''
	echo 'Usage: traceSES.sh [OPTIONS] [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the sipTraceLog.txt file collected from an Avaya SES server"
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
	ip=""
	insidesip=0
	sipstart=0
	siplines=0
	sipyear=""
	dirdefined=0
	base64found=0
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
		base64msg=$((base64msg+1))
		base64found=0
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
		echo -e "\nerror: failed to grab message header items at msg# $((n+1)) at line# $nlines"
		echo "sipdate=$sipdate siptime=$siptime ip=$ip dirstring=$dirstring1"
		echo "$line"
		echo -e "\nContact developer.\n"; exit 1
	else	
	    n=$((n+1)); sipstart=0
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
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line == *"[Recv "* ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70; 			dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)		dirstring1="-->"; 	dirstring2="ingress";;
		esac
		##ip=$(echo $line | awk '{print $5}')
	elif [[ $line == *"[Send "* ]]; then
		## elif [[ $direction == 'Outbound' ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
 		##ip=$(echo $line | awk '{print $5}')
	else
		insidesip=0
		dirdefined=0
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
		echo $line
		echo ''; exit 1
	fi
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"Server:"* ]]; then
			useragent=$(awk -F'Server: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 18 ]]; then 
##		if [[ $((n)) == 0 ]]; then
##			foundipaddr=$(echo $line | cut -d' ' -f5)
			sipyear=$(awk '{print $4}' <<< "$line") 		         # cut -d' ' -f4) --  because of multiple spaces
			sipday=$(awk '{printf "%02i",$2}' <<< "$line")  	     # cut -d' ' -f2) --  because of multiple spaces
			month=$(cut -d' ' -f1 <<< "$line")
			get_sipmonth
##		fi

####		siphour=$(echo $line | cut -d' ' -f3)
####		sipmin=$(echo $siphour | cut -d ':' -f2) # awk -F ':' '{print $2}')
####		sipsec=$(echo $siphour | cut -d ':' -f3) # awk -F ':' '{print $3}')
####		siphour=$(echo $siphour |cut -d ':' -f1) # awk -F ':' '{print $1}')
# May  4 19:59:47 2009 matching filter label <4601_BAD>: HELPDESK-SES.avaya.com: [Recv Request  ]
		sipmsec=$(awk '{print $3}' <<< "$line")       			   # cut -d' ' -f4) --  because of multiple spaces
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec="000"	
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
			findANI=$findANI											# findANI=$var
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

		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -c -e "^\{connection:" "$file" 2>/dev/null)

		if [[ $rec == 0 ]];	then
			echo -e "\nerror: No SIP messages have been found in $bvar in the expected format."
			echo "This file may not be an SES sipTraceLog.txt logfile... or, DEBUG loglevel was not enabled."
			error=1
#           rec=$(egrep -c -m 1 -e "^Server: Avaya SIP Enablement Services")
			rec=$(egrep -c -m 1 -e "^Server:Avaya SIP Enablement Services.*" "$file" 2>/dev/null)
			if [[ $rec == 0 ]]; then
			    echo "No indication $bvar being related to SES logfile. Verify source and content of this file."
			else
			    echo "Though, found reference in $bvar to SES. Verify source and content of this file"
			fi
			
			rec=$(egrep -c -e "[RC]Seq:" "$file" 2>/dev/null)
			if [[ $rec == 0 ]]; then
				echo "In fact, no sign of any \"CSeq:|RSeq:\" lines within $bvar"
				error=2; rec=0
			else
				echo "Though, found $rec lines with \"CSeq:|RSeq\" - so there might be some sort of SIP messages within $bvar."
				error=3; rec=0
				asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
				if [[ $((asmfile)) != 0 ]]; then
					asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
					if [[ $((asmfile)) != 0 ]]; then
						echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
						echo "This kind of input is not (yet) supported by this tool."
					fi
				fi
			fi
			if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file" 2>/dev/null)
				if [[ $footprint == 1 ]]; then
					echo "Actually, $bvar appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			fi
		else
			vsyslog=18
		fi

        if [[ $((vsyslog)) != 0 ]]; then
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
			callID=""
			calltime=""
			callDIR=0
			sipin=0
			sipout=0

			reset_sipmsg
			
    	    #conv=$(awk -e '/<I,sip.*INCOMING|<I,sip.*OUTGOING/{flag=1} flag; /}/{flag=0}' $file)
			#conv=$(awk -e '/.*matching.*/{flag=1} flag; /}/{flag=0}' $file)

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo -e "You may want to execute this script on a more powerful PC or server.\n"
			fi

			newfile="$file.asm.tmp"
			if [ -f "$newfile" ]; then
				rm "$newfile" 2>/dev/null
			fi

			echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
			echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
			echo "# Command line: $args" >> "$newfile"
			echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
			echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
			echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"

			while IFS= read -r line
			do
				linelength=${#line}
				nlines=$((nlines+1))

				if [[ $((sipstart)) != 0 ]] && [[ $line == *"-----------------------------------------------------------------"* ]]; then # [[ $line =~ $pattern1 ]]; then
					complete_sipmsg
				fi

				if [[ $((insidesip)) == 0 ]] && [[ $line == *"matching filter"* ]]; then       # this is a new SIP msg
					siptotalmsg=$((siptotalmsg+1))		
					insidesip=1
					get_sip_datetime
					sip_direction
				elif [[ $((insidesip)) != 0 ]] && [[ $line == *"connection:"* ]]; then
					if [[ $line == *"Unavailable"* ]]; then
						ip="6.6.6.6:666"
					else
						ip1=$(cut -d'=' -f2 <<< "$line" | cut -d' ' -f1)
						ip2=$(cut -d'=' -f3 <<< "$line" | cut -d' ' -f1)
						protocol=$(cut -d'=' -f4 <<< "$line" | cut -d'}' -f1)
						ip="$ip1:$ip2"
					fi
					sipmsg_header
				elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
					start_sipmsg
					
				elif [[ $((sipstart)) != 0 ]]; then
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
#			done <<<"$conv"
			done < "$file"

			if [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
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

				echo -e "\tTotal # of lines digested:\t\t\t\t $nlines"

				if [[ $((sipmsg)) != 0 ]]; then
					echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
					echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
					echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
					if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
						echo -e "\tBase64 encoded SIP messages:\t\t\t $base64msg"
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

if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
fi
exit 0