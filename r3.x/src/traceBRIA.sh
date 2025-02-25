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
pattern1=": [TR]: [0-9]{1,3}.*\([A-Z]{3}\)*"
pattern2="\(UDP\)$"
findANI=""
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

function usage ()  {
    echo "traceBRIA.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceBRIA.sh [OPTIONS] [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the Log.txt or Output.txt file (collected from Bria@CounterPath softclient)"	
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
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
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1;   siplines=$((siplines+1))
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
		2)	echo -e "# msgno: $((sipmsg+1)){$NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi
} # sipmsg_header() 

function sip_direction () {
	if [[ $((dirdefined)) == 1 ]]; then
#	if [[ $line == *" incoming from: "* ]]; then
		sipstream=5f70
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)		dirstring1="-->"; 	dirstring2="ingress";;
		esac
#       ip=$(echo $line | cut -d' ' -f14)
# 	    protocol=$(echo $line | cut -d' ' -f15)

    elif [[ $((dirdefined)) -gt 1 ]]; then
#	elif [[ $line == *"Transmitting to"* ]]; then
		sipstream=1474
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	else
		insidesip=0
		dirdefined=0
	fi

	if [[ $((dirdefined)) == 1 ]] || [[ $((dirdefined)) == 2 ]]; then
       	ip=$(cut -d' ' -f16 <<< "$line")
	    protocol=$(cut -d' ' -f17 <<< "$line")
	fi
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) -gt 1 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
# 2022-05-24 10:21:10.754 | INFO |   RESIP:TRANSPORT | 110164 t44372 Transmitting to [ V4 10.134.117.194:5060 TCP target domain=10.134.117.194 mFlowKey=0 ] tlsDomain= via [ V4 135.105.163.42:62851 TCP target domain=10.134.117.194 mFlowKey=0 ]
# 2022-05-24 10:37:11.274 | INFO |   RESIP:TRANSPORT | 110164 t328 incoming from: [ V4 10.134.117.194:47389 TCP target domain=unspecified mFlowKey=4512 ]

	sipmsec=$(cut -d' ' -f2 <<< "$line")
    sipday=$(cut -d' ' -f1 <<< "$line")
	sipyear=$(cut -d'-' -f1 <<< "$sipday")
    sipmonth=$(cut -d'-' -f2 <<< "$sipday")
	sipday=$(cut -d'-' -f3 <<< "$sipday")
	
	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")
	sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
	sipsec=$(cut -d'.' -f1 <<< "$sipsec")

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
  while getopts ":hbf:sN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
	b)
		base64decode=0;;
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
		elif [[ $var == "-N"* ]]; then
			skipper=2
		else
			skipper=0
		fi
		var="": continue
	elif [[ $skipper != 0 ]]; then
		if [[ $skipper == 1 ]]; then
			voutput="$var"
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
				voutput=1
			fi
		elif [[ $((skipper)) == 2 ]]; then
			findANI=$findANI		# findANI=$var
		fi	
		skipper=0; var=""	
		continue
	fi
		
	file="$var"
	bvar=$(basename "$var")
	currtime=$(date +%R:%S)
	error=0;	vsyslog=0
	
	if [ -s "$file" ]; then
		echo -en "\nExploring content in $bvar... stand by\r"

		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -m 1 -c -e ".*Bria.*" "$file" 2>/dev/null)

		if [[ $rec == 0 ]]; then
		    echo "error: $var does not appear to be a BRIA logfile."
			echo -e "Verify source and content of $bvar.\n"			
			error=1; continue
		else
			rec=$(egrep -c -e "^CSeq:.*" "$file" 2>/dev/null)
			if [[ $rec == 0 ]];	then
				echo "error: No SIP messages have been found in $bvar in the expected format."
				echo "This file may not be an DebugSIP.txt logfile... or, FINEST debug was not enabled"
				echo -e "Verify source and content of $bvar.\n"
				error=2; continue
			else
				asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
				if [[ $((asmfile)) != 0 ]]; then
					asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
					if [[ $((asmfile)) != 0 ]]; then
						echo "It appears $bvar is a traceSM file (or a converted file using 3rd output format)."
						echo "This kind of input is not (yet) supported by this tool."
					fi
				else
					rec2=$(egrep -c -e "* Transport failure: " "$file" 2>/dev/null)
					rec=$((rec-$rec2))
					vsyslog=3
				fi
			fi
		fi
    
		if [[ $rec -gt 0 ]] && [[ $((vsyslog)) != 0 ]]; then
			logsec=$SECONDS
			base64msg=0
			foundipaddr=""
			useragent=""
			ip=""
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

			vsyslog=3			

			newfile=$file.asm.tmp
			if [ -f $newfile ]; then
				rm $newfile
			fi

			echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
			echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
			echo "# Command line: $args" >> "$newfile"
			echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
			echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
			echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"

#            conv=$(awk -e '/^\-\-\-\-\-\-\-\-\-\-\-\-\-.*\-\-\-\-\-\-\-$/{flag=1} flag; /}/{flag=0}' "$file")
            # conv=$(awk -W source='/.*Transmitting to.*|.*incoming from:.*"/{flag=1} flag; /}/{flag=0}' "$file")
# ----------------------------------------------------------------------------------------			

			while IFS= read -r line
			do
				nlines=$((nlines+1))

				if [[ $((insidesip)) == 0 ]]; then
                	if [[ $line =~ RESIP.*incoming\ from: ]]; then
				   		dirdefined=1
                	elif [[ $line =~ RESIP.*Transmitting\ to ]]; then
				   		dirdefined=2
					elif [[ $line =~ RESIP.*Making.*request: ]]; then
						dirdefined=3
# 2022-05-24 10:29:35.968 | DEBUG |         RESIP:DUM | 110164 t328 Making subscription (from creator) request: SUBSCRIBE sip:8811135@lab.bud.avaya.com:5061 SIP/2.0
# Via: SIP/2.0/ ;branch=z9hG4bK-524287-1---e4057f49a97d0a6b;rport
					fi

					if [[ $((dirdefined)) != 0 ]]; then
#			    if [[ $((insidesip)) == 0 ]]; then
#				  if [[ $line == *"Transmitting to"* ]] || [[ $line == *" incoming from: "* ]]; then

				#  && [[ $line =~ $pattern2 ]]

				  	  	if [[ $((sipstart)) != 0 ]]; then
                    	  complete_sipmsg
				    	fi
			 	    	insidesip=1
			 	    	siptotalmsg=$((siptotalmsg+1))	
				    	sip_direction
			 	    	get_sip_datetime

						if [[ $((dirdefined)) == 3 ]]; then
						  ip="6.6.6.6:6666"
						  protocol="TLS"
						  line=$(awk -F"request: " '{print $2}' <<< "$line")
					      sipmsg_header
		                  start_sipmsg
						  insidesip=2
						fi
					fi			   
                elif [[ $((insidesip)) == 1 ]] && [[ $((dirdefined)) != 0 ]]; then
				   insidesip=2
				elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
				   if [[ $((dirdefined)) == 2 ]] && [[ ${#line} -lt 2 ]]; then # since "Transmitting to " lines often have no SIP msg
#				   if [[ $linelength -l 3 ]]; then
				      insidesip=0
					  dirdefined=0
				   elif [[ $((dirdefined)) -lt 3 ]]; then
				      sipmsg_header
	                  start_sipmsg
				   fi
				elif [[ $((sipstart)) == 1 ]]; then
					if [[ $line == " | "* ]] || [[ $line == "sigcomp "* ]]; then
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
#	   		done <<< "$conv"
			done < "$file"

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
					echo "==> $sipmsg out of $n/$rec SIP messages has been converted into $output.asm file"
				else
					if [[ $((sipmsg)) == 0 ]]; then 
						echo "==> no SIP messages were found for addr=$endptaddr in $bvar file"
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

				echo -e "\tTotal # of lines digested:\t\t\t\t $nlines"

				if [[ $((sipmsg)) != 0 ]]; then
					echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
					echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
					echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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
#			rm "$file"					# this is already a tmp file, can be removed
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
if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
fi
exit 0