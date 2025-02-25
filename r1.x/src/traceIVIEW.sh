#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
# echo ''
today=$(date +%m/%d/%Y)
# pattern1='.*MX Sigtrace.*'
# pattern2='<I,sip.*INCOMING|<I,sip.*OUTGOING'
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

# TODO: manage iVIEW CS Capture package

function usage ()  {
    echo "traceIVIEW.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceIVIEW.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the sip.log file from an IX Meetings (iView) server iVIEW_CS_CAPTURE logreport"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"			
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

# TODO: handle CS package logreport with multiple sip.log files

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	sipyear=""
	dirdefined=0
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	siplines=$((siplines+1))
	if [[ $((voutput)) == 1 ]]; then 
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -en "$NL$line$NL" >> "$newfile"
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
	
	if [[ $((sipsplit)) != 0 ]]; then
		sipmaxsplit=$((sipmaxsplit+1))
		
		if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
			sipmaxpart=${maxpart#0}
		fi
	fi
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
		echo -e "$NL[$sipstream] }\x0d$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -e "$NL}$NL" >> "$newfile"
	elif [[ $((voutput)) == 3 ]]; then
		echo "--------------------" >> "$newfile"
	fi

	reset_sipmsg
fi
} # complete_sipmsg()

function sipmsg_header () {
	if [[ $((dirdefined)) != 0 ]]; then
		n=$((n+1))
		sipstart=0

		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$var => $n/$rec Msgs converted            \r"
		fi

		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} # sipmsg_header() 

function sip_direction () {
# 2018-10-09 13:13:15.092 [.INFO] [..MESSAGE] <--- 10.16.201.47:5060 0 1194
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line == *"<---"* ]]; then
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
		
	elif [[ $line == *"--->"* ]]; then
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
	
#	if [[ $((dirdefined)) != 0 ]]; then
	if [[ $((vsyslog)) == 8 ]]; then
 		ip=$(echo "$line"        | cut -d' ' -f6)
		siplength=$(echo "$line" | awk '{ printf "%i",$8}')  # cut -d' ' -f8)
	else
		ip="6.6.6.6:6666"
		siplength=666
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
	if [[ $((vsyslog)) == 8 ]]; then 
# 2018-10-09 13:13:15.110 [.INFO] [..MESSAGE] ---> 10.16.201.60:5060 0 1211	
##			foundipaddr=$(echo $line | cut -d' ' -f5)
		sipday=$(echo "$line"   | cut -d' ' -f1)
		sipyear=$(echo $sipday  | cut -d'-' -f1)
		sipmonth=$(echo $sipday | cut -d'-' -f2)
		sipday=$(echo $sipday   | cut -d'-' -f3)								

		sipmsec=$(echo "$line"  | cut -d' ' -f2) 
		siphour=$(echo $sipmsec | cut -d':' -f1)
		sipmin=$(echo $sipmsec  | cut -d':' -f2)
		sipsec=$(echo $sipmsec  | cut -d':' -f3)
		sipmsec=$(echo $sipsec  | cut -d'.' -f2)
		sipsec=$(echo $sipsec   | cut -d'.' -f1)
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

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbf:s" options; do
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

if [[ $((base64decode)) != 0 ]]; then
   base64 --version >/dev/null
   if [[ $? != 0 ]]; then
	  base64decode=0
   fi
fi

skipper=0

for var in "$@"
	do

	if [[ $var == "-"* ]]; then
		if [[ $var == "-f"* ]]; then
			skipper=1
		elif [[ $var == "-e" ]]; then
		    skipper=2
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
		fi
		skipper=0
		continue
	fi
	
	file=$var
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0
	
	if [ -f $file ]; then
		echo -en "Exploring content in $var... stand by\r"
		
#		rec=$(egrep -c -e ".*MESSAGE\] <---.*|.*MESSAGE\] --->.*" <$file)
		rec=$(egrep -c -e ".*MESSAGE\] CSeq:*" "$file")

		if [[ $rec != 0 ]]; then  # iVIEW sip log
			egrep ".*\[..MESSAGE\].*" "$file" > "$file.MESSAGE"
			file="$file.MESSAGE"
			vsyslog=8
		else
			rec=$(egrep -m 1 -c -e ".*tSipAdap.*TRANSPORT.* CSeq:*" "$file")
			if [[ $rec != 0 ]]; then
				rec=0
				echo "error: $var appears to be an MCU logfile - try to use \"traceMCU.sh\" script instead"
				error=1; continue
			else
				echo "error: No SIP messages have been found in $var in the expected format."
				echo "Perhaps $var is not an iVIEW sip.log file... or, DEBUG level was not enabled in logging."
				rec=$(egrep -c -e "^CSeq:.*" "$file")
				if [[ $rec == 0 ]]; then
					echo "In fact, no sign of any "CSeq:" lines in $var"
					error=2
				else
					echo "Though, found $rec lines with "CSeq:" - so there might be some sort of SIP messages included."
					rec=0
					error=2
				fi
				echo "Verify source and content of $var"
				echo ''; continue
			fi
		fi

		if [[ $rec != 0 ]];	then
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			sipyear=""
			sipmonth=""
			sipday=""
			siphour=""
			sipmin=""
			sipsec=""
			sipmsec=""
			nlines=0
			n=0
			sipmsg=0
			siptotalmsg=0
			sipmaxlines=0
			sipmaxpart=0
			sipmaxsplit=0
		    sipwordlist=""									
            longestmsg=0
			sipin=0
			sipout=0
	
			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo "You may want to execute this script on a more powerful PC or server."
				echo ''
			fi

    	    #conv=$(awk -e '/<I,sip.*INCOMING|<I,sip.*OUTGOING/{flag=1} flag; /}/{flag=0}' $file)

			newfile="$var.asm.tmp"
			if [ -f "$newfile" ]; then
				rm "$newfile"
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "Input/output file: $var -> $var.asm\n" >> "$newfile"

			while IFS= read -r line
			do
				nlines=$((nlines+1))

				if [[ $((sipstart)) != 0 ]]; then
					if [[ $line == *"<---"* ]] || [[ $line == *"--->"* ]]; then
						complete_sipmsg
					fi
				fi

				if [[ $((dirdefined)) == 0 ]]; then
				 	if [[ $line == *"<---"* ]] || [[ $line == *"--->"* ]]; then
					 	sip_direction
					 	if [[ $((vsyslog)) == 8 ]] && [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
							reset_sipmsg
						else
							siptotalmsg=$((siptotalmsg+1))	
							insidesip=1                                         # this is a new SIP msg
							base64found=0
							get_sip_datetime
							sipmsg_header
						fi
					fi
				elif [[ $((sipstart)) == 0 ]]; then
					if [[ $line == *"<---"* ]]; then
						line=$(echo "$line" | awk -F'<--- ' '{print $2}')
						start_sipmsg
					elif [[ $line == *"--->"* ]]; then
						line=$(echo "$line" | awk -F'---> ' '{print $2}')
						start_sipmsg
					fi
				elif [[ $((sipstart)) == 1 ]]; then
					line=$(echo "$line" | awk -F'] ' '{print $3}')
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
		done < "$file"

		if [[ $((sipstart)) == 1 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

        if [[ $((sipstat)) == 1 ]]; then
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
		echo "Task started: $currtime - completed: $(date +%R:%S)"
		echo ''
		if [ -f "$var.asm" ]; then
			mv "$var.asm" "$var.asm.bak"
		fi		
		mv "$newfile" "$var.asm"
		pwd;ls -l "$var.asm"
		rm "$file"                         # this is "$var.MESSAGE" tmp file		
		echo '' 
	fi
else
	echo "error: file $var was not found."
	error=3	
fi
done