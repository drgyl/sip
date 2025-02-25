#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
today=$(date +%m/%d/%Y)
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
    echo "trace11xx.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: trace11xx.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "    <LOG_FILE>\tis the SIP Log collected from a 11xxSIP/12xxSIP phone"
	echo -e "\t\tThis log file can be retrieved from either prtlog or dbgshell."
	echo -e "\t\t11xx/12xx SIP phones do not support remote SYSLOG."	
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution or result of this conversion"
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
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	siplines=$((siplines+1))
	siptotalmsg=$((siptotalmsg+1))
	if [[ $((voutput)) == 1 ]]; then 
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -en "$NL$line" >> "$newfile"
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
	uptime=""
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
		echo -e "[$sipstream] }\x0d$NL" >> "$newfile"
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
		n=$((n+1))
		sipstart=0
		if [[ $((sipstat)) != 0 ]]; then		
			echo -en "$var => $n/$rec Msgs converted                \r"
		fi
		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} # sipmsg_header()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
#	if [[ $((vsyslog)) -lt 10 ]]; then
		if [[ $line == *"[SIP]:RECEIVED"* ]] || [[ $dirdefined == 1 ]]; then
			dirdefined=1
			sipstream=5f70			
#	 		ip=$(echo "$line"        | cut -d' ' -f20)
#			siplength=$(echo "$line" | cut -d' ' -f17)
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

		elif [[ $line == *"[SIP]:SENDING"* ]] || [[ $dirdefined == 2 ]]; then
			dirdefined=2
			sipstream=1474			
#	 		ip=$(echo "$line"        | cut -d' ' -f20)
#			siplength=$(echo "$line" | cut -d' ' -f17)
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
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 10 ]] || [[ $((vsyslog)) == 11 ]]; then
		if [[ $((vsyslog)) == 10 ]]; then
			sipyear=$(echo "$line" | cut -d' ' -f2)
			sipmsec=$(echo "$line" | cut -d' ' -f3)
		elif [[ $((vsyslog)) == 11 ]]; then
			sipyear=$(echo "$line" | cut -d' ' -f3)
			sipmsec=$(echo "$line" | cut -d' ' -f4) 
		fi

		sipday=$(echo $sipyear   | cut -d'/' -f2)
		sipmonth=$(echo $sipyear | cut -d'/' -f1)
		sipyear=$(echo $sipyear  | cut -d'/' -f3)

		siphour=$(echo $sipmsec  | cut -d':' -f1)
		sipmin=$(echo $sipmsec   | cut -d':' -f2)
		sipsec=$(echo $sipmsec   | cut -d':' -f3)

		if [[ $((vsyslog)) == 10 ]]; then
			sipmsec=$(echo $sipsec | awk -F'.' '{printf "%i",$2}') # need to use awk printf "5i" instead of "cut -d'.' -f2", in order to avoid inserting ^M to end of string
			sipsec=$(echo $sipsec  | cut -d'.' -f1)
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
			foundipaddr=$(echo $line | cut -d' ' -f5)
			sipyear=$(echo $line | cut -d' ' -f8)
			sipday=$(echo $line | awk '{printf "%02i",$2}')
			month=$(echo $line | cut -d ' ' -f1)
			get_sipmonth
		fi

		sipmsec=$(echo $line | awk '{print $13}') # cut -d' ' -f13) not good for vantageR2.log where it starts with "Feb  2 10:19:07 (two space between Feb and 2"

		siphour=$(echo $sipmsec | cut -d':' -f1)
		sipmin=$(echo $sipmsec  | cut -d':' -f2)
		sipsec=$(echo $sipmsec  | cut -d':' -f3)
		sipmsec=$(echo $sipsec  | cut -d'.' -f2)
		sipsec=$(echo $sipsec   | cut -d'.' -f1)  # TODO: sipsec/sipmsec modify in all other scripts at this point !!!		
		
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

	if   [[ $((voutput)) == 1 ]]; then
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

		##rec=$(grep -E "::SIP|\] PPM\:" $file| wc -l)
		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -c -e "^\[[SR][NC][DV]\] " "$file")

		if [[ $rec == 0 ]];	then
			rec=$(egrep -c -e "^Rec #" "$file")
			if [[ $rec != 0 ]]; then
				vsyslog=11
			else
				echo "error: No SIP messages have been found in $var. Perhaps this file is not a 11xx/12xx log file."
				rec=$(egrep -c -e "^CSeq:*" < "$file")
				error=1
				if [[ $rec == 0 ]]; then
					echo 'In fact, no sign of any "CSeq:" lines in '$var
					error=2
				else
					echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages in '$var
					rec=0
				fi
				echo "Verify source and content of this $file.";
				echo ''; continue
			fi
		else
			vsyslog=10
		fi

		if [[ $((vsyslog)) == 0 ]]; then
			echo "Could not recognize source (product) in $var."
			echo ''			
		else	
			adjusthour=0 				## 11xx logs do not support TZ field
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			uptime=""
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
			longestmsg=0			

			reset_sipmsg
			
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
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"

			while IFS= read -r line
			do
				# linelength=$(echo $line | wc -c)
#				linelength=${#line}
				nlines=$((nlines+1))

				if [[ $((insidesip)) == 1 ]] && [[ $((vsyslog)) == 11 ]]; then	
					if 	[[ $line == "Rec #"* ]]; then
						complete_sipmsg
						if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then	# IPADDR on [SND]/[RCV] line is server address, not endpoint !!  [SND] 10.100.1.61 506
							continue							
						fi
						insidesip=1														# this is a new SIP msg
						base64found=0
					fi
				elif [[ $line == "[SND] "* ]] || [[ $line == "[RCV] "* ]] || [[ $line == "Rec #"* ]]; then
					if [[ $endptaddr != "" ]]  && [[ $line != *$endptaddr* ]]; then		# IPADDR on [SND]/[RCV] line is server address, not endpoint !!  [SND] 10.100.1.61 506
						insidesip=0				# reset_sipmsg
						continue					
					fi

					insidesip=1 # this is a new SIP msg
					base64found=0

					if [[ $line == "[RCV] "* ]]; then
						dirdefined=1
					elif [[ $line == "[SND]"* ]]; then
						dirdefined=2
					fi

					if [[ $((dirdefined)) != 0 ]]; then
						ip1=$(echo -n "$line" | cut -d' ' -f2)
						ip2=$(echo -n "$line" | awk -F' ' '{printf "%i",$3}')  # grep -o '[^ ]*$') # need to use awk printf "5i" instead of cut -d' ' -f3, in order to avoid inserting ^M to end of string
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
					uptime=$(echo "$line"     | cut -d' ' -f3)
					dirstring1=$(echo "$line" | awk -F"Type: " '{print $2}')
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
					elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
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
			done <<< "$conv"
#		fi

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
				echo -e "$NL\tUser-Agent: $useragent"
				if [[ $foundipaddr != "" ]]; then
					echo -e "\t\tusing ipaddr = $foundipaddr"
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
#		rm $file					# this is already a tmp file, can be removed
		pwd;ls -l "$var.asm"
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done