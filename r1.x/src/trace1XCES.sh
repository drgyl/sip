#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
pattern1='^\([0-9]{2|-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,sip,'
pattern2='<I,sip.*INCOMING|<I,sip.*OUTGOING'
# pattern2='^FINE.*% $'
# pattern3='^% '
# pattern4='^INFO|^FINE|^FINER|^FINEST'
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0 

## TODO CES logreport - trace.log or trace_*.log in .tgz/tar or .zip: opt\IBM\WebSphere\AppServer85\profiles\default\logs\server1\

function usage ()  {
    echo "trace1XCES.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: trace1XCES.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the trace.log file from a 1X CES server logreport"
	echo -e "\t\t\twhich can be found in /opt/IBM/WebSphere/AppServer85/profiles/default/logs/server1/ folder"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
	echo -e "  Note:\t\t\t1X CES does not log IP addr in either RX or TX direction"
	echo ''
} # usage()

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
			echo -en "$var => $n/$rec Msgs converted            \r"
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
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line == *" Received "* ]] || [[ $line == *"Got response"* ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70
		dirdefined=1
		ip="6.6.6.6:666"
#		siplength="666"
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
		##ip=$(echo $line | awk '{print $5}')
	elif [[ $line == *" Sending SIP "* ]] || [[ $line == *"Sending response"* ]]; then
		## elif [[ $direction == 'Outbound' ]]; then
		sipstream=1474
		dirdefined=2
		ip="6.6.6.6:666"
#		siplength="666"	
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
		##ip=$(echo $line | awk '{print $5}')
	else
		insidesip=0
		dirdefined=0
	fi
	
#	if [[ $((dirdefined)) != 0 ]]; then
##	if [[ $((vsyslog)) == 15 ]]; then
#		ip="6.6.6.6:666"
#		siplength="666"	
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
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 1 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
#	if [[ $((vsyslog)) == 15 ]]; then 
##		if [[ $((n)) == 0 ]]; then
##			foundipaddr=$(echo $line | cut -d' ' -f5)
			sipyear=$(echo "$line"    | cut -d' ' -f1)
			sipday=$(echo $sipyear    | cut -d'/' -f2)
			sipmonth=$(echo $sipyear  | cut -d'/' -f1 | cut -d'[' -f2)
			sipyear=$(echo $sipyear   | cut -d'/' -f3)
#			sipmonth=$(echo $sipmonth | cut -d'[' -f2)
##		fi

####		siphour=$(echo $line | cut -d' ' -f3)
####		sipmin=$(echo $siphour | cut -d ':' -f2) # awk -F ':' '{print $2}')
####		sipsec=$(echo $siphour | cut -d ':' -f3) # awk -F ':' '{print $3}')
####		siphour=$(echo $siphour |cut -d ':' -f1) # awk -F ':' '{print $1}')
		sipmsec=$(echo "$line"   | cut -d' ' -f2) 
		siphour=$(echo $sipmsec  | cut -d':' -f1)
		sipmin=$(echo $sipmsec   | cut -d':' -f2)
		sipsec=$(echo $sipmsec   | cut -d':' -f3)
		sipmsec=$(echo $sipmsec  | cut -d':' -f4)

		# siptime=$(echo $line | awk '{print $3":"$8}')  ## msec included in $8
####		siptmp=$(echo $line | awk '{print $6}')
####		tzhour=$(echo $siptmp |cut -d':' -f 1) # awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
####		tzmin=$(echo $siptmp | cut -d':' -f 2) # awk -F ':' '{print $2}')
		
#	fi

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

	if [[ ${#siphour} -lt 2 ]]; then
		siphour="0$siphour"
	fi
	if [[ ${#sipmonth} -lt 2 ]]; then
		sipmonth="0$sipmonth"
	fi
	if [[ ${#sipday} -lt 2 ]]; then
		sipday="0$sipday"
	fi
	if [[ ${#sipyear} -lt 4 ]]; then
		sipyear="20$sipyear"
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
	elif [[ $((skipper)) != 0 ]]; then
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

		rec=$(egrep -c -e ".*onexsip .*Received.*|.*onexsip .*Got response.*|.*onexsip .*Sending SIP.*|.*onexsip .*Sending response.*" < "$file")

		if [[ $rec == 0 ]];	then
			echo "error: No SIP messages have been found in $file."
			echo "Perhaps this file is not an 1XCES trace.log file"
			rec=$(egrep -c -e ".*CSeq:.*" "$file")
			error=1
			if [[ $rec == 0 ]]; then
				echo "In fact, no sign of any "CSeq:" lines in $file"
				error=2
			else
				echo "Though, found $rec lines with "CSeq:" - so there might be some SIP messages within $file."
				rec=0
			fi
			echo "Verify source and content of $file"
			echo ''; continue
		else
			vsyslog=15

			base64found=0
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
			error=0			
			sipmsg=0
			siptotalmsg=0
			sipmaxlines=0
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

			##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
    	    #conv=$(awk -e '/<I,sip.*INCOMING|<I,sip.*OUTGOING/{flag=1} flag; /}/{flag=0}' $file)
#			conv=$(awk -e '/.*onexsip .*Received .*|.*onexsip .*Sending SIP.*/{flag=1} flag; /}/{flag=0}' "$file")
			conv=$(awk -W source='/.*onexsip .*Received .*|.*onexsip .*Sending SIP.*/{flag=1} flag; /}/{flag=0}' "$file")	

			newfile="$file.asm.tmp"
			if [ -f $newfile ]; then
				rm $newfile
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"

			while IFS= read -r line
			do
				nlines=$((nlines+1))

				if [[ $((dirdefined)) != 0 ]]; then
					if [[ $line == "|Thread"* ]] || [[ $line == "["* ]]; then
						complete_sipmsg
					fi
				fi

				if [[ $((dirdefined)) == 0 ]] && [[ $line == *" onexsip "* ]]; then      # this is a new SIP msg
					siptotalmsg=$((siptotalmsg+1))	

					insidesip=1 
					base64found=0
					sip_direction
					get_sip_datetime
					sipmsg_header

					if [[ $((dirdefined)) == 1 ]]; then
						if [[ $line == *"response"* ]]; then
							line=$(echo "$line" | awk -F' response ' '{print $2}')
						elif [[ $line == *"response:"* ]]; then
							line=$(echo "$line" | awk -F' response: ' '{print $2}')
						elif [[ $line == *"request:"* ]]; then
							line=$(echo "$line" | awk -F' request: ' '{print $2}')										
						elif [[ $line == *"Received NOTIFY:"* ]]; then				
							line=$(echo "$line" | awk -F'Received NOTIFY: ' '{print $2}')
						fi
						start_sipmsg

					elif [[ $((dirdefined)) == 2 ]]; then
						if [[ $line == *"request:"* ]]; then
							line=$(echo "$line" | awk -F' request: ' '{print $2}')
						elif [[ $line == *"request "* ]]; then
							line=$(echo "$line" | awk -F' request ' '{print $2}')
						elif [[ $line == *"response:"* ]]; then
							line=$(echo "$line" | awk -F' response: ' '{print $2}')
						elif [[ $line == *"response "* ]]; then
							line=$(echo "$line" | awk -F' response ' '{print $2}')
						fi
						start_sipmsg
					fi

				elif [[ $((sipstart)) == 1 ]]; then
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
		done <<<"$conv"

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
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done