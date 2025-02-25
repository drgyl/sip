#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
pattern2="^\-\-\-.*\-\-\-$"
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

# TODO: handle .zip multiple .log files

function usage ()  {
    echo "traceCC.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t   created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceCC.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the CCMS_SGM_SipMessages.log file from the Contact Center (CC) server"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
    emptyline=0
	dirdefined=0
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	emptyline=0
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
		sipstart=0
		n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$var => $n/$rec Msgs converted            \r"
		fi
		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/TLS/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} # sipmsg_header() 

function sip_direction () {
# 01/08/2022-11:36:14.354 [0x000021ac] - --> Message to Send (Dest Address IP:  10.50.14.2:4165):$$begin_record
# Direction: outgoing
# Start-Line: SIP/2.0 100 Trying
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line == *" <-- "* ]]; then		# Message Received
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

	elif [[ $line == *" --> "* ]]; then		# Message to Send
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

	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $((vsyslog)) == 10 ]]; then
			ip=$(echo "$line" | awk -F"Address IP: " '{print $2}')
			ip1=$(echo $ip | cut -d':' -f1)
			ip2=$(echo $ip | cut -d':' -f2 | cut -d')' -f1)
       		ip="$ip1:$ip2"
		elif [[ $((vsyslog)) == 11 ]]; then
			ip=$(echo "$line" | awk '{print $NF}')			# TODO: strip off ^M
			ip1=$(echo $ip | cut -d':' -f1)
			ip2=$(echo $ip | awk -F":" '{printf "%i",$2}')  # cut -d':' -f2)
			ip="$ip1:$ip2"
		fi
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
# 01/08/2022-11:36:14.360 [0x000021ac] - --> Message to Send (Dest Address IP:  10.50.14.2:4165):$$begin_record
# 24/08/2021-14:04:02.432 --> message sent to 192.168.123.22:5061
	sipday=$(echo "$line"   | cut -d' ' -f1)
	sipmsec=$(echo $sipday  | cut -d'-' -f2)
  	sipday=$(echo $sipday   | cut -d'-' -f1)	
	sipyear=$(echo $sipday  | cut -d'/' -f3)
	sipmonth=$(echo $sipday | cut -d'/' -f2)
	sipday=$(echo $sipday   | cut -d'/' -f1)

	siphour=$(echo $sipmsec | cut -d':' -f1)
	sipmin=$(echo $sipmsec  | cut -d':' -f2)
	sipsec=$(echo $sipmsec  | cut -d':' -f3)
	sipmsec=$(echo $sipsec  | cut -d'.' -f2)
	sipsec=$(echo $sipsec   | cut -d'.' -f1)

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
	e)
		endptaddr=${OPTARG};;
	b)
		base64decode=0;;
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
		echo -e -n "Exploring content in $file... stand by\r"
		rec2=$(egrep -c -e "^CSeq:*" "$file")
		rec=$(egrep -c "^Start-Line:" "$file")

		if [[ $rec == 0 ]] || [[ $rec2 == 0 ]];	then
			echo "error: no SIP messages have been found in $var."
			echo "Perhaps this file is not a CC CCMS_SGM_SipMessages.log file... or, DEBUG was not enabled"
			error=1
#			rec=$(egrep -c -e "^CSeq:.*" $file)
			if [[ $rec2 == 0 ]]; then
				echo "In fact, no sign of any "CSeq:" lines in $var"
				error=2
			else
				echo "Though, found $rec2 lines with "CSeq:" - so there might be some SIP messages in $var."
				rec=0; 	error=2
			fi
			echo "Verify source and content of $var"	
			echo ''; return
		else
			n=$(egrep -m 1 -c "^Direction:" "$file")
#			n=$(egrep -m 1 -c "* Address IP:*" "$file")			
			if [[ $((n)) != 0 ]]; then
				vsyslog=10
			else
				nmsgin=$(egrep -m 1 -c "* <-- [Mm]essage *" "$file")
				nmsgout=$(egrep -m 1 -c "* --> [Mm]essage *" "$file")
				if [[ $((nmsgin)) != 0 ]] || [[ $((nmsgout)) != 0 ]]; then				
#				if [[ $((n)) != 0 ]]; then				
					vsyslog=11
				else
					echo 'error: could not find any "message sent/received" lines in' $var
#					echo 'error: could not find any "Address IP:" lines in' $var
				fi
			fi
		fi

		if [[ $((vsyslog)) != 0 ]]; then
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			nlines=0
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
			longestmsg=0
			sipin=0
			sipout=0

			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo "You may want to execute this script on a more powerful PC or server."
				echo ''
			fi

			newfile="$file.asm.tmp"
			if [ -f $newfile ]; then
				rm $newfile
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"

#			conv=$(awk -e '/CHAP_SIP_Message/{flag=1} flag; /}/{flag=0}' "$file")
#			conv=$(awk -W source='/--> [Mm]essage|<-- [Mm]essage/{flag=1} flag; /}/{flag=0}' "$file")
			if [[ $((vsyslog)) == 10 ]]; then
				conv=$(awk -W source='/begin_record/{flag=1} flag; /}/{flag=0}' "$file")
			elif [[ $((vsyslog)) == 11 ]]; then
				conv=$(awk -W source='/essage sent|essage received/{flag=1} flag; /}/{flag=0}' "$file")
			fi				

			while IFS= read -r line
			do
				linelength=${#line}
				nlines=$((nlines+1))

#			    if [[ $line == *"begin_record"* ]]; then
				if [[ $line =~ \-\-\>\ [Mm]essage|\<\-\-\ [Mm]essage ]]; then
				    if [[ $((sipstart)) != 0 ]]; then
				    	complete_sipmsg
				    fi
					if [[ $((vsyslog)) == 11 ]]; then	# there is no ^Direction line
						insidesip=2
					else
						insidesip=1
					fi
					base64found=0
					sip_direction
			 		get_sip_datetime
					siptotalmsg=$((siptotalmsg+1))						 
					sipmsg_header					
				elif [[ $((insidesip)) != 0 ]] && [[ $((sipstart)) == 0 ]] && [[ $line =~ ^Direction: ]]; then
				    if [[ $((dirdefined)) == 1 ]] && [[ $line == *"incoming"* ]]; then
						insidesip=2
					elif [[ $((dirdefined)) == 2 ]] && [[ $line == *"outgoing"* ]]; then
						insidesip=2
					else
						reset_sipmsg
						continue
					fi
			    elif [[ $((insidesip)) == 2 ]] && [[ $line =~ ^Start-Line: ]]; then
					if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
						reset_sipmsg
					else
						line=$(echo "$line" | awk -F"Start-Line: " '{print $2}')					
						start_sipmsg
					fi
				elif [[ $((sipstart)) == 1 ]]; then
                    if [[ $line == *"end_record"* ]]; then
					   complete_sipmsg
					elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
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
#		rm $file					# this is already a tmp file, can be removed
		pwd;ls -l "$var.asm"
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done