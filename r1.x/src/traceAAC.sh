#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
# echo ''
today=$(date +%m/%d/%Y)
pattern1='.*MX Sigtrace.*'
pattern2=""
# pattern2='^FINE.*% $'
# pattern3='^% '
# pattern4='^INFO|^FINE|^FINER|^FINEST'
sipstat=1
adjusthour=0
base64decode=1
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
# vsyslog=7 

## 5) AAC SIP Message Trace : sipmcDebug
## 6) AAC SIP Message Trace : sip.txt
## 7) AAC SIP Message Trace : AACtraceForWin.log

# TODO: AAC logreport/logarchive  .zip : logs/log/sipmcDebug.txt[.X.bak] or sip*.txt[.X.bak]

function usage ()  {
    echo "traceAAC.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t    created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAAC.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either trace_XXXX.log, or sip.txt or sipmcdebug.txt file from an AAC server logarchive"
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
	dirdefined=0
	sipstart=0
	siplines=0
	emptyline=0
	sipyear=""
	ip=""
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
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} # sipmsg_header() 

function sip_direction () {
# (03-14 18:08:29.552)<I,sip,33319792,00000000-0000-0000-0000-000000000000> INCOMING (10.16.172.186:50806) TLS
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $((vsyslog)) == 6 ]]; then
		if [[ $line == *" INCOMING "* ]]; then
		## if [[ $direction == "Inbound" ]]; then
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
			##ip=$(echo $line | awk '{print $5}')
		elif [[ $line == *" OUTGOING "* ]]; then
			## elif [[ $direction == 'Outbound' ]]; then
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
		##ip=$(echo $line | awk '{print $5}')
		else
			insidesip=0
			dirdefined=0
		fi

		protocol=$(echo "$line" | awk '{print $(NF)}')
		ip=$(echo "$line" | cut -d' ' -f4 | cut -d')' -f1 | cut -d'(' -f2)		# 000000000000> INCOMING (10.20.32.81:36143) TCP
#		ip=$(echo "$line" | awk '{print $(NF-1)}')
#		ip1=$(echo $ip | cut -d '(' -f2 | cut -d':' -f1)
#		ip2=$(echo $ip | cut -d':' -f2 | cut -d')' -f1)
#		ip="$ip1:$ip2"

# (03-14 18:08:29.552)<I,eng,33319792,5d2ca2ad-4994-3046-891f-b3ed1ba047a4> ENG[002:A] <idle> Incoming SIP Message: OPTIONS sip:resource_query@10.16.172.183:5063
# Tue, October 31, 2017 13:11:02.495 : 1509430262495
# SIP Message Trace : Incoming

	elif [[ $((vsyslog)) == 5 ]] || [[ $((vsyslog)) == 7 ]]; then
		if [[ $line == *" Incoming"* ]]; then
			## if [[ $direction == "Inbound" ]]; then
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
			##ip=$(echo $line | awk '{print $5}')
		elif [[ $line == *" Outgoing"* ]]; then
			## elif [[ $direction == 'Outbound' ]]; then
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
			##ip=$(echo $line | awk '{print $5}')
		else
			insidesip=0
			dirdefined=0
		fi
	fi
	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $((vsyslog)) == 5 ]] || [[ $((vsyslog)) == 7 ]]; then
			protocol=TLS
			ip="6.6.6.6:6666"
		elif [[ $((vsyslog)) == 6 ]]; then
			protocol=$(echo "$line" | awk '{print $(NF)}')
			ip=$(echo "$line" | cut -d' ' -f4 | cut -d')' -f1 | cut -d'(' -f2)		# 000000000000> INCOMING (10.20.32.81:36143) TCP
		fi
		siplength="666"	
	fi
fi
} # sip_direction()

function get_sipmonth () {
  sipmonth="666"  
  case $month in
  "Jan"|"January") sipmonth="01";;
  "Feb"|"February") sipmonth="02";;
  "Mar"|"March") sipmonth="03";;
  "Apr"|"April") sipmonth="04";;
  "May") sipmonth="05";;
  "Jun"|"June") sipmonth="06";;
  "Jul"|"July") sipmonth="07";;
  "Aug"|"August") sipmonth="08";;
  "Sep"|"September") sipmonth="09";;
  "Oct"|"October") sipmonth="10";;
  "Nov"|"November") sipmonth="11";;
  "Dec"|"December") sipmonth="12";;
  esac	
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			if [[ $line =~ "Conferencing" ]] || [[ $line =~ "Media" ]]; then
				useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
			else
				useragent=""
			fi
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 6 ]] || [[ $((vsyslog)) == 5 ]]; then 
		sipyear=$(echo "$line"   | cut -d' ' -f1)
		sipmonth=$(echo $sipyear | cut -d'(' -f2 | cut -d'-' -f1)
		sipday=$(echo $sipyear   | cut -d'-' -f2)
		sipyear=$(echo $today    | cut -d'/' -f3)

		sipmsec=$(echo "$line"   | cut -d')' -f1 | cut -d' ' -f2) 
	
	elif [[ $((vsyslog)) == 7 ]]; then 
##		if [[ $((n)) == 0 ]]; then
##			foundipaddr=$(echo $line | cut -d' ' -f5)
			sipyear=$(echo "$prevline" | cut -d' ' -f4) # Tue, October 31, 2017 13:11:02.495 : 1509430262495
			month=$(echo "$prevline"   | cut -d' ' -f2)
			sipday=$(echo "$prevline"  | cut -d' ' -f3 | cut -d',' -f1)
			get_sipmonth

# echo "DATETIME:" "$prevline" "y=$sipyear sipm=$sipmonth mo=$month sipd=$sipday sipdate=$sipdate VEGE"

##		fi

####		siphour=$(echo $line | cut -d' ' -f3)
####		sipmin=$(echo $siphour | cut -d ':' -f2) # awk -F ':' '{print $2}')
####		sipsec=$(echo $siphour | cut -d ':' -f3) # awk -F ':' '{print $3}')
####		siphour=$(echo $siphour |cut -d ':' -f1) # awk -F ':' '{print $1}')
		sipmsec=$(echo "$prevline"| cut -d' ' -f5) 

		# siptime=$(echo $line | awk '{print $3":"$8}')  ## msec included in $8
####		siptmp=$(echo $line | awk '{print $6}')
####		tzhour=$(echo $siptmp |cut -d':' -f 1) # awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
####		tzmin=$(echo $siptmp | cut -d':' -f 2) # awk -F ':' '{print $2}')	
	fi

	siphour=$(echo $sipmsec | cut -d':' -f1)
	sipmin=$(echo $sipmsec  | cut -d':' -f2)
	sipsec=$(echo $sipmsec  | cut -d':' -f3)
	sipmsec=$(echo $sipsec  | cut -d'.' -f2)
	sipsec=$(echo $sipsec   | cut -d'.' -f1)

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
  while getopts "e:hbf:sv" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	e)
		endptaddr=${OPTARG};;
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 5 ]] || [[ $((vsyslog)) -gt 7 ]]; then
			vsyslog=7
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

		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -c -e "^SIP Message Trace :.*" "$file")

		if [[ $rec == 0 ]];	then
			# rec=$(egrep -c -e "^\([0-9]{2}\-[0-9]{2} [0-9]{2}.*<I,sip,.*" < "$file")
			error=1
			rec=$(egrep -c -e "^\([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,sip," "$file")
			if [[ $rec == 0 ]]; then
				error=1
				# rec=$(egrep -c -e "^\([0-9]{2}\-[0-9]{2} [0-9]{2}.*<I,eng,.*ing SIP Message:.*" <$file)
				rec=$(egrep -c -e "^\([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,eng,.*ing SIP Message:.*" "$file")
				if [[ $rec == 0 ]]; then 
					echo "error: No SIP messages have been found in $var. Perhaps this file is not an AAC logfile..."
					rec=$(egrep -c -e "^CSeq:.*" "$file")
					error=2
					if [[ $rec == 0 ]]; then
						echo "In fact, no sign of any "CSeq:" lines in $var"
					else
						echo "Though, found $rec lines with "CSeq:" - so there might be some SIP messages included in $var."
						rec=0
					fi
					echo "Verify source and content of $var";
					echo ''; continue
				else
					vsyslog=5
				fi
			else
				vsyslog=6
			fi
		else
			vsyslog=7
		fi

		if [[ $((vsyslog)) != 0 ]] && [[ $rec != 0 ]]; then
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			prevline=""
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
			sipmaxpart=0
		    sipwordlist=""									
			longestmsg=0
			sipin=0
			sipout=0
			timestamp=""
	
			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo "You may want to execute this script on a more powerful PC or server."
				echo ''
			fi

			#conv=$(awk -e '/,sip,/{flag=1} flag; /}/{flag=0}' $file)
			#conv=$(awk -W source='/,sip,/{flag=1} flag; /}/{flag=0}' $file)			
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
				linelength=${#line}
				nlines=$((nlines+1))

				if [[ $((vsyslog)) == 7 ]]; then
					if [[ $((sipstart)) != 0 ]]; then
				 		if [[ $((linelength)) == 1 ]]; then
							emptyline=$((emptyline+1))
							if [[ $((emptyline)) == 2 ]]; then
								echo '' >> "$newfile"
								complete_sipmsg
							fi
						elif [[ $line =~ $timestamp ]]; then
							complete_sipmsg
						else
							emptyline=0
						fi
					fi

					if [[ $((dirdefined)) == 0 ]] && [[ $line == *"SIP Message Trace :"* ]]; then
						ip=""
						sip_direction
						siptotalmsg=$((siptotalmsg+1))	
						insidesip=1					 # this is a new SIP msg candidate
						base64found=0
						get_sip_datetime			 # based on $prevline			

						if [[ $timestamp == "" ]]; then
							timestamp=$(echo "$prevline" | awk '{print $1,$2,$3,$4}')
						fi

					elif [[ $((dirdefined)) != 0 ]] && [[ $line == *"Transaction:"* ]]; then
						prevline=$line
						ip=""
						continue
					elif [[ $((dirdefined)) != 0 ]] && [[ $line == *"SIP_CB "* ]]; then
						prevline=$line
						ip=""	
						continue
					elif [[ $((dirdefined)) != 0 ]] && [[ $line == *"IPDest: "* ]]; then # sed strips off ^M
						line=$(echo "$line" | sed 's/.*[[:blank:]]//g')
#						line=$(echo "$line" | sed 's/.*\^M$//g')
						protocol=$(echo "$line" | cut -d' ' -f2)
						ip1=$(echo $protocol    | cut -d':' -f2)
						ip2=$(echo $protocol    | awk -F':' '{printf "%i",$3}') # because of final ^M
#						ip2=$(echo $protocol| cut -d':' -f3)
						ip="$ip1:$ip2"
#						ip=$(echo $protocol | awk -F':' '{print $2":"$3}')
						protocol=$(echo $protocol | cut -d':' -f1)
						if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
							reset_sipmsg
						else
							sipmsg_header
						fi
					elif [[ $((sipstart)) == 0 ]] && [[ $ip != "" ]]; then
						start_sipmsg
					elif [[ $((sipstart)) != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then # TODO: handle content type : gzip
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
				elif [[ $((vsyslog)) == 6 ]]; then
					if [[ $line == *")<I,sip,"* ]]; then
						if [[ $((sipstart)) != 0 ]]; then
							complete_sipmsg
						fi

						siptotalmsg=$((siptotalmsg+1))	
						insidesip=1                                                       # this is a new SIP msg
						base64found=0
						get_sip_datetime
						sip_direction							
					
					elif [[ $((insidesip)) != 0 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -lt 2 ]]; then
						if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
							reset_sipmsg
						else						
							insidesip=2
							sipmsg_header
						fi
					elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -gt 1 ]]; then
						start_sipmsg
					elif [[ $((sipstart)) != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then # TODO: handle content type : gzip
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
				elif [[ $((vsyslog)) == 5 ]]; then

					if [[ $line == *")<I,eng,"* ]] && [[ $line == *"ing SIP Message:"* ]]; then
						if [[ $((sipstart)) != 0 ]]; then
							complete_sipmsg
						fi

						siptotalmsg=$((siptotalmsg+1))	
						insidesip=1                                                            # this is a new SIP msg
						base64found=0
						get_sip_datetime
						sip_direction							

					elif [[ $((insidesip)) != 0 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -lt 2 ]]; then
						insidesip=2
						sipmsg_header
					elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -gt 1 ]]; then
						start_sipmsg
					elif [[ $((sipstart)) != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then # TODO: handle content type : gzip
							base64found=1
							echo "# Base64 dump found" >> "$newfile"
							if [[ -f "$newfile.b64" ]]; then
								rm "$newfile.b64"
							fi
						elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
							echo "$line" >> "$newfile.b64"
						elif [[ $((linelength)) -lt 3 ]]; then
							emptyline=$((emptyline+1))
							if [[ $((emptyline)) == 3 ]]; then
								echo '' >> "$newfile"
								complete_sipmsg
							fi
						else
							if [[ $((emptyline)) != 0 ]]; then
								emptyline=0
								echo '' >> "$newfile"
							fi
							echo "$line" >> "$newfile"
							siplines=$((siplines+1))
							get_useragent
						fi
					else
						insidesip=0
						sipstart=0						
					fi
				fi
			prevline=$line	
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
					echo "    has been converted for addr=$endptaddr into $var.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				echo -e "\n\tUser-Agent: $useragent"
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

		## echo 'Note: due to SIP msg split into multiple parts [Part 0X of 0N], do not expect presenting 100% msgs converted.'
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
		pwd; ls -l "$var.asm"
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3	
fi
done