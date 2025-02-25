#!/bin/bash
version="1.0.2.1"
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
vsyslog=0
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
# vsyslog=20  ## values explained below:

## 19) AMS sipmsDebug.txt
## 20) AMS sip.txt

function usage ()  {
    echo 'traceAMS.sh v1.0 @ 2022 : converting SIP messages into a format required by traceSM tool'
	echo -e "\t\t\t\t\t\t\t  created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAMS.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either sip.txt or sipmcDebug.txt log file from AAMS/MPaaS Troubleshooting Archive"
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
	if [[ $line =~ INCOMING|Incoming ]]; then
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
	elif [[ $line =~ OUTGOING|Outgoing ]]; then
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
		reset_sipmsg
	fi
	
	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $((vsyslog)) == 20 ]]; then
			protocol=$(echo "$line" | awk '{print $(NF)}')
			ip=$(echo "$line" | cut -d' ' -f4 | cut -d')' -f1 | cut -d'(' -f2)		# 000000000000> INCOMING (10.20.32.81:36143) TCP
		else
			protocol="TLS"
			ip="6.6.6.6:6666"
		fi		
		siplength="666"	
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
# sipua.log:
# Apr-13 05:25:21.674 INFO  [SIP-TCP-Core-PipelineThreadpool-20] SUA3 SipMessageGate  TCP - processing request: : OPTIONS sip:censysinspect@censys.io SIP/2.0 | 
# sip1.txt
# (08-10 20:24:24.609)<I,sip,90983280,00000000-0000-0000-0000-000000000000> INCOMING (10.20.32.81:36143) TCP
	if [[ $((vsyslog)) == 19 ]] || [[ $((vsyslog)) == 20 ]]; then 
##		if [[ $((n)) == 0 ]]; then
##			foundipaddr=$(echo $line | cut -d' ' -f5)
			sipyear=$(echo $today     | cut -d'/' -f3)
			sipday=$(echo "$line"     | cut -d' ' -f1 | cut -d'-' -f2)
			sipmonth=$(echo "$line"   | cut -d' ' -f1 | cut -d'-' -f1 | cut -d'(' -f2)
##		fi

		sipmsec=$(echo "$line"   | cut -d' ' -f2 | cut -d')' -f1) 
		siphour=$(echo $sipmsec  | cut -d':' -f1)
		sipmin=$(echo $sipmsec   | cut -d':' -f2)
		sipsec=$(echo $sipmsec   | cut -d':' -f3 | cut -d'.' -f1)
		sipmsec=$(echo $sipmsec  | cut -d'.' -f2)
	fi

	if [[ $((adjusthour)) == 1 ]]; then
		siphour=$(echo $siphour"=="$tzhour | awk -F '==' '{printf "%02i",$1+$2}')
		sipmin=$(echo $sipmin"=="$tzmin | awk -F '==' '{printf "%02i",$1+$2}') ## TODO need to handle overflow and '-' case
		if [[ $((siphour)) -gt 23 ]]; then
			siphour=$(($((siphour))-24)) 								## TODO need to print 2 digits
		fi
		if [[ $((sipmin)) -gt 59 ]]; then
			sipmin=$(($((sipmin))-60)) 									## TODO need to print 2 digits
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
  while getopts "e:hbf:s" options; do
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
	
	vsyslog=0

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
		skipper=0
		if [[ $((skipper)) == 1 ]]; then
		    voutput=$var
		    if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			    voutput=1
		    fi
		elif [[ $((skipper)) == 2 ]]; then
			endptaddr=$var
        fi
		continue
	fi

	file=$var
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0
	tmpfile=0
	
	if [ -f "$file" ]; then
		echo -en "Exploring content in $var... stand by\r"
		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)

		filetype1=$(file -b "$file")
		filetype2=$(file -bZ "$file")

		if [[ $filetype1 =~ compressed ]] && [[ $filetype2 =~ ASCII ]]; then
			gunzip --version >/dev/null
			if [[ $? == 0 ]]; then
				gunzip -q -c "$file" > "$file.txt"
				tmpfile=1
				file="$file.txt"
			else
				error=8
				echo "error: unable to uncompress $var, using \"gunzip\" utility."
				echo ''; exit $error
			fi
		fi

		rec=$(egrep -c -e "^\([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,sip," "$file")

		if [[ $rec == 0 ]];	then	
			rec=$(egrep -c -e "^\([0-9]{2}\-[0-9]{2} [0-9]{2}.*<I,eng,.*ing SIP Message:.*" "$file")
			if [[ $rec == 0 ]];	then
			    error=1
				echo "error: No SIP messages have been found in $var."
				echo "Perhaps this file is not an AMS sip.txt or sipmcDebug.txt logfile... or, DEBUG was not enabled."
				rec=$(egrep -c -e "^CSeq:*" "$file")
				if [[ $rec == 0 ]]; then
					echo "In fact, no sign of any "CSeq:" lines in $var"
					error=2
				else
					echo "Though, found $rec lines with CSeq: - so there might be some SIP messages included in $var."
					rec=0
				fi
				echo "Verify source and content of $var"
				continue
			else
				vsyslog=19
			fi
		else
			vsyslog=20
		fi

		if [[ $((vsyslog)) != 0 ]] && [[ $((rec)) != 0 ]]; then
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
	
			## conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
    	    ## conv=$(awk -e '/<I,sip.*INCOMING|<I,sip.*OUTGOING/{flag=1} flag; /}/{flag=0}' $file)
			# conv=$(awk -e '/,sip,/{flag=1} flag; /}/{flag=0}' "$file")
			# conv=$(awk -W source='/,sip,/{flag=1} flag; /}/{flag=0}' "$file")			
			newfile="$file.asm.tmp"
			if [ -f "$newfile" ]; then
				rm "$newfile"
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm$NL" >> "$newfile"

			while IFS= read -r line
			do
				linelength=${#line}
				nlines=$((nlines+1))

				if [[ $((vsyslog)) == 20 ]]; then
					if [[ $line == *",sip,"* ]]; then
						if [[ $((sipstart)) != 0 ]]; then # [[ $line =~ $pattern1 ]]; then
						# if [[ $((dirdefined)) == 1 ]] && [[ $line == *",sip,"* ]]; then
							complete_sipmsg
						fi

						if [[ $((dirdefined)) == 0 ]]; then 		# this is a new SIP msg
							sip_direction
							if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
						        reset_sipmsg
								continue
							fi

						insidesip=1 
						siptotalmsg=$((siptotalmsg+1))							
						base64found=0
						get_sip_datetime
						fi
					elif [[ $((dirdefined)) != 0 ]] && [[ $((insidesip)) == 1 ]]; then
						if [[ $((linelength)) == 0 ]]; then
							insidesip=2
						fi
					elif [[ $((linelength)) -gt 1 ]] && [[ $((insidesip)) == 2 ]]; then
							sipmsg_header							
							start_sipmsg
							insidesip=3
					elif [[ $((sipstart)) != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
							base64found=1
							echo "# Base64 dump found" >> $newfile
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

				elif [[ $((vsyslog)) == 19 ]]; then
					if [[ $line =~ \)\<I,eng, ]] && [[ $line == *"ing SIP Message:"* ]]; then
						if [[ $((sipstart)) != 0 ]]; then
							complete_sipmsg
						fi

						if [[ $((dirdefined)) == 0 ]]; then                     # this is a new SIP msg
							sip_direction
							if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
						        reset_sipmsg
								continue
							fi
						fi

						siptotalmsg=$((siptotalmsg+1))
						insidesip=1 
						base64found=0
						get_sip_datetime
						sip_direction							
					elif [[ $((insidesip)) == 1 ]] && [[ $((linelength)) -lt 2 ]]; then
						insidesip=2
					elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -gt 1 ]]; then
						sipmsg_header						
						start_sipmsg
						insidesip=3
					elif [[ $((sipstart)) != 0 ]]; then
						if [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then # TODO: handle content type : gzip
							base64found=1
							echo "# Base64 dump found" >> "$newfile"
							if [[ -f $newfile.b64 ]]; then
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
					fi
				fi
#		done <<< "$conv"
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
		echo -e "\tTask started: $currtime - completed: $(date +%R:%S)"
		echo ''

		if [ -f "$var.asm" ]; then
			mv "$var.asm" "$var.asm.bak"
		fi
		mv "$newfile" "$var.asm"
		if [[ $tmpfile == 1 ]]; then
			rm $file					# this is already a tmp file, can be removed
		fi
		ls -l "$var.asm"
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done