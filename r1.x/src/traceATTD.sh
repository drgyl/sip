longestmsg=0#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
today=$(date +%m/%d/%Y)
siplength=666
sipstat=1
adjusthour=0
alllogs=0
noINFO=0
base64decode=1
protocol="TLS"
ip="6.6.6.6:6666"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

function usage ()  {
    echo "traceATTD.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceATTD.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either an Attendant.log (from ATTD server) or a ClientSDKlog.txt"
    echo -e "\t\t\tor a cereport.tgz file collected from Breeze server (with Attendant.logs)"		
    echo -e "\t\t\tor a zip file collected by R5.x Workplace ATTD LogReport"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"					
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-A:\t\tconvert all aditional logs in logreport where SIP message found"	
	echo -e "\t-I:\t\tignore all SIP INFO messages (used in sharedcontrol session)"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
    echo ''
	echo -e "  Note:\t\tfor server log, the SIP proxy IP address:port and SIP msg length"
	echo -e "\t\tinserted into converted msg header is showing fake/dummy values"
    echo ''	
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	siplines=$((siplines+1))

# strip off leading ^M from beginning of first SIPline ($line) for Attendant server's SipContainerPool : xx] Attendant FINER
	if [[ $((vsyslog)) == 12 ]]; then
		line=${line:1}							# strip off leading 0d ^M character
#		line=$(echo "$line" | tr -d "\r")		
#		line=$(echo "$line" | sed 's/\^M//g')
	fi

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
	if [[ $((sipstart)) == 1 ]]; then
		sipmsg=$((sipmsg+1))
		dirdefined=0
		if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then	
			sipmaxlines=$siplines
			longestmsg=$sipmsg
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
} # complete_sipmsg ()

function sipmsg_header () {
	if [[ $((dirdefined)) != 0 ]]; then
		n=$((n+1))
		sipstart=0
        if [[ $ip == "127.0.0.2"* ]]; then
			ip1="6.127.0.2:6666"
		fi
		if [[ $((sipstat)) != 0 ]]; then		
			echo -en "$var => $n/$rec Msgs converted           \r"
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
	if [[ $((dirdefined)) == 1 ]] || [[ $line == *"[SIP]:RECEIVED"* ]]; then
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
		
	elif [[ $((dirdefined)) == 2 ]] || [[ $line == *"[SIP]:SENDING"* ]]; then
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
	fi

	if [[ $((vsyslog)) == 12 ]]; then	
#	if [[ $line == *"SipContainerPool"* ]]; then
		ip="6.6.6.6:6666"
		siplength=666
	elif [[ $((vsyslog)) == 13 ]]; then
		ip=$(echo "$line"        | awk '{print $11}')
		siplength=$(echo "$line" | awk '{print $8}')

	elif [[ $((dirdefined)) != 0 ]]; then
 		ip=$(echo "$line"        | cut -d' ' -f20)
		siplength=$(echo "$line" | cut -d' ' -f17)
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
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 12 ]]; then
		sipday=$(echo "$line"   | cut -d' ' -f1)
		sipyear=$(echo $sipday  | cut -d'-' -f1)
		sipmonth=$(echo $sipday | cut -d'-' -f2)
		sipday=$(echo $sipday   | cut -d'-' -f3)  # awk '{printf "%02i",$2}')
				
		sipmsec=$(echo "$line"  | cut -d' ' -f2)
		siphour=$(echo $sipmsec | cut -d':' -f1)
		sipmin=$(echo $sipmsec  | cut -d':' -f2)
		sipsec=$(echo $sipmsec  | cut -d':' -f3)
		sipmsec=$(echo $sipsec  | cut -d',' -f2)
		sipsec=$(echo $sipsec   | cut -d',' -f1)

	elif [[ $((vsyslog)) == 13 ]]; then
		sipday=$(echo "$line"   | cut -d' ' -f1)
		sipyear=$(echo $sipday  | cut -d'-' -f1)
		sipmonth=$(echo $sipday | cut -d'-' -f2)
		sipday=$(echo $sipday   | cut -d'-' -f3)  # awk '{printf "%02i",$2}')
		
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
} # get_sip_datetime ()

function convert_siplog () {
if [[ $file != "" ]]; then
# echo -e "\nConverting $file..."
	rec=$(egrep -c "SipContainerPool : [0-9]{1,2}\] Attendant FINER" "$file") # TODO need better regexp [0-9]{1,2,3,4} ??
	if [[ $rec != 0 ]]; then
		vsyslog=12
	else
		rec=$(egrep -c "] Debug SIP: " "$file") 
		if [[ $rec == 0 ]]; then
			echo "error: No SIP messages have been found in $file"
               error=1
			rec=$(egrep -c -e "^CSeq:.*" "$file")
			if [[ $rec == 0 ]]; then
				echo "In fact, no sign of any "CSeq:" lines in $file"
				error=2
			else
				echo "Though, found $rec lines with "CSeq:" - so there might be some SIP messages within $file"
				rec=0
			fi
			echo "Verify source and content of $file"
			echo ''; continue
		else
			vsyslog=13
		fi
	fi

	if [[ $rec != 0 ]] && [[ $((vsyslog)) != 0 ]]; then
		base64found=0
		base64msg=0
		foundipaddr=""
		useragent=""
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
		sipmaxsplit=0
		sipwordlist=""		
		longestmsg=0
		nlines=0
		n=0
		sipmsg=0

		reset_sipmsg

		if [[ $rec -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo "You may want to execute this script on a more powerful PC or server."
			echo ''
		fi

		if [[ $((vsyslog)) == 12 ]]; then
#        	conv=$(awk -e '/SipContainerPool :*/{flag=1} flag; /}/{flag=0}' "$file")
        	conv=$(awk -W source='/SipContainerPool :*/{flag=1} flag; /}/{flag=0}' "$file")
		elif [[ $((vsyslog)) == 13 ]]; then
#			conv=$(awk -e '/ Debug SIP: /{flag=1} flag; /}/{flag=0}' "$file")
			conv=$(awk -W source='/ Debug SIP: /{flag=1} flag; /}/{flag=0}' "$file")
		fi

		newfile="$file.asm.tmp"
		if [ -f $newfile ]; then 
			rm $newfile
		fi
		echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"
		fi

		while IFS= read -r line
		do
		nlines=$((nlines+1))

		if [[ $((vsyslog)) == 12 ]] && [[ $line == *"[SipContainerPool :"* ]] && [[ $line == *"] Attendant FINER -"* ]]; then
			if [[ $line == *"CallServer.requestReceived"* ]]; then
				dirdefined=1
			elif [[ $line == *"CallServer.responseReceived"* ]]; then
				dirdefined=1
			elif [[ $line == *"CallServer.sendingOut Request"* ]]; then
				dirdefined=2
			elif [[ $line == *"CallServer.sendingOut Response"* ]]; then
				dirdefined=2
			else 
				dirdefined=0
			fi

		elif [[ $((vsyslog)) == 13 ]] && [[ $line == *" Debug SIP: "* ]]; then
			if [[ $line == *"SIP: RECEIVED"* ]]; then
				dirdefined=1
			elif [[ $line == *"SIP: SENDING"* ]]; then
				dirdefined=2
			else
				dirdefined=0
			fi
		fi

		if [[ $((dirdefined)) != 0 ]]; then
			if [[ $((insidesip)) == 0 ]]; then
				sip_direction
				if [[ $((vsyslog)) == 12 ]] && [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
					reset_sipmsg
					continue
				fi
				insidesip=1
				siptotalmsg=$((siptotalmsg+1))
				base64found=0
				get_sip_datetime					
#				sipmsg_header
			elif [[ $((sipstart)) ==  0 ]] && [[ ${#line} -gt 2 ]]; then
				if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then			
					reset_sipmsg
					continue
				else
					sipmsg_header
					start_sipmsg
				fi
			elif [[ ${#line} != 0 ]]; then
				if [[ $((vsyslog)) == 13 ]] && [[ $line == "}" ]]; then
					complete_sipmsg
				elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
					base64found=1
					echo "# Base64 dump found" >> "$newfile"
					if [[ -f $newfile.b64 ]]; then
						rm "$newfile.b64"
					fi
				elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
					echo "$line" >> "$newfile.b64"
				else 
					echo "$line" >> "$newfile"
					siplines=$((siplines+1))
					get_useragent
				fi
			elif [[ $((vsyslog)) == 12 ]] && [[ ${#line} -lt 2 ]]; then
				complete_sipmsg
			fi
		fi
		done <<<"$conv"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi
		
        if [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm file"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $var file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    have been converted for addr=$endptaddr into $output.asm, file"
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
					echo -e "\tBase64 encoded SIP messages: $base64msg"
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
		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd; ls -l "$output.asm"			
		echo ''
	fi
else
	error=6
	echo "convert_siplog() received null string for input"
	echo ''
fi
} # convert_siplog

##################### Execution starts here #########################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbf:sAI" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
    I)
		 noINFO=1;;		
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
	filelist=""
	tmpfile=0
	basefile=""
	input=""
	input2=""
	error=0
	n=0
	vsyslog=0

	if [ -f $file ]; then
		echo -en "Exploring content in $var... stand by\r"

		filetype=$(file -b "$file")
		filecontent="cereport"

		if [[ $filetype == "Zip archive"* ]]; then
			if [[ $file == *"."* ]]; then
				input=$(echo "${file%.*}")					# equal to: input=$(echo "$file" | cut -d'.' -f1)
			else
				input="$file"
			fi
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp"
				if [[ $? != 0 ]]; then
					error=100
					echo "error: could not delete $input.tmp folder. Check if any subfolders or files currently opened."
					exit $error
				fi
			fi

			tmpfile=1
			mkdir "$input.tmp"
			cd "$input.tmp"			
			unzip -qq -v 2>&1 >/dev/null
			if [[ $? == 0 ]]; then
				unzip -qq "../$file" 2>/dev/null
				if [[ $? -gt 1 ]]; then
					tar --version >/dev/null
					if [[ $? == 0 ]]; then
						tar xf "../$file"
						if [[ $? != 0 ]]; then
							error=8
							echo "error: could not uncompress $var, using \"tar\" utility."
							echo ''; continue
						fi
					else
						error=8
						echo "error: could not uncompress $var, using \"unzip\".  Suggest to validate \"unzip\" in your environment."
						echo ''; continue
					fi
				fi
			else
				echo "warning: \"unzip\" package not found - if using Ubuntu, execute \"sudo apt-get unzip install\" and re-try."
				echo ''
				tar --version >/dev/null
				if [[ $? == 0 ]]; then
					tar xf "../$file"
					if [[ $? != 0 ]]; then
						echo ''; error=8
						echo "error: could not uncompress $var, using \"tar\" utility."
						echo "Suggest to validate uncompressing $var in your environment."
						echo ''; continue
					fi
				fi
			fi

			if [ -d "log" ]; then
				filelist=$(ls -c log/A*ClientSDKlog*.log)
				filecontent="ClientSDKlog"

				if [[ $filelist == *"such"* ]]; then
					filelist=$(ls -c "log/Attendant.Log*")
					filecontent="AttendantLog"
				fi
			else
				filelist=$(ls -c "*ClientSDKlog*")
				filecontent="ClientSDKlog"				
				if [[ $filelist == *"such"* ]]; then				
					filelist=$(ls -c "Attendant.log*")
					filecontent="AttendantLog"
					if [[ $filelist == *"such"* ]]; then						# get the first cereport (only)
						filelist=$(ls -c "cereport*.tgz")
						filecontent="cereport"
					fi
				fi
			fi
			if [[ $filelist != *"such"* ]]; then				# no such file or directory
				file=$(echo $filelist | head -1)
				filetype=$(file "$file")				
				file="$input.tmp/$file"
			else
				filelist=""
				filecontent=""
			fi
			cd ..
		fi

		if [[ $filecontent == "cereport" ]] && [[ $filetype == *"compressed data"* ]]; then
			filecontent=$(file -Zb "$file")
			if [[ $filecontent == *"ASCII text"* ]]; then			# there can be a single log file gzipped, eg Attendant.log.gz
				if [[ $file == *"."* ]]; then
					input2=$(echo "${file%.*}")
				else
					input2="$file"
				fi
				if [[ $input != "" ]]; then
					input="$input.tmp/$input2"
				else
					input=$input2
				fi
				gunzip --version >/dev/null
				if [[ $? == 0 ]]; then
					gunzip -q "$file"
					if [[ $? -gt 1 ]]; then					
						error=8
						echo "error: could not uncompress $var->$file, using \"unzip\".  Suggest to validate \"unzip\" in your environment."
						echo ''; continue
					else
						file=$input
					fi
				else
					error=8
					echo "warning: \"unzip\" package not found - if using Ubuntu, execute \"sudo apt-get unzip install\" and re-try."				
					echo ''; continue
				fi
				filecontent="ATTD"
			elif [[ $filecontent == *"tar"* ]]; then				# handling cereport.tgz
				if [[ $file == *"."* ]]; then
#					input=$(echo "$file" | cut -d'.' -f1)
					input2=$(echo "${file%.*}")
				else
					input2="$file"
				fi

				if [[ $input != "" ]]; then
					input="$input.tmp/$input2"
				else
					input="$input2"
				fi
				if [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp"
					if [[ $? != 0 ]]; then
						error=100
						echo "error: could not delete $input.tmp folder. Check if any subfolders or files currently opened."
						exit $error
					fi
				fi
				tmpfile=1
				mkdir "$input.tmp"
				cd "$input.tmp"			
				tar --version >/dev/null
				if [[ $? == 0 ]]; then
					tar zxf "../$file"
					if [[ $? -gt 1 ]]; then
						error=8
						echo "error: could not untar $var->$input->$file, using \"tar zxf\"."
						echo "Suggest to validate \"tar\" in your environment."
						echo ''; continue
					fi					
				else
					gunzip --version >/dev/null
					if [[ $? == 0 ]] ; then
						gunzip -q "../$file" 2>/dev/null	# TODO: can gunzip untar or only uncompress .tgz into .tar?
						if [[ $? -gt 1 ]]; then					
							error=8
							echo "error: could not uncompress $var->$file, using \"unzip\".  Suggest to validate \"unzip\" in your environment."
							echo ''; continue
						fi
					fi
				fi

				if [ -d var/log/Avaya/services/Attendant ]; then
					filelist=$(ls var/log/Avaya/services/Attendant/Attendant.log*)
					filecontent="AttendantLog"
				else
					echo "Warning: could not find any Attendant.log files in $var->$input->var/log/Avaya/services/Attendant folder"
					echo ''; continue
				fi
				cd ..
			fi
		fi

		if [[ $alllogs == 0 ]]; then
			if [[ $filelist != "" ]]; then
				file=$(echo $filelist | awk '{print $1}')		# head -1)
				file="$input.tmp/$file"
			fi
			convert_siplog
		else
			echo "Warning: this may take a while... converting multiple files!"
			echo "You may want to execute this script on a more powerful PC or server."
			echo ''
			for file in $filelist;
			do
				file="$input.tmp/$file"
				convert_siplog
			done
		fi
	else
		echo "error: file $var was not found."
		echo ''; error=3
	fi
done
