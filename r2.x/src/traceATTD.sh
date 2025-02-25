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
siplength=666
sipstat=1
adjusthour=0
converted=0
alllogs=0
noINFO=0
bCAT=0
findANI=""
bDelTemp=1
fixSYSLOG=0
base64decode=1
protocol="TLS"
ip="6.6.6.6:6666"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

function usage ()  {
    echo "traceATTD.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
	echo 'Usage: traceATTD.sh <options> [<LOG_FILE> | <folder>, ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either an Attendant.log (from ATTD server) or a ClientSDKlog.txt"
    echo -e "\t\t\tor a cereport.tgz file collected from Breeze server (with Attendant.logs)"		
    echo -e "\t\t\tor a zip file collected by R5.x Workplace ATTD LogReport"
	echo -e "\t<folder>\tincludes either of the above files, or it could be even any of the local"
	echo -e "\t\t\t\"Local/Avaya\", \"Avaya/Avaya Workplace Attendant\", \"Avaya Workplace Attendant/logs\","
	echo -e "\t\t\t\"Avaya/logs\", \"../logs\" or \"/var/log/Avaya/services/Attendant\" directories."
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"					
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport where SIP message found"	
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converted multiple logfiles)"		
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session, or DTMF)"
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
    echo ''
	echo -e "  Note:\t\t\tfor server log, the SIP proxy IP address:port and SIP msg length"
	echo -e "\t\t\t(inserted into converted msg header) is showing fake/dummy values."
#    echo ''	
} # usage()

function reset_sipmsg () {
	ip=""
	sipyear=""
	sipdate=""	
	siptime=""	
	insidesip=0
	sipstart=0
	siplines=0
	dirdefined=0
	base64found=0
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1;	siplines=$((siplines+1))

# strip off leading ^M from beginning of first SIPline ($line) for Attendant server's SipContainerPool : xx] Attendant FINER
	if [[ $((vsyslog)) == 12 ]]; then
		line=${line:1}							# strip off leading 0d ^M character
#		line=$(echo "$line" | tr -d "\r")		
#		line=$(echo "$line" | sed 's/\^M//g')
	fi

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
if [[ $((sipstart)) == 1 ]]; then
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
		rm "$newfile.b64" 2>/dev/null
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
} # complete_sipmsg ()

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
        if [[ $ip == "127.0.0.2"* ]]; then
			ip1="6.127.0.2:6666"
		fi
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted            \r"
			else
				echo -en "$var => $n/$rec Msgs converted            \r"
			fi
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
	if [[ $((dirdefined)) == 1 ]] || [[ $line == *"[SIP]:RECEIVED"* ]]; then
		sipstream=5f70;				dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	dirstring1="-->";		dirstring2="ingress";;
		esac		
	elif [[ $((dirdefined)) == 2 ]] || [[ $line == *"[SIP]:SENDING"* ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	fi

	if [[ $((vsyslog)) == 12 ]]; then	
		ip="6.6.6.6:6666"
		siplength=666

	elif [[ $((vsyslog)) == 13 ]]; then
		ip=$(awk -F"Debug SIP: " '{print $2}' <<< "$line")
		siplength=$(cut -d' ' -f2 <<< "$ip")
		ip=$(cut -d' ' -f5 <<< "$ip")

	elif [[ $((dirdefined)) != 0 ]]; then
 		ip=$(cut -d' ' -f20 <<< "$line")
		siplength=$(cut -d' ' -f17 <<< "$line")
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
		echo $line; echo ''; exit 1
	fi
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	if [[ $((vsyslog)) == 12 ]]; then
		sipday=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d'-' -f1 <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
		sipday=$(cut -d'-' -f3 <<< "$sipday")  # awk '{printf "%02i",$2}')
				
		sipmsec=$(cut -d' ' -f2 <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d',' -f2 <<< "$sipsec")
		sipsec=$(cut -d',' -f1 <<< "$sipsec")

	elif [[ $((vsyslog)) == 13 ]]; then
		sipday=$(cut -d' ' -f1 <<< "$line")
		sipyear=$(cut -d'-' -f1 <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
		sipday=$(cut -d'-' -f3 <<< "$sipday")  # awk '{printf "%02i",$2}')
		
		sipmsec=$(cut -d' ' -f2 <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")
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
} # get_sip_datetime ()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
# echo -e "\nConverting $file..."

	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile="$file"
	fi

#	echo "                                                                                                                                                  "

	fsize=$(wc -c < "$file" 2>/dev/null)
	if [[ $((fsize)) -gt 0 ]]; then
		rec=$(egrep -c "SipContainerPool : [0-9]{1,2}\] Attendant FINER" "$file") # TODO need better regexp [0-9]{1,2,3,4} ??
		rec2=$(egrep -c "CSeq:*" "$file")
	fi

	if [[ $((rec)) != 0 ]]; then
		vsyslog=12
	else
		rec=$(egrep -c "] Debug SIP: " "$file") 
		if [[ $((rec)) == 0 ]]; then
            error=1
			echo -e "\nerror: No SIP messages have been found in $basefile in the expected format."
			if [[ $((rec2)) == 0 ]]; then
				error=2
				echo 'In fact, no sign of any "CSeq:" lines within' $basefile
				echo -e "Perhaps logging level configured was lower than DEBUG?\n"
				loglevel=$(egrep SetLogLevel "$file")
				if [[ $loglevel != "" ]]; then
					echo $loglevel
				fi
			elif [[ $var != $file ]]; then
				echo "Though found a line including \"CSeq:\" - so there might be some SIP messages within $var -> $basefile."
			else
				echo "Though found a line including \"CSeq:\" - so there might be some SIP messages within $var."
			fi
		if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
				footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
				if [[ $footprint == 1 ]]; then
					echo "Actually, $basefile appears to be an .asm file created by SIPlog2traceSM tool."
				fi
			elif [[ $var != $file ]]; then
				echo -e "Verify source and content of $bvar -> $basefile.\n"
			else
				echo -e "Verify source and content of $bvar.\n"
			fi
		else
			vsyslog=13
		fi
	fi

	if [[ $((rec)) != 0 ]] && [[ $((vsyslog)) != 0 ]]; then
		logsec=$SECONDS
		base64msg=0
		foundipaddr=""
		useragent=""
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
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
		nlines=0
		nINFO=0
		n=0
		sipmsg=0
		sipin=0
		sipout=0

		reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then 
			echo -e "\nWarning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo -e "You may want to execute this script on a more powerful PC or server.\n"
		fi

		if [[ $((vsyslog)) == 12 ]]; then
#        	conv=$(awk -e '/SipContainerPool :*/{flag=1} flag; /}/{flag=0}' "$file")
        	conv=$(awk -W source='/SipContainerPool :*/{flag=1} flag; /}/{flag=0}' "$file")
		elif [[ $((vsyslog)) == 13 ]]; then
#			conv=$(awk -e '/ Debug SIP: /{flag=1} flag; /}/{flag=0}' "$file")
			conv=$(awk -W source='/ Debug SIP: /{flag=1} flag; /}/{flag=0}' "$file")
		fi

		bakfile=""; output=""; 	bfile=""

		if [[ $basefile != "" ]] && [[ $basefile == *"."* ]]; then
			bfile=${basefile%.*}
		fi

		if [[ $var != $basefile ]] && [[ $basefile != $file ]]; then
			xfile=${bvar%%.*}
			if [[ $bvar == $basefile ]]; then
				output=$bvar
			elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
				output="$xfile-$basefile"
			else
				output=$bvar
			fi
		else
			output=$basefile
		fi

		if [[ $output != "" ]]; then
			newfile="$output.asm.tmp"
			bakfile=$output
		elif [[ $file != "" ]]; then
			newfile="$file.asm.tmp"
			bakfile="$file"
		fi

		if [ -f "$newfile" ]; then
			mv "$newfile" "$bakfile.asm.bak"
		fi

		echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
		echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
		echo "# Command line: $args" >> "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
		echo "# Input: $var" >> "$newfile"		

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $output.asm\n" >> "$newfile"
		fi

		while IFS= read -r line
		do
			nlines=$((nlines+1))

			if [[ $((vsyslog)) == 12 ]] && [[ $line == *"[SipContainerPool :"* ]]; then
				if [[ $((sipstart)) != 0 ]]; then
					complete_sipmsg
				fi
			
				if [[ $line == *"] Attendant FINER -"* ]]; then
					if [[ $line == *"CallServer.requestReceived"* ]]; then
						dirdefined=1
					elif [[ $line == *"CallServer.responseReceived"* ]]; then
						dirdefined=1
					elif [[ $line == *"CallServer.sendingOut Request"* ]]; then
						dirdefined=2
					elif [[ $line == *"CallServer.sendingOut Response"* ]]; then
						dirdefined=2
					elif [[ $((insidesip)) == 0 ]]; then
						dirdefined=0
					fi
				fi

			elif [[ $((vsyslog)) == 13 ]] && [[ $line == *" Debug SIP: "* ]]; then
				if [[ $((sipstart)) != 0 ]]; then
					complete_sipmsg
				fi

				if [[ $line == *"SIP: RECEIVED"* ]]; then
					dirdefined=1
				elif [[ $line == *"SIP: SENDING"* ]]; then
						dirdefined=2
				elif [[ $((insidesip)) == 0 ]]; then
					dirdefined=0
				fi
			fi

			if [[ $((dirdefined)) != 0 ]]; then
				if [[ $((insidesip)) == 0 ]]; then
					sip_direction
					if [[ $((vsyslog)) == 13 ]] && [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
						reset_sipmsg
						continue
					fi
					insidesip=1
					siptotalmsg=$((siptotalmsg+1))
					get_sip_datetime					

				elif [[ $((sipstart)) ==  0 ]] && [[ ${#line} -gt 2 ]]; then
					if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
						nINFO=$((nINFO+1))			
						reset_sipmsg
						continue
					else
						sipmsg_header
						start_sipmsg
					fi
				elif [[ $((sipstart)) != 0 ]] && [[ ${#line} != 0 ]]; then
					if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
						if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
							calltime=$siptime
						elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
							callID=$line; callDIR=$dirdefined
						fi
					fi
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
				elif [[ $((vsyslog)) == 12 ]] && [[ $((sipstart)) != 0 ]] && [[ ${#line} -lt 2 ]]; then
					complete_sipmsg
				fi
			fi
		done <<< "$conv"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi
		
		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error\n\n"

        elif [[ $((sipstat)) != 0 ]]; then
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

			echo -e "\tTotal # of lines digested:\t\t\t $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
				if [[ $((nINFO)) != 0 ]]; then
					echo -e "\tINFO messages ignored:\t\t\t\t $nINFO"
				fi
				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages: $base64msg"
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
						echo -e "\tLast  msg:\t$lastmsg\t\t\t $timelast"
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

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
		fi
		
		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.2f "$(($((n)) * 100 / $tmpsec))e-2")
			echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: $avgmsg\t Time spent: $SECONDS sec\n"
		else
			echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t Time spent: $SECONDS sec\n"
		fi
		currtime=$(date +%R:%S)	
		
		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak" 2>/dev/null
		fi
		mv "$newfile" "$output.asm"
		pwd; ls -l "$output.asm"			
		echo ''

		if [[ $((error)) == 0 ]] && [[ $((bCAT)) != 0 ]] && [[ $((n)) != 0 ]]; then
			echo -e "\n# ///////////////////////////////////////////////////////////////////////////////////////" >> "$ctarget"
			echo -e "# CAT $basefile into $ctarget" >> "$ctarget"
			echo -e "# ///////////////////////////////////////////////////////////////////////////////////////\n" >> "$ctarget"			
			cat "$output.asm" >> "$ctarget"
			echo "Converted $basefile into $output.asm, and concatenated it into $ctarget."
			echo ''; ls -l "$ctarget"				
			echo ''
		fi
	fi

elif [[ $file != "" ]]; then
		echo -e "\nerror: $file was not found in the current folder: $PWD\n"
		error=9
else
	echo -e "\nerror: convert_siplog() received null string for input. Contact developer.\n"
	error=6
fi
} # convert_siplog()

function explore_logfolder() {
	targetfiles=""

	targetX=""; targetX=`ls -r -t1 AvayaWorkplaceAttendant_ClientSDKlog_* 2>/dev/null`
	if [[ $? != 0 ]]; then
		targetX=`ls -r -t1 AvayaEquinoxAttendant_ClientSDKlog_* 2>/dev/null`
	fi

	if [[ $targetX != "" ]]; then
		targetfiles=$targetX
	fi

	targetX=""; targetX=`ls -t1 Attendant.log.10 2>/dev/null`
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then		
			targetfiles="$targetX $targetfiles"
		else
			targetfiles=$targetX
		fi		
	fi

	targetX=""; targetX=`ls -r -t1 Attendant.log.? 2>/dev/null`
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then		
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi		
	fi

	targetX=""; targetX=`ls -t1 Attendant.log 2>/dev/null`
	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $targetfiles != "" ]]; then		
			targetfiles="$targetfiles $targetX"
		else
			targetfiles=$targetX
		fi		
	fi	

	if [[ $((alllogs)) == 0 ]]; then
		if [[ "$targetfiles" != "" ]]; then
			targetfiles=$(tail -1 <<< $targetfiles)
		else
			targetfiles=$targetX
		fi
	fi

	xfile=""; file=""; filelist=""
	for xfile in $targetfiles
	do
		if [ -s "$xfile" ]; then
			if [[ $file == "" ]]; then					
				file="$destdir/$xfile"
			fi
			if [[ $((alllogs)) != 0 ]]; then
				if [[ "$filelist" == "" ]]; then
					filelist="=$destdir/$xfile"
				else
					filelist="$filelist=$destdir/$xfile"
				fi
			fi
		fi
	done
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
	fi

	if [ -d "Avaya" ]; then														# typical usecase: %APPDATA% local/roaming folder
		destdir="$destdir/Avaya"
		target="$target-Avaya"
		cd "Avaya"
	fi

	if [ -d "logs" ] || [ -d "log" ] || [ -d "Avaya Workplace Attendant" ] || [ -d "Avaya Equinox Attendant" ]; then
		if [ -d "Avaya Workplace Attendant" ]; then
			destdir="$destdir/Avaya Workplace Attendant"
			target="$target-AvayaWorkplaceAttendant"
			cd "Avaya Workplace Attendant"
		elif [ -d "Avaya Equinox Attendant" ]; then
			destdir="$destdir/Avaya Equinox Attendant"
			target="$target-AvayaEquinoxAttendant"
			cd "Avaya Equinox Attendant"
		fi
		if [ -d "logs" ]; then
			destdir="$destdir/logs"
			target="$target-logs"
			cd "logs"
		elif [ -d "log" ]; then
			destdir="$destdir/log"
			target="$target-log"
			cd "log"
		fi

	elif [ -d "var/log/Avaya/services/Attendant" ]; then
		if [ -d "var/log/Avaya/sm" ]; then
			let asmfiles=0
			asmfiles=$(ls var/log/Avaya/sm/asm* 2>/dev/null | wc -l)
			if [[ $((asmfiles)) != 0 ]]; then
				echo "NOTE: found $asmfiles asm files at \"var/log/Avaya/sm\" folder."
				echo "These files can be decoded using traceBREEZE.sh script."
			fi
		fi
		if [ -d "var/log/Avaya/services/DeviceAdapter" ]; then
			let adafiles=0
			adafiles=$(ls var/log/Avaya/services/DeviceAdapter/dsa* 2>/dev/null | wc -l)
			if [[ $((adafiles)) != 0 ]]; then
				echo "NOTE: found $adafiles dsa.log files at \"var/log/Avaya/services/DeviceAdapter\" folder."
				echo "These files can be decoded using traceADA.sh script."
			fi
		fi

		destdir="$destdir/var/log/Avaya/services/Attendant"
		target="$target-ce-Attendant"
		cd "var/log/Avaya/services/Attendant"
		
	elif [ -d "log/Avaya/services/Attendant" ]; then
		if [ -d "log/Avaya/sm" ]; then
			let asmfiles=0
			asmfiles=$(ls log/Avaya/sm/asm* 2>/dev/null | wc -l)
			if [[ $((asmfiles)) != 0 ]]; then
				echo "NOTE: found $asmfiles asm files at \"log/Avaya/sm\" folder"
				echo "These files can be decoded using traceBREEZE.sh script."
			fi
		fi
		if [ -d "log/Avaya/services/DeviceAdapter" ]; then
			let adafiles=0
			adafiles=$(ls log/Avaya/services/DeviceAdapter/dsa* 2>/dev/null | wc -l)
			if [[ $((adafiles)) != 0 ]]; then
				echo "NOTE: found $adafiles dsa.log files at \"log/Avaya/services/DeviceAdapter\" folder."
				echo "These files can be decoded using traceADA.sh script."
			fi
		fi

		destdir="$destdir/log/Avaya/services/Attendant"
		target="$target-ce-Attendant"
		cd "log/Avaya/services/Attendant"

	elif [ -d "Avaya/services/Attendant" ]; then
		if [ -d "Avaya/sm" ]; then
			let asmfiles=0
			asmfiles=$(ls Avaya/sm/asm* 2>/dev/null | wc -l)
			if [[ $((asmfiles)) != 0 ]]; then
				echo "NOTE: found $asmfiles asm files at \"Avaya/sm\" folder."
				echo "These files can be decoded using traceBREEZE.sh script."
			fi
		fi
		if [ -d "Avaya/services/DeviceAdapter" ]; then
			let adafiles=0
			adafiles=$(ls Avaya/services/DeviceAdapter/dsa* 2>/dev/null | wc -l)
			if [[ $((adafiles)) != 0 ]]; then
				echo "NOTE: found $adafiles dsa.log files at \"Avaya/services/DeviceAdapter\" folder."
				echo "These files can be decoded using traceADA.sh script."
			fi
		fi

		destdir="$destdir/Avaya/services/Attendant"
		target="$target-ce-Attendant"
		cd "Avaya/services/Attendant"

	elif [ -d "services/Attendant" ]; then
		if [ -d "sm" ]; then
			let asmfiles=0
			asmfiles=$(ls sm/asm* 2>/dev/null | wc -l)
			if [[ $((asmfiles)) != 0 ]]; then
				echo "NOTE: found $asmfiles asm files at \"sm\" folder - these files can be decoded using traceBREEZE.sh script."
			fi
		fi
		if [ -d "services/DeviceAdapter" ]; then
			let adafiles=0
			adafiles=$(ls services/DeviceAdapter/dsa* 2>/dev/null | wc -l)
			if [[ $((adafiles)) != 0 ]]; then
				echo "NOTE: found $adafiles dsa.log files at \"services/DeviceAdapter\" folder."
				echo "These files can be decoded using traceADA.sh script."
			fi
		fi

		destdir="$destdir/services/Attendant"
		target="$target-ce-Attendant"
		cd "services/Attendant"

	elif [ -d "Attendant" ]; then
		if [ -d "sm" ]; then
			let asmfiles=0
			asmfiles=$(ls sm/asm* 2>/dev/null | wc -l)
			if [[ $((asmfiles)) != 0 ]]; then
				echo "NOTE: found $asmfiles asm files at \"sm\" folder - these files can be decoded using traceBREEZE.sh script."
			fi
		fi
		if [ -d "DeviceAdapter" ]; then
			let adafiles=0
			adafiles=$(ls DeviceAdapter/dsa* 2>/dev/null | wc -l)
			if [[ $((adafiles)) != 0 ]]; then
				echo "NOTE: found $adafiles dsa.log files at \"DeviceAdapter\" folder."
				echo "These files can be decoded using traceADA.sh script."
			fi
		fi

		destdir="$destdir/Attendant"
		target="$target-ce-Attendant"
		cd "Attendant"

	elif [ -s "logs.zip" ]; then
		ftype=$(file -b "logs.zip")
		if [[ $ftype == "Zip archive"* ]] && [[ $filecontent == "ATTD" ]]; then
			if [ -d "logs.tmp" ]; then
				rm -rf "logs.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not delete existing \"logs.tmp\" folder in $PWD."
					echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
					error=7; return
				fi
			fi
			mkdir "logs.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create \"logs.tmp\" folder at $PWD.\n"
				error=7; return				
			elif [ -d "logs.tmp" ]; then
				cd "logs.tmp"
				echo -e "\nExtracting logs.zip from $var using \"unzip\" ...                                             "			
				unzip -qq "../logs.zip" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "logs.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress logs.zip, using \"unzip\" utility."
					echo -e "Suggesting to validate \"unzip\" manually on \"$var->logs.zip\".\n"
					error=8; return
				else
					input="$destdir/logs"; tmpfile=3			
					target="$target-logs"
					destdir="$destdir/logs.tmp"
				fi
			fi
		else
			echo -e "\nWarning: found \"logs.zip\" but unable to uncompress it due to lack of required tool: \"unzip\"\n"
			error=8; return			
		fi
	fi

	explore_logfolder
		
	if [[ $file == "" ]]; then
		error=1
		echo -e "\nerror: could not find any ATTD related logs in $folder\n"
	fi
	cd $currdir		
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

##################### Execution starts here #########################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts "e:hbdsf:ACIN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
	C)
		bCAT=1;;
    I)
		noINFO=1;;		
	s)
		sipstat=0;;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;
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
bUnzip=0
bGunzip=0
ctarget=""
origctarget=""

file --help >/dev/null 2>&1
if [[ $? != 0 ]]; then
	echo -e "\nerror: unable to find "file" utility.  You may want to install it with "apt install file" command."
	echo -e "This tool relies heavily upon "file" command. Cannot continue execution. Aborting...\n"
	exit 1
fi

if [[ $((base64decode)) != 0 ]]; then
   base64 --version >/dev/null
   if [[ $? != 0 ]]; then
	  base64decode=0
   fi
fi
cmdtest=$(unzip -qq -v >/dev/null 2>&1)
if [[ $? == 0 ]]; then
	bUnzip=1
fi
gunzip --version >/dev/null 2>&1
if [[ $? -le 1 ]]; then
	bGunzip=1
fi

for var in "$@"
	do

	if [[ $var == "-"* ]]; then
		if [[ $var == "-f"* ]]; then
			skipper=1
		elif [[ $var == "-e" ]]; then
		    skipper=2
		elif [[ $var == "-N"* ]]; then
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
           endptaddr=$var
		elif [[ $((skipper)) == 3 ]]; then
			findANI=$findANI		# findANI=$var
		fi
		skipper=0
		continue
	fi

	n=0; 		error=0;	vsyslog=0
	bdir="";	bvar="";	folder=""
	target=""; 	destdir="";	input=""; input2=""
	file=""; 	filelist="";basefile=""
	currtime=$(date +%R:%S);currdir=$PWD	
	bSinglefile=0; tmpfile=0
	filetype2=""; filecontent="ATTD"
	
	filetype=$(file -b "$var")
	filetype2=$(file -bZ "$var")
	bdir=$(dirname "$var")
	bvar=$(basename "$var")
	if [[ $var == $bvar ]]; then
		bvar=$(basename "$var" .tar)
		if [[ $var == $bvar ]]; then
			bvar=$(basename "$var" .tgz)
			if [[ $var == $bvar ]]; then
				bvar=$(basename "$var" .gz)
			else
				bvar=$(basename "$var" .zip)
			fi
		fi
		target="$bvar"
		bvar=$(basename "$var")		
	elif [[ $var == "." ]]; then
		target="ATTD"
	else
		target=$bvar		
	fi

#	target=${target%%.*}										# TODO: what about ../folder or ../filename - note the leading ".."	
	if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
		target=${target%.*}
		if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
			target=${target%.*}
		fi
	fi

	if [ -d "$var" ]; then
		echo -en "\nExploring content in \"$var\" folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"
		file="$var"

		if [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "ATTD" ]]; then
			if [[ $bvar == *"."* ]]; then
				input=${bvar%.*}
			else
				input="$bvar"
			fi
			if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then										
					echo -e "\nerror: could not delete existing $input.tmp folder."
					echo -e "Check if any subfolders or files currently open (in other shell sessions)."
					echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"
					error=7; cd $currdir; input=""; continue
				fi
			fi

			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"
				input=""; error=7; cd $currdir; continue
			fi

			if [[ $bUnzip != 0 ]] && [ -d "$input.tmp" ]; then
				cd "$input.tmp"
				bfile=$(basename "$var")

				echo -e "\nUncompressing $bfile into $input.tmp ...                                                  "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress $bfile, using \"unzip\" utility. Skipping this file..."
					echo -e "Suggesting to validate \"unzip -qq $bfile\" command manually.\n"					
					error=8; cd "$currdir"; input=""; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders

					if [[ $file == "" ]]; then
						file=""; filelist=""
						filecontent="cereport"					
						file=$(ls -t "cereport*.tgz" 2>/dev/null)
						if [[ $file == "" ]]; then
							file=$(ls -t "cereport*.tar" 2>/dev/null)
						fi
						if [[ $file != "" ]]; then
							file=$(awk '{print $1}' <<< "$file")				# head -1)
							filetype=$(file -b "$file")
						fi
					fi
				fi

			elif [[ $bUnzip == 0 ]]; then
				cd ..; rm -rf "$input.tmp" 2>/dev/null				
				echo -e "\nWarning: \"unzip\" package was not found."
				echo -e "If using Ubuntu, execute \"sudo apt-get unzip install\" to deploy and re-try.\n"
				error=8; cd $currdir; input=""; continue
			fi
			cd "$currdir"
		fi

		if [[ $filetype == *"compressed data"* ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				zfile="$file"
				bfile=$(basename "$file")
				filetype2=$(file -bZ "$file")
			else
				zfile="$var"
				bfile=$(basename "$var")
				filetype2=$(file -bZ "$var")
			fi

			if [[ $filetype =~ compressed ]]; then
				if [[ $filetype2 =~ ASCII|text|data|tar ]]; then
					if [[ $bfile == *"."* ]]; then
						input2=${bfile%.*}
					else
						input2="$bfile"
					fi

					if [[ $bGunzip != 0 ]]; then
						echo "Uncompressing $zfile into $input2 ...                                        "
						gunzip -q -c "$zfile" > "$input2" 2>/dev/null

						if [[ $? -le 1 ]]; then
							file="$input2"; tmpfile=2
							filetype=$(file -b "$file")
							filecontent="ASCII"
						else
							echo -e "\nerror: failed to uncompress $bfile, using \"gunzip\" utility.\n"
							error=8; continue
						fi
					else
						echo -e "\nerror: unable to uncompress $bfile, \"gunzip\" utility not found.\n"
						error=8; continue
					fi
				fi
			fi
		fi


		if [[ $filetype =~ tar ]] || [[ $filetype2 =~ tar ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")			
			fi

			tar --version >/dev/null 2>&1
			if [[ $? == 0 ]]; then
				if [[ $bfile == *"."* ]]; then
					input=${bfile%.*}					
				else
					input="$bfile"
				fi

				if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp" 2>/dev/null
					if [[ $? != 0 ]]; then						
						echo -e "\nerror: could not delete existing temp folder: $input.tmp"
						echo "Check if any subfolders or files are open (in other shell sessions).\n"
						error=7; cd $currdir; input=""; continue
					fi
				fi

				mkdir "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd $currdir; input=""; continue
				fi

				cd "$input.tmp"
				echo "Extracting $bfile ...                                                                              "

				if [[ $filetype =~ compressed ]] && [[ $filetype2 =~ tar ]]; then
					tar zxf "../$file" 2>/dev/null
				elif [[ $filetype =~ tar ]]; then
					tar xf "../$file" 2>/dev/null				
				fi

				if [[ $? != 0 ]]; then
					if [[ $bGunzip != 0 ]]; then
						gunzip -q "../$file" 2>/dev/null
						if [[ $? != 0 ]]; then
							echo -e "error: could not uncompress $bfile, using neither \"tar\" nor \"gunzip\" utilities.\n"
							error=8; cd $currdir; input=""; continue
						else
							tar xf $input 2>/dev/null										# TODO verify the exact new filename after gunzip
							if [[ $? != 0 ]]; then
								cd ..; rm -rf "$input.tmp"						
								echo -e "\nerror: failed to uncompress $bfile, using \"tar\" utility.\n"
								error=8; cd $currdir; input=""; continue
							else
								destdir="$PWD"; tmpfile=1
								folder="$input"
								explore_folders
							fi
						fi
					else 
						cd ..; rm -rf "$input.tmp"						
						echo -e "error: failed to uncompress $bfile, using \"tar\" utility.\n"
						error=8; cd $currdir; input=""; continue
					fi
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"					
					explore_folders
				fi
				cd $currdir				
			else
				echo -e "\nerror: unable to uncompress $bvar, \"tar\" utility not found.\n"
				error=1; continue
			fi

		elif [[ $filetype =~ text ]] || [[ $filetype == "data" ]]; then
			filelist=""
			filecontent="ASCII"
			bSinglefile=1

		elif [[ $file == "" ]] && [[ $error == 0 ]]; then
			echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
			error=4
		fi

	elif [[ $filetype =~ cannot|open ]]; then
		echo -e "\nerror: $bvar was not found or unable to open. Verify path and filename."
		error=3

	elif [[ $file == "" ]] && [[ $error == 0 ]]; then
		echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
		error=4

	elif [ -f "$var" ]; then
		echo -e "\nerror: $bvar is an empty file."
		ls -l "$var"; error=3
	fi

	if [[ "$filelist" != "" ]] && [[ $file != $filelist ]]; then
		bSinglefile=0
	else
		bSinglefile=1					
	fi

	if [[ $((bCAT)) != 0 ]] && [[ $bSinglefile != 0 ]]; then
		if [[ $origctarget == "" ]]; then
			ctarget="$target.casm"
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
#			echo -e "\nConcatenating for $var into $ctarget\n"
			echo -e "# Concatenating for $var\n" > "$ctarget"
			origctarget=$ctarget
		else
			ctarget=$origctarget
		fi
	elif [[ $((bCAT)) != 0 ]]; then
		ctarget="$target.casm"
		if  [ -f "$ctarget" ]; then
			mv "$ctarget" "$ctarget.bak"
		fi
#		echo -e "\nConcatenating for $var into $ctarget\n"
		echo -e "# Concatenating for $var\n" > "$ctarget"
	fi

	nfiles=0; origIFS=$IFS
	if [[ $((alllogs)) != 0 ]] && [[ "$filelist" != "" ]]; then
#		nfiles=$(wc -w <<< "$filelist")
		if [[ $filelist =~ ^= ]]; then
			nfiles=$(awk -F"=" '{print NF}' <<< "$filelist")		
			filelist=${filelist:1}
			nfiles=$((nfiles-1))
		fi
		if [[ $((bCAT)) != 0 ]]; then
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
		fi
		IFS="="

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x ClientSDKLog*.txt or Attendant.log.*)."
			echo -e "This may take a while... You may want to execute the script on a more powerful PC or server.\n"

			let z=0; file=""
			for file in $filelist;
			do
				if [[ $file != "" ]] && [ -s "$file" ]; then
					IFS=$origIFS				
					z=$(egrep -m 1 -c -e "CSeq:" "$file")
					if [[ $((z)) != 0 ]]; then
						convert_siplog
					else
						bfile=$(basename "$file")					
						echo "Skipping $bfile - no SIP messages have been found."
					fi
					z=0; error=0
				fi
				IFS="="; currtime=$(date +%R:%S)
			done

			if [[ $((bCAT)) != 0 ]] && [ -f "$ctarget" ]; then
				echo -e "All converted files found in $bvar have been concatenated into $ctarget\n"
				ls -l "$ctarget"; echo ''
			fi

		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			IFS=$origIFS
			convert_siplog
		fi
		IFS=$origIFS

	elif [[ "$filelist" != "" ]]; then
		file=$(awk '{print $1}' <<< "$filelist")		# head -1)
#		file="$input.tmp/$file"
		convert_siplog
	elif [[ $file != "" ]]; then
		convert_siplog	
	fi

	if [[ $bDelTemp != 0 ]]; then
		if [[ $input2 != "" ]] && [ -d "$input2.tmp" ]; then
			rm -rf "$input2.tmp" 2>/dev/null
		fi
		if [[ $input != "" ]]; then 
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp" 2>/dev/null
			fi
			if [ -f "$input" ]; then
				rm "$input" 2>/dev/null
			fi
		fi
		if [[ $tmpfile == 2 ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
		fi		
	fi
done
if [[ $((converted)) != 0 ]] && [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0