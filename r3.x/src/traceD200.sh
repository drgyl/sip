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
pattern1='-----------------------------------------------------------------'
pattern2='<I,sip.*INCOMING|<I,sip.*OUTGOING'
# pattern2='^FINE.*% $'
# pattern3='^% '
# pattern4='^INFO|^FINE|^FINER|^FINEST'
sipstat=1
alllogs=0
bDelTemp=1
bCAT=0
findANI=""
converted=0
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0  ## values explained below:

# TODO: extract SYSLOG from pcapng/pcap wireshark

function usage ()  {
    echo "traceD200.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"
#	echo ''
	echo 'Usage: traceD200.sh [OPTIONS] [<LOG_FILE> | <folder> ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the BS package (.zip) or the SIPLOG file collected from a D200 DECT box"
	echo -e "\t<folder>\twhich includes SIPLOG traces files (.txt).\n"
	echo '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"	
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
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
	sipstart=1; 	siplines=$((siplines+1))
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
		n=$((n+1)); 		sipstart=0
		if [[ $((sipstat)) != 0 ]]; then
			if [[ $basefile != "" ]]; then
				echo -en "$basefile => $n/$rec Msgs converted            \r"
			else
				echo -en "$var => $n/$rec Msgs converted            \r"
			fi
		fi
		case $voutput in
		1)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
		2)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi
} # sipmsg_header() 

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line =~ ^Received ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70; 				dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)	dirstring1="-->"; 			dirstring2="ingress";;
		esac

	elif [[ $line =~ ^Sent ]]; then
		## elif [[ $direction == 'Outbound' ]]; then
		sipstream=1474; 			dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	else
		sipstream=0
		insidesip=0
		dirdefined=0
	fi
# Sent to tls:192.168.11.34:5061 at 31/08/2021 01:39:33  (918 bytes)	
	if [[ $(($dirdefined)) != 0 ]]; then
		siplength=$(awk '{print $7}' <<< "$line" | cut -d'(' -f2)	
		ip=$(cut -d' ' -f3 <<< "$line")
		protocol=$(cut -d':' -f1 <<< "$ip")
		ip1=$(cut -d':' -f2 <<< "$ip")
		ip2=$(cut -d':' -f3 <<< "$ip")
		ip="$ip1:$ip2"
	fi
fi	
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"Server:"* ]]; then
			useragent=$(awk -F'Server: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	sipyear=$(awk '{print $5}' <<< "$line")          # cut -d' ' -f4) --  because of multiple spaces
	sipday=$(cut -d'/' -f1 <<< "$sipyear")
	sipmonth=$(cut -d'/' -f2 <<< "$sipyear")
	sipyear=$(cut -d'/' -f3 <<< "$sipyear")

# Received from tls:192.168.11.34:5061 at 31/08/2021 01:39:33  (453 bytes)
# Sent to tls:192.168.11.34:5061 at 31/08/2021 01:39:33  (918 bytes)
	sipmsec=$(cut -d' ' -f6 <<< "$line")
	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")
	sipmsec="000"	
						
	case $voutput in
	1)	sipdate="$sipmonth/$sipday/$sipyear"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	2)	sipdate="$sipyear/$sipmonth/$sipday"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	3)	sipdate="$sipday/$sipmonth/$sipyear"
		siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
	esac
} # get_sip_datetime()

function explore_logfolder() {
	file="";	filelist=""
	targetX="";	xfile=""
	targetX=$(ls -r -t1 *.txt 2>/dev/null)

	if [[ $? == 0 ]] && [[ $targetX != "" ]]; then
		if [[ $((alllogs)) == 0 ]]; then
#			file=$(head -1 <<< $targetX)
			file=${targetX%% *}
			if [ -s "$file" ]; then
#				n=$(egrep -c "CSeq:" "$xfile")
				file="$destdir/$file"
			fi
		else
			for xfile in $targetX
			do
				if [ -s $xfile ]; then
					if [[ $filelist == "" ]]; then
						filelist="=$destdir/$xfile"
					else
						filelist="$filelist=$destdir/$xfile"
					fi
				fi
			done
		fi
	fi
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
	fi

	if [ -d SIPLOG_traces ]; then
		destdir="$destdir/SIPLOG_traces"
		cd SIPLOG_traces
	fi

	if [ -d "log" ] || [ -d "logs" ]; then
		if [ -d "log" ]; then
			destdir="$destdir/log"
			target="$target-log"
			cd "log"
		elif [ -d "logs" ]; then
			target="$target-logs"
			if [ -d "logs/log" ]; then
				destdir="$destdir/logs/log"
				cd "logs/log"
			else
				destdir="$destdir/logs"
				cd "logs"
			fi
		fi
	fi

	explore_logfolder

	if [[ $file == "" ]]; then
		error=1
		echo -e "\nerror: could not find any SIPLOG (D200) trace files in $folder\n"
	fi
	cd "$currdir"
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "
	rec=$(egrep -c -e "^Received|^Sent" "$file")
#	rec2=$(egrep -m 1 -c -e "^CSeq:*" "$file")	

	if [[ $((rec)) == 0 ]];	then
		echo -e "\nerror: No SIP messages have been found in $basefile in the expected format."
		echo "This file may not be a SIPLOG from D200 device."
		rec=$(egrep -c -e "^CSeq:.*" "$file")
		if [[ $((rec)) == 0 ]]; then
			echo "In fact, no sign of any "CSeq:" lines within $basefile"
			error=2; rec=0
		else
			echo "Though, found $rec lines with "CSeq:" - so there might be some sort of SIP messages within $basefile."
			error=1; rec=0
			asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
			if [[ $((asmfile)) != 0 ]]; then
				asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
				if [[ $((asmfile)) != 0 ]]; then
					echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
					echo "This kind of input is not (yet) supported by this tool."
				fi
			fi
		fi			

#  	    rec=$(egrep -c -m 1 -e "^Server: Avaya SIP Enablement Services")
		rec=$(egrep -c -m 1 -e "^User-Agent: Avaya D2.*" "$file")
		if [[ $((rec)) == 0 ]]; then
		    echo "No indication $basefile being related to D200 logfile."
		else
	    	rec=0; echo "Though, found reference in $basefile to D200."
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

	elif [[ $((rec2)) != 0 ]]; then
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
		conv=$(awk -e '/^Sent|^Received/{flag=1} flag; /}/{flag=0}' "$file")

		if [[ $rec -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo -e "You may want to execute this script on a more powerful PC or server.\n"
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
		echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"

		while IFS= read -r line
		do
			linelength=${#line}
			nlines=$((nlines+1))

			if [[ $line =~ ^Received|^Sent ]]; then
				if [[ $((sipstart)) != 0 ]]; then
					complete_sipmsg
				fi

				siptotalmsg=$((siptotalmsg+1))
				insidesip=1
				get_sip_datetime
				sip_direction

			elif [[ $((insidesip)) == 0 ]]; then
				continue
			elif [[ $((insidesip)) == 1 ]] && [[ $linelength -lt 2 ]]; then
				if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
					reset_sipmsg
				else
					insidesip=2
				fi
			elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
				sipmsg_header
				start_sipmsg						
				insidessip=3
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
		done <<< "$conv"
#		done < "$file"

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

			echo -e "\tTotal # of lines digested:\t\t\t $nlines"

			if [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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
		if [[ $tmpfile == 1 ]]; then
			rm "$file"
		fi
		pwd; ls -l "$var.asm"
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
	echo -e "convert_siplog() received null string for input. Contact developer.\n"
	error=6
fi
} # convert_siplog()

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbdsf:ACN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
	C)
		bCAT=1;;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	d)
		bDelTemp=0;;
	S)
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
bUnzip=0
bGunzip=0
ctarget=""
origctarget=""; var=""

file --help >/dev/null 2>&1
if [[ $? != 0 ]]; then
	echo -e "\nerror: unable to find "file" utility.  You may want to install it with "apt install file" command."
	echo -e "This tool relies heavily upon "file" command. Cannot continue execution. Aborting...\n"
	exit 1
fi

if [[ $((base64decode)) != 0 ]]; then
	base64 --help >/dev/null 2>&1
	if [[ $? != 0 ]]; then
		base64decode=0
	fi
fi

unzip -qq -v >/dev/null 2>&1
if [[ $? -le 1 ]]; then
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
			findANI=$findANI		# findANI=$var
		fi
		skipper=0; var=""
		continue
	fi

	file=$var; filelist=""; folder=""
	currtime=$(date +%R:%S);currdir=$PWD	
	error=0;	vsyslog=0; 	tmpfile=0
	target="";	destdir="";	input=""

	bSinglefile=0; 		filecontent="D200"
	filetype1=$(file -b "$var")
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
		target=$bvar
		bvar=$(basename "$var")
	elif [[ $var == "." ]]; then
		target="D200"
	else
		target=$bvar		
	fi

#	target=${target%%.*}				# TODO: what about ../folder or ../filename - note the leading ".."	
	if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
		target=${target%.*}
		if [[ $target == *"."* ]] && [[ $target != "."* ]]; then
			target=${target%.*}
		fi
	fi

	if [ -d "$var" ]; then
		echo -en "\nExploring content in $var folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders
		cd "$currdir"		

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"
		file="$var"

		if [[ $filetype1 == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype1 =~ "Zip archive" ]] && [[ $filecontent == "D200" ]]; then
			if [[ $bvar == *"."* ]]; then
				input=${bvar%.*}
			else
				input="$bvar"
			fi
			if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp"
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not delete temp folder: $input.tmp in $PWD."
					echo -e "Check if any subfolders or files are open (in other shell sessions).\n"	
					error=7; cd "$currdir"; input=""; continue
				fi
			fi

			if [[ $bUnzip != 0 ]]; then		
				echo -e "\nExtracting $file ...                                                                                            "
				mkdir "$input.tmp"
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not create $input.tmp folder in $PWD.\n"
					error=7; cd "$currdir"; input=""; continue
				fi

				cd "$input.tmp"			
				unzip -qq "../$file" 2>/dev/null
				if [[ $? != 0 ]]; then
					cd ..
					if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
						rm -rf "$input.tmp"	
					fi
					echo -e "\nerror: could not uncompress $bvar, using unzip."
					echo -e "Suggesting to validate \"unzip\" manually on \"$file\".\n"
					error=8; cd "$currdir"; input=""; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
				fi
			else
				echo -e "\nerror: could not uncompress $bvar, \"unzip\" utility not found."
				echo -e "Suggesting to deploy \"unzip\" package. in Ubuntu, you can install it by typing: \"sudo apt install unzip\".\n"
				error=7; cd "$currdir"; input=""; continue				
			fi

		elif [[ $filetype1 == *"compressed data"* ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				zfile="$file"
				bfile=$(basename "$file")
				filetype2=$(file -bZ "$file")
			else
				zfile="$var"
				bfile=$(basename "$var")
				filetype2=$(file -bZ "$var")
			fi

			if [[ $filetype1 =~ compressed ]]; then
				if [[ $filetype2 =~ ASCII|text|data|tar ]]; then
					if [[ $bfile == *"."* ]]; then
						input2=${bfile%.*}
					else
						input2="$bfile"
					fi

					if [[ $input2 == $zfile ]]; then input2="$input2.uncompressed"; fi

					if [ -d "$input2" ]; then
						input2="$input2-tmp"
						if [ -f "$input2" ]; then
							rm "$input2" 2>/dev/null
						fi
					fi

					if [[ $bGunzip != 0 ]]; then
						echo "Uncompressing $zfile into $input2 ...                                                                    "
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

		if [[ $filetype1 =~ tar ]] || [[ $filetype2 =~ tar ]]; then
			tar --version >/dev/null 2>&1
			if [[ $? == 0 ]]; then
				if [[ $file == *"."* ]]; then
					input=${file%.*}					
				else
					input="$file"
				fi

				if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp"
					if [[ $? != 0 ]]; then						
						echo -e "\nerror: could not delete existing $input.tmp folder."
						echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
						error=7; cd "$currdir"; input=""; continue
					fi
				fi
				mkdir "$input.tmp"
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd "$currdir"; input=""; continue
				fi

				cd "$input.tmp"
				echo "Extracting $file ...                                                                                "
				if [[ $filetype1 =~ compressed ]] && [[ $filetype2 =~ tar ]]; then
					tar zxf "../$file" 2>/dev/null
				elif [[ $filetype =~ tar ]]; then
					tar xf "../$file" 2>/dev/null		
				fi

				if [[ $? != 0 ]]; then
					if [[ $bGunzip != 0 ]]; then
						gunzip -q "../$file"
						if [[ $? != 0 ]]; then							
							echo -e "\nerror: could not uncompress $file, using neither \"tar\" nor \"gunzip\" utilities.\n"
							error=8; continue
						else
							tar xf $input									# TODO verify the exact new filename after gunzip
							if [[ $? != 0 ]]; then
								cd ..; rm -rf "$input.tmp"						
								echo -e "\nerror: failed to uncompress $var, using \"tar\" utility.\n"
								error=8; cd "$currdir"; input=""; continue
							else
								destdir="$PWD"; tmpfile=1
								folder="$input"
								explore_folders
							fi
						fi
					else 						
						cd ..; rm -rf "$input.tmp"
						echo -e "\nerror: failed to uncompress $var, using \"tar\" utility.\n"
						error=9; cd "$currdir"; input=""; continue
					fi
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
				fi
			fi

		elif [[ $filetype1 =~ capture ]]; then
			if [[ $filetype1 =~ tcpdump ]] || [[ $filetype1 =~ pcap ]]; then
		  		line=$(whereis tshark 2>&1)
				tshark --version >/dev/null 2>&1

				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
		     		echo -e "\nerror: unable to locate 'tshark' command."
					echo -e "'tshark' is required to extract syslog messages from $var wireshark capture into text file.\n"
					error=10; continue
				else
					if [[ $endptaddr != "" ]]; then
				    	tshark -r $file -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi
					if [ -s "$file.syslog2" ]; then
						sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
					else
						echo -e "\nerror: could not extract any SYSLOG packets from $file using \"tshark\" command.\n"
						error=11; continue
					fi
					if [ -s "$file.syslog" ]; then
						input="$file"
#						rm "$file.syslog2"
						file="$file.syslog"; tmpfile=2
						filecontent="syslog"
						bSinglefile=1						
						echo -e "\nALERT: current version of $@ script does not cover extracting SIP messages from wireshark traces.  Contact developer.\n"
						error=13; continue
#						vsyslog=25
					else
						echo -e "\nerror: problem occured transforming $file.syslog2 into $file.syslog. Contact developer.\n"
						error=12; continue						
					fi
				fi
	  		fi

		elif [[ $filetype1 =~ text ]] || [[ $filetype1 == "data" ]]; then
			filelist=""
			filecontent="ASCII"
			bSinglefile=1

		elif [[ $file == "" ]] && [[ $error == 0 ]]; then
			echo -e "\nerror: filetype of $bvar is not supported ($filetype1)."
			error=4
		fi

	elif [[ $filetype1 =~ cannot|open ]]; then
		echo -e "\nerror: $bvar was not found or unable to open. Verify path and filename."
		error=3

	elif [[ $file == "" ]] && [[ $error == 0 ]]; then
		echo -e "\nerror: filetype of $bvar is not supported ($filetype1)."
		error=4

	elif [ -f "$var" ]; then
		echo -e "\nerror: $bvar is an empty file."
		ls -l "$var"; error=3
	fi

	if [[ $error != 0 ]]; then
		continue
	fi

	if [[ $filelist != "" ]] && [[ $file != $filelist ]]; then		
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
	if [[ $((alllogs)) != 0 ]]; then
		if [[ $filelist != "" ]]; then
			nfiles=$(echo $filelist | wc -w)
		elif [[ $file != "" ]]; then
			nfiles=1
		fi

		if [[ $((bCAT)) != 0 ]]; then
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
		fi
		IFS="="

		if [[ $((nfiles)) -gt 1 ]] && [[ $filelist != "" ]]; then
			echo "Warning: about to convert multiple files ($nfiles x siptraces or logs_phoneapp) found in $var"
			echo "This may take a while... you may want to execute the script on a more powerful PC or server."
			echo ''

			let z=0; file=""
			for file in $filelist;
			do
				IFS=$origIFS
				z=$(egrep -c "CSeq:" "$file" 2>/dev/null)
				if [[ $z != 0 ]]; then
					convert_siplog
				else
					bfile=$(basename "$file")				
					echo -e "\n$bfile : No SIP messages have been found."
				fi
				z=0; 		error=0
				IFS="="; 	currtime=$(date +%R:%S)
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

	elif [[ $file != "" ]]; then
		convert_siplog
	fi

	if [[ $bDelTemp != 0 ]]; then
		if [[ $tmpfile != 0 ]] && [[ $file != $var ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
		fi
		if [[ $input != "" ]]; then
			if [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp"
			elif [ -f "$input" ]; then
				rm "$input"
			fi
		fi
		if [[ $tmpfile == 2 ]] && [[ $file != $var ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
		fi		
	fi
done

if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
elif [[ $((converted)) != 0 ]] && [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget"
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0