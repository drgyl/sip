#!/bin/bash
version="2.0.0.1"
NL=$'\n'
TAB=$'\t'
AWKSRCFLAG="-W source="
today=$(date +%m/%d/%Y)
year=$(date +%Y)
localip="1.1.1.1:1111"
protocol="TLS"
sipstat=1
alllogs=0
noINFO=0
bCAT=0
bDelTemp=1
findANI=""
converted=0
fixVSYSLOG=0
siplength=666
base64decode=1
voutput=1
vsyslog=0

function usage ()  {
    echo "traceAAFD.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAAFD.sh <options> [<LOG_FILE> | <folder>, ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the \"AvayaAgentLogs.zip\" logReport itself, or the \"LogsFromDefaultDir.zip\""
	echo -e "\t\t\tor \"LogsFromUserDir.zip\" or SIPMessagesX.txt files from a logReport."
	echo -e "\t<folder>\tincludes either of the above files, or it could be even any of the local"
	echo -e "\t\t\t\"Roaming/Avaya\", \"Avaya/Avaya Agent\", \"Avaya Agent/LogsFromDefaultDir\","
	echo -e "\t\t\t\"Avaya/logs\", \"Avaya Agent/logs\", \"AvayaAgentLogs\" or \"../logs\" directories."
	echo  '  Options:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-b \t\tdo not decode Base64/gzip/deflate encoded content in SIP messages"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converted multiple logfiles)"			
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"		
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	dirdefined=0
	base64found=0
	ip=""
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

	lastmsg="$sipword"; timelast="$sipdate $siptime"
	if [[ $((sipmsg)) == 1 ]]; then
		firstmsg=$lastmsg; 	timefirst=$timelast
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
		base64msg=$((base64msg+1))
		rm "$newfile.b64" 2>/dev/null
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
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line == *"RECEIVED"* ]]; then
		sipstream=5f70; 			dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line == *"SENT"* ]]; then
		sipstream=1474; 			dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	else
	    reset_sipmsg
	fi
	if [[ $((dirdefined)) != 0 ]]; then
		siplength=$(awk '{printf "%i",$NF}' <<< "$line")
		ip=$(awk '{print $9}' <<< "$line")		# cut -d' ' -f10)
		ip1=$(cut -d':' -f1 <<< "$ip")
		ip2=$(cut -d':' -f2 <<< "$ip" | cut -d'.' -f1)
		ip=$ip1:$ip2
	fi
fi	
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
# 2022-05-20 09:33:24.326 DBH [13536] SIGNAL | SENT to 10.134.117.194:5061. Length= 604.			

    sipday=$(cut -d' ' -f1 <<< "$line")
	sipyear=$(cut -d'-' -f1 <<< "$sipday")
	sipmonth=$(cut -d'-' -f2 <<< "$sipday")
    sipday=$(cut -d'-' -f3 <<< "$sipday")
									
	sipmsec=$(cut -d' ' -f2 <<< "$line")
	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")
	sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
	sipsec=$(cut -d'.' -f1 <<< "$sipsec")

	case $voutput in
	1)	sipdate="$sipmonth/$sipday/$sipyear"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	2)	sipdate="$sipyear/$sipmonth/$sipday"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	3)	sipdate="$sipday/$sipmonth/$sipyear"
		siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
	esac
} # get_sip_datetime()

function convert_siplog () {
# echo -e "\nEntering convert_siplog()... $file"
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "

	fsize=$(wc -c < "$file" 2>/dev/null)
	if [[ $((fsize)) -gt 0 ]]; then
		rec=$(egrep -ce "DBH \[.*SIGNAL" "$file")
		rec2=$(egrep -ce "^CSeq:*" "$file")
	fi

	if [[ $((rec)) == 0 ]]; then
		if [[ $var != $file ]]; then
			echo -e "\nerror: $var -> $basefile does not include any SIP messages in the expected format."
		else
			echo -e "\nerror: $var : No SIP messages have been found in the expected format."
		fi

		if [[ $((rec2)) != 0 ]]; then
			if [[ $var != $file ]]; then
				echo -e "Though found a line starting with \"CSeq:\" - so there might be some SIP messages within $var -> $basefile.\n"
			else
				echo -e "Though found a line starting with \"CSeq:\" - so there might be some SIP messages within $var.\n"
			fi
		else
			rec2=$(egrep -c "^User-Agent: Avaya Agent for Desktop*" "$file")
			if [[ $((rec2)) == 0 ]]; then
				echo 'And, could not locate any lines including "CSeq:" or "User-Agent: Avaya Agent for Desktop" either.'
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
		fi
		rec2=0; error=9; return

	elif [[ $((rec2)) != 0 ]]; then
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

 # echo file=$file basefile=$basefile filelist=$filelist
 # echo input=$input output=$output
 # echo target=$target newfile=$newfile

		echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
		echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
		echo "# Command line: $args" >> "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
		echo "# Input: $var" >> "$newfile"
		iohist=""
		if [[ $var != $file ]]; then
			iohist="$var -> $file -> $output.asm"
		else
			iohist="$var -> $output.asm"
		fi

		if [[ ${#iohist} -lt 48 ]]; then
			echo -e "# Input/output file history: $iohist\n" >> "$newfile"
		else
			echo -e "# Input/output file history:" >> "$newfile"
			echo -e "# $iohist\n" >> "$newfile"
		fi

#	    conv=$(awk -e '/DBH \[*/{flag=1} flag; /}/{flag=0}' "$file")
	    conv=$(awk -W source='/DBH \[.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file")			

		logsec=$SECONDS
		base64msg=0
		useragent=""
		foundipaddr=""
		nlines=0
		sipyear=""
		sipmonth=""
		sipday=""
		siphour=""
		sipmin=""
		sipsec=""
		sipmsec=""
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
		nINFO=0
		n=0		

	    reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo -e "You may want to execute this script on a more powerful PC or server.\n"
		fi

		while IFS= read -r line
		do
			nlines=$((nlines+1))

#			if [[ $line =~ DBH\ \[.*\]\ SIGNAL ]]; then
			if [[ $line =~ DBH\ \[.*SIGNAL ]]; then			
				if [[ $((sipstart)) != 0 ]]; then
					complete_sipmsg
				fi
				insidesip=1
				siptotalmsg=$((siptotalmsg+1))	
				sip_direction
				get_sip_datetime	
															
			elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]] && [[ $line == "{"* ]];	then
#				sipmsg_header	
				sipstart=1
			elif [[ $((sipstart)) ==  1 ]];	then
				if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
					nINFO=$((nINFO+1))
					reset_sipmsg
					continue
				else
					sipmsg_header	
					start_sipmsg
					sipstart=2
				fi
			elif [[ $((sipstart)) == 2 ]]; then
				if [[ $line == *"}"* ]]; then
					complete_sipmsg
					continue
				fi
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
						rm "$newfile.b64"
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

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output="$var"
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

			if [[ $((error)) != 0 ]]; then
				echo -e "\n\tError found: $error\n\n"

			elif [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
				echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
				if [[ $((nINFO)) != 0 ]]; then
					echo -e "\tINFO messages ignored:\t\t\t\t $nINFO"
				fi
				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
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
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd;ls -l "$output.asm"
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

function probe_LogsFromDir () {
if [[ $destdir != "" ]]; then
	if [ -d "LogsFromUserDir" ]; then
		destdir="$destdir/LogsFromUserDir"
		target="$target-LogsFromUserDir"
		cd "LogsFromUserDir"
		explore_logfolder
		cd ..

	elif [ -d "LogsFromDefaultDir" ]; then
		destdir="$destdir/LogsFromDefaultDir"
		target="$target-LogsFromDefaultDir"
		cd "LogsFromDefaultDir"
		explore_logfolder
		cd ..

	elif [ -f "LogsFromUserDir.zip" ]; then
		ftype=$(file -b "LogsFromUserDir.zip")
		if [[ $ftype == "Zip archive"* ]] && [[ $bUnzip != 0 ]]; then 
			if [ -d "LogsFromUserDir.tmp" ]; then
				rm -rf "LogsFromUserDir.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not delete existing \"LogsFromUserDir.tmp\" folder in $PWD."
					echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
					error=7; return
				fi
			fi
			mkdir "LogsFromUserDir.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create \"LogsFromUserDir\" folder at $PWD.\n"
				error=7; return				
			elif [ -d "LogsFromUserDir.tmp" ]; then
				cd "LogsFromUserDir.tmp"
				echo "Extracting LogsFromUserDir.zip from $var using \"unzip\" ..."			
				unzip -qq "../LogsFromUserDir.zip" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "LogsFromUserDir.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress LogsFromUserDir.zip, using \"unzip\" utility."
					echo -e "Suggesting to validate \"unzip\" manually on \"$var->LogsFromUserDir.zip\".\n"
					error=8; return
				else
					input="$destdir/LogsFromUserDir"				
					target="$target-LogsFromUserDir"
					destdir="$destdir/LogsFromUserDir.tmp"
					explore_logfolder
				fi
				cd ..
			fi
		else
			echo -e "\nWarning: found \"LogsFromUserDir.zip\" but unable to uncompress it due to lack of required tool: \"unzip\"\n"
			error=8; return			
		fi

	elif [ -f "LogsFromDefaultDir.zip" ]; then
		ftype=$(file -b "LogsFromDefaultDir.zip")
		if [[ $ftype == "Zip archive"* ]] && [[ $bUnzip != 0 ]]; then 
			if [ -d "LogsFromDefaultDir.tmp" ]; then
				rm -rf "LogsFromDefaultDir.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not delete existing \"LogsFromDefaultDir.tmp\" folder in $PWD."
					echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
					error=7; return
				fi
			fi
			mkdir "LogsFromDefaultDir.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create \"LogsFromDefaultDir.tmp\" folder at $PWD.\n"
				error=7; return
			elif [ -d "LogsFromDefaultDir.tmp" ]; then
				cd "LogsFromDefaultDir.tmp"
				echo "Extracting LogsFromDefaultDir.zip from $var using \"unzip\" ..."			
				unzip -qq "../LogsFromDefaultDir.zip" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "LogsFromDefaultDir.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress LogsFromDefaultDir.zip, using \"unzip\" utility."
					echo -e "Suggesting to validate \"unzip\" manually on \"$var->LogsFromDefaultDir.zip\".\n"
					error=8; return
				else
					input="$destdir/LogsFromDefaultDir.tmp"				
					target="$target-LogsFromDefaultDir"
					destdir="$destdir/LogsFromDefaultDir.tmp"
					explore_logfolder
				fi
				cd ..
			fi
		else
			echo -e "\nWarning: found \"LogsFromDefaultDir.zip\" but unable to uncompress it due to lack of required tool: \"unzip\"\n"
		fi
	fi
else
	error=1; echo -e "\nerror: probe_LogsFromDir() was called with null string - contact developer.\n"
fi
} # probe_LogsFromDir()

function explore_logfolder () {								# explore the potential log files found in current folder
	targetfiles=""; targetX=""; xfile=""
	targetX=`ls -r -t1 SIPMessages* 2>/dev/null | egrep -v bak`
	if [[ $? != 0 ]]; then
		targetX=""

	elif [[ $((alllogs)) == 0 ]] && [[ $targetX != "" ]]; then
		targetfiles=$(tail -1 <<< $targetX)
	else
		targetfiles=$targetX
	fi

	file=""; filelist=""
	for xfile in $targetfiles
	do
		if [ -s "$xfile" ]; then
			if [[ $file == "" ]]; then					
				file="$destdir/$xfile"
			fi
			if [[ $((alllogs)) != 0 ]]; then
				if [[ $filelist == "" ]]; then
					filelist="=$destdir/$xfile"
				else
					filelist="$filelist=$destdir/$xfile"
				fi
			fi
		fi
	done
	if [[ $xfile != "" ]] && [ -s "$xfile" ]; then
		file="$destdir/$xfile"
	fi
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
	fi

	if [ -d "Avaya" ]; then									# typical usecase: %APPDATA% roaming folder
		destdir="$destdir/Avaya"
		target="$target-Avaya"
		cd "Avaya"
		if [ -d "Avaya Agent" ]; then
			destdir="$destdir/Avaya Agent"
			target="$target-AvayaAgent"
			cd "Avaya Agent"
			probe_logsFromDir				
			if [[ $file == "" ]] && [[ $filelist == "" ]]; then
				if [ -d "logs" ]; then
					destdir="$destdir/logs"
					target="$target-logs"
					cd logs
					probe_LogsFromDir
				fi
			fi
		fi

	elif [ -d "Avaya Agent" ]; then							# typical usecase: %APPDATA%\Avaya folder
		destdir="$destdir/Avaya Agent"
		target="$target-AvayaAgent"
		cd "Avaya Agent"
		probe_logsFromDir				
		if [[ $file == "" ]] && [[ $filelist == "" ]]; then
			if [ -d "logs" ]; then
				destdir="$destdir/logs"
				target="$target-logs"
				cd "logs"
				probe_LogsFromDir
			fi
		fi

	elif [ -s "AvayaAgentLogs.zip" ]; then
		if [ -d "AvayaAgentLogs" ]; then
			rm -rf "AvayaAgentLogs" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not delete existing \"AvayaAgentLogs\" folder."
				echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
				error=7
			fi
		fi
		mkdir "AvayaAgentLogs" 2>/dev/null
		if [[ $? != 0 ]]; then
			echo -e "\nerror: could not create \"AvayaAgentLogs\" folder at $PWD.\n"
			error=7
		elif [ -d "AvayaAgentLogs" ] && [[ $bUnzip != 0 ]]; then
			cd "AvayaAgentLogs"
			echo -e "\nUncompressing AvayaAgentLogs.zip ..."
			unzip -qq "../AvayaAgentLogs.zip" >/dev/null 2>&1
			if [[ $? -gt 1 ]]; then
				cd ..; rm -rf "AvayaAgantLogs" 2>/dev/null
				echo -e "\nerror: failed to uncompress AvayaAgentLogs.zip, using \"unzip\" utility. Skipping this file..."
				echo -e "Suggesting to validate \"unzip -qq AvayaAgentLogs.zip\" command manually.\n"
				error=8
			else
				target="$target-AvayaAgentLogs"
				destdir="$destdir/AvayaAgentLogs"
				probe_LogsFromDir
			fi
			if [[ $file == "" ]] && [[ $filelist == "" ]]; then
				if [ -d "logs" ]; then
					destdir="$destdir/logs"
					target="$target-logs"
					cd "logs"
					probe_LogsFromDir
				fi
			fi
		elif [[ $bUnzip == 0 ]]; then
			echo -e "\nWarning: found \"AvayaAgentLogs.zip\" but unable to uncompress it due to lack of required tool: \"unzip\"\n"		
			error=9
		fi

	elif [ -d "AvayaAgentLogs" ]; then
		cd "AvayaAgentLogs"		
		destdir="$destdir/AvayaAgentLogs"
		target="$target-AvayaAgentLogs"
		probe_LogsFromDir
		if [[ $file == "" ]] && [[ $filelist == "" ]]; then
			if [ -d "logs" ]; then
				destdir="$destdir/logs"
				target="$target-logs"
				cd "logs"
				probe_LogsFromDir
			fi
		fi

	elif [ -d "log" ] || [ -d "logs" ]; then
		if [ -d "log" ]; then
			destdir="$destdir/log"
			target="$target-log"
			cd "log"
			probe_LogsFromDir
		elif [ -d "logs" ]; then
			target="$target-logs"
			if [ -d "logs/log" ]; then
				destdir="$destdir/logs/log"
				cd "logs/log"
				probe_LogsFromDir
			else
				destdir="$destdir/logs"
				cd "logs"
				probe_LogsFromDir
			fi
		fi
	else
		probe_LogsFromDir
	fi

	if [[ $file == "" ]] && [[ $filelist == "" ]]; then
		explore_logfolder
	fi

	if [[ $file == "" ]]; then
		error=1
		echo -e "\nerror: could not find any AAfD related logs (SIPMessages*.txt) in $folder\n"
	fi
	cd "$currdir"
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts "hbf:sdACIN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	C)  
		bCAT=1;;
	A)
		alllogs=1;;
    I)
		noINFO=1;;	
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	s)
		sipstat=0;;
	d)
		bDelTemp=0;;
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
		elif [[ $var == "-N"* ]]; then
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
			findANI=$findANI		# findANI=$var
		fi
		skipper=0
		continue
	fi

	n=0; 		error=0;	tmpfile=0
	bdir="";	bvar=""; 	folder=""
	target=""; 	destdir="";	input=""	
	file=""; 	filelist="";basefile=""
	currtime=$(date +%R:%S);currdir=$PWD	

	if [[ $((fixVSYSLOG)) == 0 ]]; then
		vsyslog=0
	fi

	bSinglefile=0	
	filecontent="AAfD"	
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
		target="AAFD"
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

	elif [ -s "$var" ];then
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

		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "AAfD" ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")			
			fi

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
					echo -e "Unable to unzip $bfile into a temp folder. Skipping this file...\n"
					error=7; cd $currdir; input=""; continue
				fi
			fi

#			target=$(basename "$input")
#			target=${target%%.*}
			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bfile into a temp folder. Skipping this file...\n"
				input=""; error=7; cd $currdir; continue
			fi

			if [[ $bUnzip != 0 ]] && [ -d "$input.tmp" ]; then
				cd "$input.tmp"
				echo -e "\nUncompressing $var into $input.tmp ...                                                    "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? -gt 1 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "\nerror: failed to uncompress $bfile, using \"unzip\" utility. Skipping this file..."
					echo -e "Suggesting to validate \"unzip -qq $bfile\" command manually.\n"
					cd "$currdir"; input=""; error=8; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
#					probe_LogsFromDir
				fi

			elif [[ $filetype == "Zip archive"* ]]; then
				cd ..; rm -rf "$input.tmp" 2>/dev/null
				cd $currdir; input=""
				echo -e "\nWarning: \"unzip\" package was not found."
				echo -e "If using Ubuntu, execute \"sudo apt-get unzip install\" to deploy and re-try.\n"
				error=8; continue
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
						echo "Uncompressing $zfile into $input2 ...                                             "
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
						echo -e "\nerror: could not delete existing $input.tmp folder."
						echo -e "Check if any subfolders or files currently opened (in other shell sessions).\n"
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

	if [[ $((error)) != 0 ]]; then
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
	if [[ $((alllogs)) != 0 ]] && [[ $filelist != "" ]]; then
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
			echo "Warning: about to convert multiple files ($nfiles x SIPMessagesX.txt)."
			echo "This may take a while... You may want to execute the script on a more powerful PC or server."

#			xbfile=$(head -1 <<< "$filelist")
#			xbfile=$(basename "$xbfile")
#			if [[ $xbfile != "SIPMessages0.txt" ]]; then
#				echo "Warning: SIPMessages0.txt could be missing? Very unlikely... but to be sure, verify content of $var"
#				echo -e "Starting conversion with $xbfile instead of SIPMessages0.txt ...\n"
#			fi

			let z=0; file=""
			for file in $filelist;
			do
				if [[ $file != "" ]] && [ -s "$file" ]; then
					IFS=$origIFS
					z=$(egrep -m 1 -c -e "^CSeq:" "$file")
					if [[ $((z)) != 0 ]]; then
						convert_siplog
						if [[ $((fixVSYSLOG)) == 0 ]]; then
							vsyslog=0
						fi
					else
						bfile=$(basename "$file")
						echo -e "\n$bfile : No SIP messages have been found."
					fi
					z=0; error=0
				fi
				IFS="="; currtime=$(date +%R:%S)
			done
			
			if [[ $((bCAT)) != 0 ]] && [ -s "$ctarget" ]; then
				echo -e "All converted files found in $bvar have been concatenated into $ctarget\n"
				ls -l "$ctarget"; echo ''
			fi

		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			IFS=$origIFS
			convert_siplog
#			if [[ $((error)) == 0 ]] && [[ $((bCAT)) != 0 ]]; then
#				echo -e "Warning: Only a single file was converted, hence discarding concatenate option.\n"
#			fi
		fi
		IFS=$origIFS

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