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
pattern1='^\([0-9]{2|-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,sip,'
pattern2='<I,sip.*INCOMING|<I,sip.*OUTGOING'
# pattern2='^FINE.*% $'
# pattern3='^% '
# pattern4='^INFO|^FINE|^FINER|^FINEST'
sipstat=1
converted=0
adjusthour=0
base64decode=1
bDelTemp=1
bCAT=0
alllogs=0
noINFO=0
findANI=""
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
vsyslog=0
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
targetfiles=""
# targetfiles="sip.txt* sipmcDebug.txt*"
# vsyslog=20  ## values explained below:

## 19) AMS sipmsDebug.txt
## 20) AMS sip.txt

function usage ()  {
    echo "traceAMS.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAMS.sh <options> [<LOG_FILE> | <Troubleshooting archive> | <folder> ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the sip.txt or sipmcDebug.txt log file,"
	echo -e "\t\t\tor logreport (.zip/.tar/.tgz) collected from AAMS/MPaaS Troubleshooting Archive"
	echo -e "\t<folder>\tincludes one or more of the files extracted from a logreport (eg. sip.txt.X.bak)"
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"	
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"		
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"	
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
	sipyear=""
	sipdate=""
	siptime=""
	ip=""
	dirdefined=0
	base64found=0
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then
	sipstart=1; siplines=$((siplines+1))
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

	lastmsg="$sipword"; 	timelast="$sipdate $siptime"
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
		base64msg=$((base64msg+1))
		base64found=0		
		rm "$newfile.b64"		
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
		2)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi
} # sipmsg_header() 

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
	if [[ $line =~ INCOMING|Incoming ]]; then
		## if [[ $direction == "Inbound" ]]; then
		sipstream=5f70;					dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)	dirstring1="-->";			dirstring2="ingress";;
		esac
		##ip=$(echo $line | awk '{print $5}')
	elif [[ $line =~ OUTGOING|Outgoing ]]; then
		## elif [[ $direction == 'Outbound' ]]; then
		sipstream=1474;				dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--";		dirstring2="egress";;
		esac
		##ip=$(echo $line | awk '{print $5}')
	else
		reset_sipmsg
	fi
	
	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $((vsyslog)) == 20 ]]; then
			protocol=$(awk '{print $(NF)}' <<< "$line")
			ip=$(cut -d' ' -f4 <<< "$line" | cut -d')' -f1 | cut -d'(' -f2)			# 000000000000> INCOMING (10.20.32.81:36143) TCP
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
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
# sipua.log:
# Apr-13 05:25:21.674 INFO  [SIP-TCP-Core-PipelineThreadpool-20] SUA3 SipMessageGate  TCP - processing request: : OPTIONS sip:censysinspect@censys.io SIP/2.0 | 
# sipmcDebug.txt:
# (11-11 04:26:14.982)<I,eng,3861445440,f38ae62d-226a-37cc-8c85-86fb21a7dc0b> ENG[056:A] <conn> Incoming SIP Message: INFO sip:379bf905-da2f-11e0-882c-e36c7400a53b@135.27.211.37:5061
# sip1.txt
# (08-10 20:24:24.609)<I,sip,90983280,00000000-0000-0000-0000-000000000000> INCOMING (10.20.32.81:36143) TCP
	if [[ $((vsyslog)) == 19 ]] || [[ $((vsyslog)) == 20 ]]; then 
##		if [[ $((n)) == 0 ]]; then
##			foundipaddr=$(echo $line | cut -d' ' -f5)
			sipyear=$(cut -d'/' -f3 <<< "$today")
			sipday=$(cut -d' ' -f1 <<< "$line"   | cut -d'-' -f2)
			sipmonth=$(cut -d' ' -f1 <<< "$line" | cut -d'-' -f1 | cut -d'(' -f2)
##		fi

		sipmsec=$(cut -d' ' -f2 <<< "$line"   | cut -d')' -f1) 
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2 <<< "$sipmsec")
		sipsec=$(cut -d':' -f3 <<< "$sipmsec" | cut -d'.' -f1)
		sipmsec=$(cut -d'.' -f2 <<< "$sipmsec")
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

	case $voutput in
	1)	sipdate="$sipmonth/$sipday/$sipyear"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	2)	sipdate="$sipyear/$sipmonth/$sipday"
		siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
	3)	sipdate="$sipday/$sipmonth/$sipyear"
		siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
	esac
} # get_sip_datetime()

function convert_siptxt () {
	while IFS= read -r line
	do
		linelength=${#line}
		nlines=$((nlines+1))

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
				get_sip_datetime
			fi

			elif [[ $((insidesip)) == 0 ]]; then
				continue

			elif [[ $((dirdefined)) != 0 ]] && [[ $((insidesip)) == 1 ]]; then
				if [[ $((linelength)) == 0 ]]; then
					insidesip=2
				fi
			elif [[ $((linelength)) -gt 1 ]] && [[ $((insidesip)) == 2 ]]; then
				if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO|^CSeq:.*INFO$ ]]; then
					nINFO=$((nINFO+1))
					reset_sipmsg;
					continue
				else
					sipmsg_header							
					start_sipmsg
					insidesip=3
				fi
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
#		done <<< "$conv"
		done < "$file"
} # convert_siptxt()

function convert_sipmc () {
	while IFS= read -r line
	do
		linelength=${#line}
		nlines=$((nlines+1))

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

			if [[ $((dirdefined)) != 0 ]]; then
				siptotalmsg=$((siptotalmsg+1))
				insidesip=1 
				get_sip_datetime
			else	
				continue
			fi
#			sip_direction	

		elif [[ $((insidesip)) == 0 ]]; then
			continue

		elif [[ $((insidesip)) == 1 ]] && [[ $((linelength)) -lt 2 ]]; then
			insidesip=2
		elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -gt 1 ]]; then
			if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
				reset_sipmsg;
				continue
			else
				sipmsg_header						
				start_sipmsg
				insidesip=3
			fi
		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
				if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
					calltime=$siptime
				elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
					callID=$line; callDIR=$dirdefined
				fi
			fi
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
#	done <<< "$conv"
	done < "$file"
} # convert_sipmc()

function explore_logfolder () {
	targetfiles=""

	targetX=""; targetX=$(ls -r -t1 sipmcDebug.txt.[0-9]*.bak 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	else
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -r -t1 sip.txt.[0-9]*.bak 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetfiles != "" ]]; then
		targetfiles="$targetfiles $targetX"
	else
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -r -t1 sipmcDebug.txt 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetfiles != "" ]]; then
		targetfiles="$targetfiles $targetX"
	else
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -r -t1 sip.txt 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetfiles != "" ]]; then
		targetfiles="$targetfiles $targetX"
	else
		targetfiles=$targetX
	fi

	if [[ $((alllogs)) == 0 ]]; then
		if [[ "$targetfiles" != "" ]]; then
			targetfiles=$(tail -1 <<< $targetfiles)
		else
			targetfiles=$targetX
		fi
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
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	if [ -d "$folder" ]; then
		destdir="$destdir/$folder"
		cd "$folder"
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
		echo -e "\nerror: could not find any AMS related logs in $folder\n"	
		error=1
	fi
	cd $currdir
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; rec=0
	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "
	rec=$(egrep -c -e "^\([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,sip," "$file")

	if [[ $rec == 0 ]];	then	
		rec=$(egrep -c -e "^\([0-9]{2}\-[0-9]{2} [0-9]{2}.*<I,eng,.*ing SIP Message:.*" "$file")
		if [[ $rec == 0 ]];	then
		    echo -e "\n$basefile : No SIP messages have been found in the expected format."
			echo "This file may not be an AMS sip.txt or sipmcDebug.txt logfile... or, DEBUG loglevel was not enabled."
			error=1; rec=$(egrep -c -e ".*CSeq:.*" "$file")
			if [[ $rec == 0 ]]; then
				echo "In fact, no sign of any "CSeq:" lines within $basefile."
				error=2
			else
				echo "Though, found $rec lines with CSeq: - so there might be some SIP messages included within this file."
				rec=0
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
			rec=0			
		else
			vsyslog=19					# sipmcDebug.txt
		fi
	else
		vsyslog=20						# sip.txt
	fi

	if [[ $((vsyslog)) != 0 ]] && [[ $((rec)) != 0 ]]; then
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
		sipin=0
		sipout=0
		nINFO=0
		callID=""
		calltime=""
		callDIR=0			

        reset_sipmsg

		if [[ $rec -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages)"
			echo -e "This may take a while... You may want to execute the script on a more powerful PC or server.\n"
		fi
	
		## conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
   	    ## conv=$(awk -e '/<I,sip.*INCOMING|<I,sip.*OUTGOING/{flag=1} flag; /}/{flag=0}' $file)
		# conv=$(awk -e '/,sip,/{flag=1} flag; /}/{flag=0}' "$file")
		# conv=$(awk -W source='/,sip,/{flag=1} flag; /}/{flag=0}' "$file")		

#		if [[ $basefile == *"."* ]]; then
#			basefile=${basefile%.*}
#		fi

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
		iohist=""
		if [[ $var != $file ]]; then
			if [[ $input2 != "" ]] && [[ $file != "" ]] && [[ $file != $input2 ]]; then
				iohist="$var -> $input2 -> $basefile -> $output.asm"
			elif [[ $file != "" ]] && [[ $file != $output ]]; then
				iohist="$var -> $basefile -> $output.asm"
			fi
		else 
			iohist="$var -> $output.asm"
		fi		

		if [[ ${#iohist} -lt 48 ]]; then
			echo -e "# Input/output file history: $iohist\n" >> "$newfile"
		else
			echo -e "# Input/output file history:" >> "$newfile"
			echo -e "# $iohist\n" >> "$newfile"
		fi

		case $vsyslog in
		19) convert_sipmc;;
		20) convert_siptxt;;
		esac

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

			if [[ $((sipmsg)) != 0 ]]; then
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
		if [[ $bDelTemp != 0 ]] && [[ $tmpfile == 1 ]]; then
			rm $file					# this is already a tmp file, can be removed
		fi
		ls -l "$output.asm"
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
  while getopts "e:hbf:AICN:ST" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	e)
		endptaddr=${OPTARG};;
	A)
		alllogs=1;;
	C)
		bCAT=1;;
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
		elif [[ $((skipper)) == 3 ]]; then
			findANI=$findANI
        fi
		continue
	fi

	file="";	filelist="";	folder=""
	n=0;	error=0; bdir=""; 	bvar=""
	target=""; 	destdir="";		input=""	
	currtime=$(date +%R:%S); 	currdir=$PWD
	vsyslog=0;	bSinglefile=0;	tmpfile=0

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
		target="AMS"
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
		echo -en "\nExploring content in \"$var\" folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"

		sample=""; sample2=""
		input=""; input2=""		
		filelist=""; file="$var"
		destdir="$PWD"; filecontent=""

		filetype=$(file -b  "$file")
		filetype2=$(file -bZ "$file")

		if [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype =~ "Zip archive" ]]; then
			if [[ $bvar == *"."* ]]; then
				input=${bvar%.*}
			else
				input="$bvar"
			fi
			if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
				rm -rf "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not delete temp folder: $input.tmp in $PWD."
					echo "Check if any subfolders or files are open (in other shell sessions).\n"
					echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"					
					error=7; cd $currdir; input=""; continue
				fi
			fi

			mkdir "$input.tmp"
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD.\n"
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bvar into a temp folder. Skipping this file...\n"
				input=""; error=7; cd $currdir; continue
			fi

			if [[ $bUnzip != 0 ]] && [ -d "$input.tmp" ]; then
				cd "$input.tmp"
				if [[ $file != "" ]] && [[ $file != $var ]]; then
					bfile=$(basename "$file")
				else
					bfile=$(basename "$var")
				fi

				echo -e "\Uncompressing $bfile into $input.tmp...                                                     "
				unzip -qq "../$file" >/dev/null 2>&1
				if [[ $? != 0 ]]; then
					cd ..; rm -rf "$input.tmp" 2>/dev/null
					echo -e "\nerror: could not uncompress $bfile, using unzip. Skipping this file..."
					echo -e "Suggesting to validate \"unzip -qq $bfile\" command manually.\n"
					input=""; error=8; cd $currdir; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
				fi
			else
				if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
					cd ..; 	rm -rf "$input.tmp" 2>/dev/null					
				fi
				echo -e "\nerror: could not uncompress $bvar, \"unzip\" utility not found."
				echo -e "Suggesting to deploy \"unzip\" package. in Ubuntu, you can install it by typing: \"sudo apt install unzip\".\n"
				error=8; input=""; cd $currdir; continue
			fi

		elif [[ $filetype == *"compressed data"* ]]; then
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
						echo "Uncompressing $zfile into $input2 ...                                                    "
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
				echo "Extracting $bfile ...                                                                   "

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

	if [[ $((error)) != 0 ]]; then
		continue
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

#	if [[ $file != "" ]]; then
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
			echo -e "\nWarning: about to convert multiple files ($nfiles x sipX.txt/sipmcDebugX.txt) found in $var."
			echo -e "\nThis may take a while... you may want to execute this script on a more powerful PC or server.\n"
			let z=0; file=""
			for file in $filelist;
			do
				if [[ $file != "" ]] && [ -s "$file" ]; then
					IFS=$origIFS
					z=$(egrep -c "CSeq:" "$file")
					if [[ $z != 0 ]]; then
						convert_siplog
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
		fi
		IFS=origIFS

	elif [[ $file != "" ]]; then
		convert_siplog
	fi

	if [[ $bDelTemp != 0 ]]; then
		if [[ $input2 != "" ]] && [ -d "$input2.tmp" ]; then
			rm -rf "$input2.tmp" 2>/dev/null
		fi

		if [[ $input != "" ]]; then
			if [ -d "$intput.tmp" ]; then
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