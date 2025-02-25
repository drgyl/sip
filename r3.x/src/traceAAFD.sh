#!/bin/bash
version="2.0.0.3"
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
bDebug=1
findANI=""
findCALLID=""
filtdate=""
filterI=""; filterX=""
converted=0
let bAllINC=1
let noINFO=0
let noOPTIONS=0
let noSUBSCRIBE=0
let noPUBLISH=0
let noNOTIFY=0
let noREG=0
let noUPDATE=0
let noPONG=0
let bEVX=0
let bEXC=0
let bEVI=0
let bINC=0
let bEvPresence=0
let bEvDialog=0
let bEvCC=0
let bEvReg=0
let bEvCMstat=0
let bEvMsgSum=0
let bEvCCSprof=0
let bEvRefer=0
let bEvScrUpd=0
let bEvUAprof=0
let bEvConf=0
bIgnoreMonth=0
fixVSYSLOG=0
siplength=666
base64decode=1
voutput=1
vsyslog=0

function usage ()  {
    echo "traceAAFD.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAAFD.sh [OPTIONS] [<LOG_FILE> | <logReport> | <folder>, ...]'
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
#	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session)"		
#	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"
	echo -e "\t-N ANI|id:CallID       find a call with From/To header matching to ANI (digit string) or to CallID"
	echo -e "\t-I str1,str2,str3,...  Include only SIP requests matching with string, eg. -I INFO,ev:reg,ev:pres"	
	echo -e "\t-X str1,str2,str3,...  eXclude SIP requests matching with string eg. -X ev:pres,OPTIONS,ev:ccs-pro"
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
	echo -e " Note: -I/-X option supports these SIP methods: INFO,NOTIFY,OPTIONS,PONG,PUBLISH,REGISTER,SUBSCRIBE,UPDATE"
	echo -e "\tas well as events for PUBLISH/NOTIFY messages: ev:pres(ence), ev:dia(log), ev:reg, ev:ccs(-profile),"
	echo -e "\tev:cm-feat(ure-status), ev:cc-info, ev:message(-summary), ev:conf(erence), ev:ref(er), ev:scr(een),"
	echo -e "\tev:ua(-profile) and ev:push(-notification)"
	echo ''	
} # usage()

function reset_sipmsg () {
	insidesip=0;	sipstart=0;			dirdefined=0
	siplines=0;   	base64found=0;  	badmsg=0
#	previp="";		prevlocalip=""	
	ip="";				embedded=0
	sipdate="";			siptime="";		sipyear=""	
	linebuf=""; 		linebuf64=""
	prevcseq=$currcseq;	prevsipword=$sipword
	sipword="";			cseqword="";	currcseq=0
	prevline="notempty"; notifyrefer=0;	sipnotify=0	
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	sipword=$(cut -d' ' -f1 <<< "$line" | sed -e 's/[[:space:]]*$//')
	if [[ $sipword == "" ]]; then
		if [[ $((siplength)) == 4 ]]; then							# PONG message (empty SIP)
			sipword="PONG";	nPONG=$((nPONG+1))
		else
			echo -e "\nALERT: sipword in start_sipmsg() is null string on msgno:$sipmsg at $siptime! Contact developer."
			if [[ $line == "" ]]; then
				echo vsyslog=$vsyslog -- line#$nlines -- msgno=$sipmsg -- siptime=$siptime -- siplength=$siplength -- line is empty.
			else
				echo vsyslog=$vsyslog -- line#$nlines -- msgno=$sipmsg -- siptime=$siptime -- siplength=$siplength -- linelength=${#line} -- line=$line
			fi
		fi
	elif [[ $sipword == "SIP/2.0" ]]; then
	   sipword=$(awk -F"SIP/2.0 " '{print $2}' <<< "$line" | sed -e 's/[[:space:]]*$//' | tr -d "\r")
	elif [[ $sipword == "NOTIFY" ]]; then
		sipnotify=1
	fi
	if [[ $linebuf == "" ]]; then
		linebuf="$line"
	else
		linebuf="$linebuf\r\n$line"
	fi	
fi
} # start_sipmsg()

function complete_sipmsg () {
if [[ $((sipstart)) != 0 ]]; then
	if [[ $linebuf != "" ]] && [[ $sipword != "" ]]; then
		sipmsg=$((sipmsg+1))
		timelast="$sipdate $siptime"	

		if [[ $sipword != "" ]]; then
			lastmsg="$sipword"
			if [[ $sipwordlist != *$sipword* ]]; then
				if [[ $sipwordlist == "" ]]; then
					sipwordlist="$sipword"
				else
					sipwordlist="$sipwordlist | $sipword"
				fi
			fi

			if [[ $((sipmsg)) == 1 ]]; then
				firstmsg=$lastmsg; 	timefirst=$timelast
			fi
		fi

		if [[ $prevsiptime != "" ]]; then
			if [[ $siptime < $prevsiptime ]]; then
				badmsg=1
				if [[ $sipbadtimemsg == "" ]]; then
					sipbadtimemsg="$sipmsg $prevsiptime $siptime"
				fi
			fi
		fi
		prevsiptime=$siptime

		if [[ $siplength == 0 ]]; then
			siplength=${#linebuf}
		fi

		siplines=$(wc -l <<< "$linebuf")
		lineX=$(head -1  <<< "$linebuf")

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

		if [[ $voutput != 3 ]] || [[ $prevsipword != "PONG" && $sipword != "PONG" ]]; then
			if [[ $base64found != 0 ]]; then
				if [[ $embedded != 0 ]]; then
					echo -e "# msgno: $sipmsg (Embedded) - Base64dump found" >> "$newfile"
				else
					echo -e "# msgno: $sipmsg - Base64dump found" >> "$newfile"
				fi
			elif [[ $embedded != 0 ]]; then
				echo -e "# msgno: $sipmsg (Embedded)" >> "$newfile"
			else		
				echo -e "# msgno: $sipmsg" >> "$newfile"
			fi
		fi

		if [[ $((sipstart)) == 1 ]] && [[ $((vsyslog)) -ge 11 ]]; then
			n=$((n+1))	
			echo -e "\n# error: incomplete SIP message (sipword=$sipword) at $sipdate $siptime ($n)\n" >> "$newfile"
			if [[ $bDebug == 0 ]]; then
				echo -e "\nerror: incomplete SIP message (sipword=$sipword) at $sipdate $siptime ($n)\n"
			fi
		else	
			case $voutput in
			1)	echo -e "[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
				echo -e "{$NL[$sipstream] $lineX" >> "$newfile"
				if [[ $((base64found)) != 0 ]] && [[ $linebuf64 != "" ]]; then
					encoding=$(egrep -m 1 -e "^Content-Encoding:" <<< "$linebuf" 2>/dev/null)
					if [[ $linebuf != "" ]]; then
						lastline=$(tail -1 <<< "$linebuf")
						if [[ $lastline =~ ^\.\.\.\ unprintable ]]; then
							linebuf=$(head --lines=-1 <<< "$linebuf")
						fi
					fi
					tail -n +2 <<< "$linebuf" >> "$newfile"
					if [[ $encoding =~ gzip ]] && [[ $bGunzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | gunzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					elif [[ $encoding =~ gzip ]] && [[ $bUnzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | unzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					else
						echo "$linebuf64" | base64 -d | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					fi
					base64msg=$((base64msg+1))
					base64found=0; 	linebuf64=""
				else
					tail -n +2 <<< "$linebuf" >> "$newfile"
				fi
				echo -e "$NL[$sipstream] }\x0d$NL" >> "$newfile";;
			2)	echo -e "[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
				echo -e "$NL$lineX" >> "$newfile"
				if [[ $((base64found)) != 0 ]] && [[ $linebuf64 != "" ]]; then
					encoding=$(egrep -m 1 -e "^Content-Encoding:" <<< "$linebuf" 2>/dev/null)
					if [[ $linebuf != "" ]]; then
						lastline=$(tail -1 <<< "$linebuf")
						if [[ $lastline =~ ^\.\.\.\ unprintable ]]; then
							linebuf=$(head --lines=-1 <<< "$linebuf")
						fi
					fi
					tail -n +2 <<< "$linebuf" >> "$newfile"
					if [[ $encoding =~ gzip ]] && [[ $bGunzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | gunzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					elif [[ $encoding =~ gzip ]] && [[ $bUnzip != 0 ]]; then
						sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | unzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					else
						echo "$linebuf64" | base64 -d | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
					fi
					base64msg=$((base64msg+1))
					base64found=0; 	linebuf64=""
				else
					tail -n +2 <<< "$linebuf" >> "$newfile"
				fi
				echo -e "$NL}$NL"       >> "$newfile";;
			3)	if [[ ! $sipword =~ PONG ]] || [[ $siplength != 4 ]]; then
					echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile"
					echo -e "$lineX"    >> "$newfile"	
					if [[ $((base64found)) != 0 ]] && [[ $linebuf64 != "" ]]; then
						encoding=$(egrep -m 1 -e "^Content-Encoding:" <<< "$linebuf" 2>/dev/null)
						if [[ $linebuf != "" ]]; then
							lastline=$(tail -1 <<< "$linebuf")
							if [[ $lastline =~ ^\.\.\.\ unprintable ]]; then
								linebuf=$(head --lines=-1 <<< "$linebuf")
							fi
						fi
						tail -n +2 <<< "$linebuf" >> "$newfile"
						if [[ $encoding =~ gzip ]] && [[ $bGunzip != 0 ]]; then
							sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | gunzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
						elif [[ $encoding =~ gzip ]] && [[ $bUnzip != 0 ]]; then
							sed -e 's/\\r\\n//g' <<< "$linebuf64" | base64 -d | unzip 2>/dev/null | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
						else
							echo "$linebuf64" | base64 -d | sed 's/>\s*</>\n</g' | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g' >> "$newfile"
						fi
						base64msg=$((base64msg+1))
						base64found=0; 	linebuf64=""
					else
						tail -n +2 <<< "$linebuf" >> "$newfile"
					fi
					echo -e "--------------------" >> "$newfile"
				elif [[ $dirdefined == 1 ]]; then
					echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}octets: $siplength, Body Length: 0${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}SIPMsgContext: [NONE]${NL}--------------------" >> "$newfile"
					echo "${NL}${NL}" >> "$newfile"
				else
					echo -e "com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}octets: $siplength, Body Length: 0${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}SIPMsgContext: [NONE]${NL}--------------------" >> "$newfile"
					echo "${NL}" >> "$newfile"
				fi;;
			esac
		fi

		if [[ $foundipaddr != "" ]]; then
			lastfoundip="$foundipaddr"
		elif [[ $dirdefined == 2 ]]; then
			contacthdr=""; contactip=""
			contacthdr=$(egrep -m 1 -e "^Contact:" <<< "$linebuf" 2>/dev/null)
			if [[ $contacthdr != "" ]]; then
				contactip=$(cut -d '@' -f2 <<< "$contacthdr" | cut -d ';' -f1)
				if [[ $contactip != "" ]] && [[ ! $contactip =~ 127\.0 ]]; then
					lastfoundip="$contactip"
				fi
			fi
		fi

		get_useragent4

		if [[ $((badmsg)) != 0 ]]; then
			echo -e "# This is a BAD message\n" >> "$newfile"
			sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadmsgnum == "" ]]; then
				sipbadmsgnum="$siptotalmsg $siptime"
			fi
		fi

    	reset_sipmsg

	else															# cannot complete a SIP message unless it started properly
		badmsg=1; sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadmsgnum == "" ]]; then
			sipbadmsgnum="$siptotalmsg $siptime"
		fi
	fi

elif [[ $bDebug == 0 ]]; then
	echo -e "\nerror: complete_sipmsg() was called with \$sipstart=0 at msgno: $sipmsg at $sipdate $siptime. Contact developer."
	exit 1
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
				echo -en "$var => $n/$rec Msgs converted                 \r"
			fi
		fi

#		case $voutput in
#		1)	echo -e "# msgno: $((sipmsg+1))${NL}[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
#		2)	echo -e "# msgno: $((sipmsg+1)){$NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
#		3)	echo -e "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/$protocol/ }${NL}--------------------" >> "$newfile";;
#		esac
	fi

elif [[ $bDebug == 0 ]]; then
	echo -e "\nerror: sipmsg_header() was called with \$dirdefined=0 at msgno: $sipmsg at $sipdate $siptime. Contact developer.\n"
	exit 1
fi
} # sipmsg_header() 

function multi_sipmsg () {
	if [[ $bDebug == 0  ]]; then
		echo -e "\n\ndebug: multiple SIP message at line#$nlines found at $siptime and notiref=$notifyrefer"
		echo $line	
	fi

	multimsg=$((multimsg+1))
	case $dirdefined in
	1)	multimsgin=$((multimsgin+1));;
	2)	multimsgout=$((multimsgout+1));;
	esac
	psipdate=$sipdate; 		psiptime=$siptime
	pinsidesip=$insidesip;	psipstart=$sipstart;	pdirdefined=$dirdefined
	pip=$ip;				plocalip=$localip
	embedded=1
	complete_sipmsg

	sipdate=$psipdate;		siptime=$psiptime
	insidesip=$pinsidesip; 	dirdefined=$pdirdefined
	ip=$pip; localip=$plocalip; base64found=0
	siptotalmsg=$((siptotalmsg+1))			
	sipmsg_header
	start_sipmsg
	sipstart=$psipstart;
	prevline="$line"
	linebuf="$line"	
} # multi_sipmsg()

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line =~ RECEIVED ]]; then
		sipstream=5f70; 			dirdefined=1
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->";		dirstring2="ingress";;
		esac

	elif [[ $line =~ SENT|SENDING ]]; then
		sipstream=1474; 			dirdefined=2
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
	else
		echo -e "\nerror: direction of message could not be determined from $line at msgno: $sipmsg. Contact developer.\n"
	    reset_sipmsg
	fi

	if [[ $((dirdefined)) != 0 ]]; then
		case $vsyslog in
		10) ip=$(awk '{print $9}' <<< "$line")								# cut -d' ' -f10)
			siplength=$(awk '{printf "%i",$NF}' <<< "$line");;
		11)	ip=$(awk '{print $8}' <<< "$line" | sed -e 's/\.$//g')			# cut -d' ' -f10)
			siplength=$(awk '{printf "%i",$NF}' <<< "$line");;			
		12) ip=$(awk '{print $7}' <<< "$line" | sed -e 's/\.$//g')			# cut -d' ' -f10)
			siplength=$(awk '{printf "%i",$4}' <<< "$line");;
		esac
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

function get_useragent4 () {
	case $dirdefined in
	1) 	if [[ $scua == "" ]] && [[ $sipword == "INFO" ]]; then
			scip=""; sccontact=""
			scua=$(egrep -m 1 "^User-Agent" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
			if [[ $scua != "" ]]; then
				sccontact=$(egrep -m 1 "^Contact:" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
				if [[ $sccontact != "" ]]; then
					scip=$(awk -F "Contact:" '{print $2}' <<< "$sccontact"| cut -d ';' -f1 | cut -d '@' -f2)
				fi
			fi
		fi
		serverua=$(egrep -m 1 -e "^Server:" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
		if [[ $serverua != "" ]]; then
#			serverua=$(awk -F'Server: ' '{print $2}' <<< "$serverua" | tr -d "\r\n")
			if [[ ! $serverua =~ Presence ]]; then
				if [[ $server == "" ]]; then
					server="$serverua"; serverip="$ip"
				elif [[ ${#serverua} -gt ${#server} ]]; then
					server="$serverua"; serverip="$ip"
				fi
			fi
		fi;;
	2)	if [[ $useragent == "" ]]; then
			useragent=$(egrep -m 1 "^User-Agent" <<< "$linebuf" 2>/dev/null | tr -d "\r\n")
#			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$useragent"  | tr -d "\r\n")
		fi;;
	esac
} # get_useragent4()

function get_sip_datetime () {
# AAFD:  2022-05-20 09:33:24.326 DBH [13536] SIGNAL | SENT to 10.134.117.194:5061. Length= 604.
# 1XC:	 [04/27/2022 20:21:23:545] DBH:     SIGNAL: [be84] SENT to 135.64.253.72:5061. Length= 696.
# ACIOS: [2016/09/26 11:37:16:715] SENDING 740 bytes to 198.152.66.101:5061 {
	if [[ $line =~ DBH: ]] && [[ ${line:0:1} == '[' ]]; then												# 1XC
    	sipday=$(cut -d' ' -f1   <<< "$line" | cut -d'[' -f2)
		sipyear=$(cut -d'/' -f3  <<< "$sipday")
		sipmonth=$(cut -d'/' -f1 <<< "$sipday")
	    sipday=$(cut -d'/' -f2   <<< "$sipday")
									
		sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d']' -f1)
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d':' -f4 <<< "$sipmsec")

	elif [[ $line =~ DBH ]]; then
    	sipday=$(cut -d' ' -f1   <<< "$line")
		sipyear=$(cut -d'-' -f1  <<< "$sipday")
		sipmonth=$(cut -d'-' -f2 <<< "$sipday")
	    sipday=$(cut -d'-' -f3   <<< "$sipday")
									
		sipmsec=$(cut -d' ' -f2 <<< "$line")
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1  <<< "$sipsec")

	elif [[ $line =~ \]\ R|SE ]]; then																		# ACiOS
    	sipday=$(cut -d' ' -f1   <<< "$line" | cut -d'[' -f2)
		sipyear=$(cut -d'/' -f1  <<< "$sipday")
		sipmonth=$(cut -d'/' -f2 <<< "$sipday")
	    sipday=$(cut -d'/' -f3   <<< "$sipday")
									
		sipmsec=$(cut -d' ' -f2 <<< "$line" | cut -d']' -f1)
		siphour=$(cut -d':' -f1 <<< "$sipmsec")
		sipmin=$(cut -d':' -f2  <<< "$sipmsec")
		sipsec=$(cut -d':' -f3  <<< "$sipmsec")
		sipmsec=$(cut -d':' -f4 <<< "$sipmsec")
	fi

	if [[ $sipyear != "" ]]; then
		case $voutput in
		1)	sipdate="$sipmonth/$sipday/$sipyear"
			siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
		2)	sipdate="$sipyear/$sipmonth/$sipday"
			siptime="$siphour:$sipmin:$sipsec:$sipmsec";;
		3)	sipdate="$sipday/$sipmonth/$sipyear"
			siptime="$siphour:$sipmin:$sipsec.$sipmsec";;
		esac
	else
		echo -e "\nerror: could not extract date/time from SIP message header line at msg#$n. Contact developer."
		echo $line; echo ''
	fi
} # get_sip_datetime()

function reset_filters () {
	bAllINC=1; bEVX=0; bEVI=0
	noINFO=0; noOPTIONS=0; noUPDATE=0; noREG=0; noPONG=0
	noSUBSCRIBE=0; noPUBLISH=0; noNOTIFY=0
		
	bEvPresence=0;	bEvDialog=0; bEvCC=0
	bEvReg=0; bEvCMstat=0; bEvMsgSum=0
	bEvCCSprof=0; bEvRefer=0; bEvPush=0
	bEvScrUpd=0; bEvUAprof=0; bEvConf=0
} # reset_filters()

function explore_filters () {
if [[ $filterX != "" ]]; then
#	declare -A filtarr
	filt="";		evfilt=""
	oldIFS=$IFS; 	IFS=','
	bEVX=0; 		bEXC=0

	read -ra filtarr <<< "$filterX"
	for filt in "${filtarr[@]}"
	do
		if [[ $filt =~ ev:|EV:|Ev:|eV: ]]; then
			filt="${filt,,*}"																			# lowercase
#		else
#			filt="${filt^^*}"																			# uppercase
		fi
		if [[ $filt =~ ev: ]]; then
			case ${filt/ev:/} in
			all|any) 	bEVX=1; bEXC=1
						bEvPresence=1; bEvDialog=1; bEvReg=1; bEvMsgSum=1; bEvScrUpd=1; bEvUAprof=1; bEvConf=1
						bEvCC=1; bEvCCSprof=1; bEvCMstat=1; bEvRefer=1; bEvPush=1;;
			pres*)
				if [[ $bEvPresence == 2 ]]; then
					echo "error: ev:presence was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPresence == 1 ]]; then
					echo "warning: ev:presence was already specified by -X option."
				else
					bEvPresence=1; bEVX=1; bEXC=1
				fi;;
			dia*)
				if [[ $bEvDialog == 2 ]]; then
					echo "error: ev:dialog was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvDialog == 1 ]]; then
					echo "warning: ev:dialog was already specified by -X option."
				else
					bEvDialog=1; bEVX=1; bEXC=1
				fi;;
			reg)
				if [[ $bEvReg == 2 ]]; then
					echo "error: ev:cc-info was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvReg == 1 ]]; then
					echo "warning: ev:cc-info was already specified by -X option."
				else
					bEvReg=1; bEVX=1; bEXC=1
				fi;;
			mwi|message*)
				if [[ $bEvMsgSum == 2 ]]; then
					echo "error: ev:message-summary was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvMsgSun == 1 ]]; then
					echo "warning: ev:message-summary was already specified by -X option."
				else
					bEvMsgSum=1; bEVX=1; bEXC=1
				fi;;
			cc-info*|avaya-cm-cc-*)
				if [[ $bEvCC == 2 ]]; then
					echo "error: ev:cc-info was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCC == 1 ]]; then
					echo "warning: ev:cc-info was already specified by -X option."
				else
					bEvCC=1; bEVX=1; bEXC=1
				fi;;
			ccs|ccs-prof*|avaya-cm-ccs-prof*)
				if [[ $bEvCCSprof == 2 ]]; then
					echo "error: ev:ccs-prof was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCCSprof == 1 ]]; then
					echo "warning: ev:ccs-prof was already specified by -X option."
				else
					bEvCCSprof=1; bEVX=1; bEXC=1
				fi;;
			cm-feat|avaya-cm-feat)
				if [[ $bEvCMstat == 2 ]]; then
					echo "error: ev:cm-feature was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCMstat == 1 ]]; then
					echo "warning: ev:cm-feature was already specified by -X option."
				else
					bEvCMstat=1; bEVX=1; bEXC=1
				fi;;
			push*|avaya-push*)
				if [[ $bEvPush == 2 ]]; then
					echo "error: ev:push-notification was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPush == 1 ]]; then
					echo "warning: ev:push-notification was already specified by -X option."
				else
					bEvPush=1; bEVX=1; bEXC=1
				fi;;
			scr*|screen-update)
				if [[ $bEvScrUpd == 2 ]]; then
					echo "error: ev:screen-update was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvScrUpd == 1 ]]; then
					echo "warning: ev:screen-update was already specified by -X option."
				else
					bEvScrUpd=1; bEVX=1; bEXC=1
				fi;;
			ua*|ua-profile)
				if [[ $bEvUAprof == 2 ]]; then
					echo "error: ev:ua-profile was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvUAprof == 1 ]]; then
					echo "warning: ev:ua-profile was already specified by -X option."
				else
					bEvUAprof=1; bEVX=1; bEXC=1
				fi;;
			conf*)
				if [[ $bEvConf == 2 ]]; then
					echo "error: ev:conf was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvConf == 1 ]]; then
					echo "warning: ev:conf was already specified by -X option."
				else
					bEvConf=1; bEVX=1; bEXC=1
				fi;;				
			ref*)
				if [[ $bEvRefer == 2 ]]; then
					echo "error: ev:refer was already specified by -I option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvRefer == 1 ]]; then
					echo "warning: ev:refer was already specified by -X option."
				else
					bEvRefer=1; bEVX=1; bEXC=1
				fi;;
			*)
				echo "Warning: \"ev:\" string in -X option includes an unrecognized value: $filt"
				echo "Supporting pres(ence), dia(log), cc-info, reg, message(-summary), ccs-prof(ile), cm-feat(ure-status), refer"
				echo "push(-notification), screen(-update), ua(-profile)";;
			esac

		else case ${filt^^*} in 
		INFO)
			if [[ $noINFO == 2 ]]; then
				echo "error: INFO was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noINFO == 1 ]]; then
				echo "warning: INFO was already specified by -X option."
			else
				noINFO=1; bEXC=1
			fi;;
		OPTIONS)
			if [[ $noOPTIONS == 2 ]]; then
				echo "error: INFO was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noOPTIONS == 1 ]]; then
				echo "warning: INFO was already specified by -X option."
			else
				noOPTIONS=1; bEXC=1
			fi;;
		SUB*)
			if [[ $noSUBSCRIBE == 2 ]]; then
				echo "error: SUBSCRIBE was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noSUBSCRIBE == 1 ]]; then
				echo "warning: SUBSCRIBE was already specified by -X option."
			else
				noSUBSCRIBE=1; bEXC=1
			fi;;
		PUB*)
			if [[ $noPUBLISH == 2 ]]; then
				echo "error: PUBLISH was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noPUBLISH == 1 ]]; then
				echo "warning: PUBLISH was already specified by -X option."
			else
				noPUBLISH=1; bEXC=1
			fi;;
		NOTIFY)
			if [[ $noNOTIFY == 2 ]]; then
				echo "error: NOTIFY was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noNOTIFY == 1 ]]; then
				echo "warning: NOTIFY was already specified by -X option."
			else
				noNOTIFY=1; bEXC=1
			fi;;
		UPDATE)
			if [[ $noUPDATE == 2 ]]; then
				echo "error: UPDATE was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noUPDATE == 1 ]]; then
				echo "warning: UPDATE was already specified by -X option."
			else
				noUPDATE=1; bEXC=1
			fi;;
		PONG)
			if [[ $noPONG == 2 ]]; then
				echo "error: UPDATE was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noPONG == 1 ]]; then
				echo "warning: UPDATE was already specified by -X option."
			else
				noPONG=1; bEXC=1
			fi;;
		REG*)
			if [[ $noREG == 2 ]]; then
				echo "error: REGISTER was already specified by -I option.  Review your filters and take correction."
				exit 1
			elif [[ $noREG == 1 ]]; then
				echo "warning: REGISTER was already specified by -X option."
			else
				noREG=1; bEXC=1
			fi;;
		*)
			echo "Warning: -X option includes unrecognized value(s): $filt"
			echo "Supported strings are INFO, OPTIONS, NOTIFY, PUBLISH, REG(ISTER), SUB(SCRIBE), UPDATE.";;	
		esac
		fi
	done
	IFS=$oldIFS; filterX=""
fi

if [[ $filterI != "" ]]; then
#	declare -A filtarr
	if [[ $filterI =~ only: ]]; then
		bAllINC=0
		filterI="${filterI/only:/}"
	elif [[ $filterI =~ ONLY: ]]; then
		bAllINC=0
		filterI="${filterI/ONLY:/}"
	fi

	filt=""; 		evfilt="";
	bEVI=0; 		bINC=0
	oldIFS=$IFS; 	IFS=','

	read -ra filtarr <<< "$filterI"
	for filt in "${filtarr[@]}"
	do
		if [[ $filt =~ ev:|EV:|Ev:|eV: ]]; then
			filt="${filt,,*}"
#		else
#			filt="${filt^^*}"
		fi
		if [[ $filt =~ ev: ]]; then
			case ${filt/ev:/} in
			all|any)	bEVI=1; bINC=1
						bEvPresence=2; bEvDialog=2; bEvReg=2; bEvMsgSum=2; bEvScrUpd=2; bEvUAprof=2; bEvConf=2
						bEvCC=2; bEvCCSprof=2; bEvCMstat=2; bEvRefer=2; bEvPush=2;;
			pres*)
				if [[ $bEvPresence == 1 ]]; then
					echo "error: ev:presence was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPresence == 2 ]]; then
					echo "warning: ev:presence was already specified by -I option."
				else
					bEvPresence=2; bEVI=1; bINC=1
				fi;;
			dia*)
				if [[ $bEvDialog == 1 ]]; then
					echo "error: ev:dialog was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvDialog == 2 ]]; then
					echo "warning: ev:dialog was already specified by -I option."
				else
					bEvDialog=2; bEVI=1; bINC=1
				fi;;
			reg)
				if [[ $bEvReg == 1 ]]; then
					echo "error: ev:cc-info was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvReg == 2 ]]; then
					echo "warning: ev:cc-info was already specified by -I option."
				else
					bEvReg=2; bEVI=1; bINC=1
				fi;;
			message*)
				if [[ $bEvMsgSum == 1 ]]; then
					echo "error: ev:message-summary was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvMsgSun == 2 ]]; then
					echo "warning: ev:message-summary was already specified by -I option."
				else
					bEvMsgSum=2; bEVI=1; bINC=1
				fi;;
			cc-info*|avaya-cm-cc-*)
				if [[ $bEvCC == 1 ]]; then
					echo "error: ev:cc-info was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCC == 2 ]]; then
					echo "warning: ev:cc-info was already specified by -I option."
				else
					bEvCC=2; bEVI=1; bINC=1
				fi;;
			ccs*|avaya-cm-ccs*)
				if [[ $bEvCCSprof == 1 ]]; then
					echo "error: ev:ccs-prof was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCCSProf == 2 ]]; then
					echo "warning: ev:ccs-prof was already specified by -I option."
				else
					bEvCCSprof=2; bEVI=1; bINC=1
				fi;;
			cm-feat*|avaya-cm-feat*)
				if [[ $bEvCMstat == 1 ]]; then
					echo "error: ev:cm-feature was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvCMstat == 2 ]]; then
					echo "warning: ev:cm-feature was already specified by -I option."
				else
					bEvCMstat=2; bEVI=1; bINC=1
				fi;;
			push*|avaya-push*)
				if [[ $bEvPush == 1 ]]; then
					echo "error: ev:push-notification was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvPush == 2 ]]; then
					echo "warning: ev:push-notification was already specified by -I option."
				else
					bEvPush=2; bEVI=1; bINC=1
				fi;;
			scr*|screen-update)
				if [[ $bEvScrUpd == 1 ]]; then
					echo "error: ev:screen-update was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvScrUpd == 2 ]]; then
					echo "warning: ev:screen-update was already specified by -I option."
				else
					bEvScrUpd=2; bEVI=1; bINC=1
				fi;;
			ua*|ua-profile)
				if [[ $bEvUAprof == 1 ]]; then
					echo "error: ev:ua-profile was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvUAprof == 2 ]]; then
					echo "warning: ev:ua-profile was already specified by -I option."
				else
					bEvUAprof=2; bEVI=1; bINC=1
				fi;;
			conf*)
				if [[ $bEvConf == 1 ]]; then
					echo "error: ev:conf was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvConf == 2 ]]; then
					echo "warning: ev:conf was already specified by -I option."
				else
					bEvConf=2; bEVI=1; bINC=1
				fi;;				
			ref*)
				if [[ $bEvRefer == 1 ]]; then
					echo "error: ev:refer was already specified by -X option.  Review your filters and take correction."
					exit 1
				elif [[ $bEvRefer == 2 ]]; then
					echo "warning: ev:refer was already specified by -I option."
				else
					bEvRefer=2; bEVI=1; bINC=1
				fi;;
			*)	
				echo "Warning: \"ev:\" string in -I option includes unrecognized value(s): $filt"
				echo "Supporting pres(ence), dia(log), cc-info, reg, message(-summary), ccs-prof(ile), cm-feat(ure-status), refer"
				echo "push(-notification), screen(-update), ua(-profile)";;
			esac

		else case ${filt^^*} in 
		INFO)
			if [[ $noINFO == 1 ]]; then
				echo "error: INFO was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noINFO == 2 ]]; then
				echo "warning: INFO was already specified by -I option."
			else
				noINFO=2; bINC=1
			fi;;
		OPTIONS)
			if [[ $noOPTIONS == 1 ]]; then
				echo "error: INFO was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noOPTIONS == 2 ]]; then
				echo "warning: INFO was already specified by -I option."
			else
				noOPTIONS=2; bINC=1
			fi;;
		SUB*)
			if [[ $noSUBSCRIBE == 1 ]]; then
				echo "error: SUBSCRIBE was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noSUBSCRIBE == 2 ]]; then
				echo "warning: SUBSCRIBE was already specified by -I option."
			else
				noSUBSCRIBE=2; bINC=1
			fi;;
		PUB*)
			if [[ $noPUBLISH == 1 ]]; then
				echo "error: PUBLISH was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noPUBLISH == 2 ]]; then
				echo "warning: PUBLISH was already specified by -I option."
			else
				noPUBLISH=2; bINC=1
			fi;;
		NOTIFY)
			if [[ $noNOTIFY == 1 ]]; then
				echo "error: NOTIFY was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noNOTIFY == 2 ]]; then
				echo "warning: NOTIFY was already specified by -I option."
			else
				noNOTIFY=2; bINC=1
			fi;;
		UPDATE)
			if [[ $noUPDATE == 1 ]]; then
				echo "error: UPDATE was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noUPDATE == 2 ]]; then
				echo "warning: UPDATE was already specified by -I option."
			else
				noUPDATE=2; bINC=1
			fi;;
		PONG)
			if [[ $noPONG == 1 ]]; then
				echo "error: UPDATE was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noPONG == 2 ]]; then
				echo "warning: UPDATE was already specified by -I option."
			else
				noPONG=2; bINC=1
			fi;;
		REG*)
			if [[ $noREG == 1 ]]; then
				echo "error: REGISTER was already specified by -X option.  Review your filters and take correction."
				exit 1
			elif [[ $noREG == 2 ]]; then
				echo "warning: REGISTER was already specified by -I option."
			else
				noREG=2; bINC=1
			fi;;
		*)
			echo "Warning: -X option includes unrecognized value(s): $filt"
			echo "Supported strings are INFO, OPTIONS, NOTIFY, PUBLISH, REG(ISTER), SUB(SCRIBE), UPDATE.";;	
		esac
		fi
	done
	IFS=$oldIFS; filterI=""
fi
} # explore_filters()

function validate_sipmsg () {
	let ncseq=0
	let nrseq=0
	ncseq=$(egrep -ce "^CSeq:"    <<< "$linebuf" 2>/dev/null)
	nrseq=$(egrep -ce "^RSeq:"    <<< "$linebuf" 2>/dev/null)

	if [[ $((ncseq)) == 0 ]] || [[ $cseqline == "" ]]; then
		if [[ $siplength != 4 ]]; then
			passed=0; sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadtimemsg == "" ]]; then
				sipbadtimemsg="$siptime"
			fi
			echo -e "\nALERT: Found a SIP message without a CSeq: header - $sipword in msgno#$sipmsg at $siptime. Contact developer.\n"
			echo $linebuf
		fi

	elif [[ $((ncseq)) -gt 1 ]]; then
		passed=0; sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadtimemsg == "" ]]; then
			sipbadtimemsg="$siptime"
		fi
		echo -e "\nALERT: Found a SIP message with multiple CSeq: headers ($ncseq) - $sipword in msgno#$sipmsg  at $siptime. Contact developer.\n"

#	elif [[ $prevsipword == $sipword ]] && [[ $prevcseq == $currcseq ]]; then
#		if [[ $ip == $previp ]] && [[ $localip == $prevlocalip ]]; then
#			passed=0
#			echo -e "\nALERT: Found duplicate SIP message (two SIP requests with same CSeq:) - $sipword : $cseqline in msgno#$sipmsg at $siptime. Contact developer.\n"
#		fi

	elif [[ ${#cseqword} -lt 3 ]]; then						 # SIP msg without CSeq: is considered invalid
		passed=0; sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadtimemsg == "" ]]; then
			sipbadtimemsg="$siptime"
		fi
		echo -e "\nALERT: Found a SIP message with an invalid CSeq: header - $sipword : $cseqline in msgno#$sipmsg at $siptime. Contact developer.\n"

	elif [[ $((nrseq)) != 0 ]]; then
		if [[ $((nrseq)) != 1 ]]; then
			passed=0; sipbadmsg=$((sipbadmsg+1))
			if [[ $sipbadtimemsg == "" ]]; then
				sipbadtimemsg="$siptime"
			fi
			echo -e "\nALERT: Found a SIP message with multiple RSeq: headers - $sipword in msgno#$sipmsgat $siptime. Contact developer.\n"
		else
# TODO: validate RSeq counter and/or seq# number and string		
			rseqline=""; rseqline=$(egrep -m 1 -e "^RSeq:"  <<< "$linebuf" 2>/dev/null | tr -d '\r')
#			rseqword=""; rseqword=$(cut -d' ' -f3 <<< "$rseqline" | tr -d '\r') # ; rseqword=${rseqword//'\r\n'$//}			
			rseq=0; rseq=$(awk '{print $2}' <<< "$rseqline")
			if [[ $((rseq)) -lt 1 ]]; then
				passed=0; sipbadmsg=$((sipbadmsg+1))
				if [[ $sipbadtimemsg == "" ]]; then
					sipbadtimemsg="$siptime"
				fi
				echo -e "\nALERT: Found a SIP message with an invalid RSeq: header - $sipword : $rseqline at $siptime. Contact developer.\n"
			fi
		fi

	elif [[ ! $sipword =~ ^[A-Z]+|^[1-7][0-9][0-9]\ |^SIP\/2.0\  ]]; then					# invalid $sipword
		passed=0;sipbadmsg=$((sipbadmsg+1))
		if [[ $sipbadtimemsg == "" ]]; then
			sipbadtimemsg="$siptime"
		fi
		echo -e "\nALERT: Found a SIP msg with an unknown or invalid SIP request - $sipword in msgno#$sipmsg at $siptime. Contact developer.\n"

	elif [[ $filtdate != "" ]]; then
		if [[ ! $sipday =~ ${filtdate:2:2} ]]; then
			passed=0
		elif [[ ! $sipmonth =~ ${filtdate:0:2} ]]; then
			passed=0
		fi
	fi

	if [[ $passed != 0 ]] && [[ $userext != "" ]]; then
		fromhdr=""; tohdr="";
		fromhdr=$(egrep -m 1 "^From:" <<< "$linebuf" 2>/dev/null)
		tohdr=$(egrep -m 1 "^To:" <<< "$linebuf" 2>/dev/null)
		if [[ ! $fromhdr =~ $userext ]] && [[ ! $tohdr =~ $userext ]]; then
			passed=0
		fi
	fi
} # validate_sipmsg()

function ignore_sipmsg () {
	notpassed=$((notpassed+1))
	case $dirdefined in
	1) notpassedin=$((notpassedin+1));;
	2) notpassedout=$((notpassedout+1));;
	esac		

	if [[ $sipword == "INFO" ]]; then
		nINFO=$((nINFO+1))
		case $dirdefined in
		1) infoin=$((infoin+1));;
		2) infoout=$((infoout+1));;
		esac
	fi

	echo "# msgno: $siptotalmsg (not passed) - $sipdate $siptime $dirstring1 $dirstring2 $ip" >> "$newfile"
	if [[ $eventstr == "" ]]; then
		echo -e "# $(head -1 <<< "$linebuf" | tr -d '\r') / $cseqline\n" >> "$newfile"		
	else
		echo -e "# $(head -1 <<< "$linebuf" | tr -d '\r') / $cseqline / $eventstr\n" >> "$newfile"
	fi

	reset_sipmsg
	currcseq=0; cseqword=""	
} # ignore_sipmsg()

function explore_sipmsg () {
if [[ $linebuf != "" ]]	; then
	passed=1
	currcseq=0; cseqline="";	cseqword=""

#	linebkup="$line"																			# last line of the SIP msg
	linebuf=$(sed 's/\\r\\n/\n/g' <<< "$linebuf")
	cseqline=$(egrep -m 1 -e "^CSeq:"  <<< "$linebuf" 2>/dev/null | tr -d '\r')
#	cseqline=$(egrep -m 1 -e "^CSeq:"  <<< "$linebuf" 2>/dev/null); cseqline=${cseqline//'\r\n$'/}
	currcseq=$(cut -d' ' -f2 <<< "$cseqline")
	cseqword=$(cut -d' ' -f3 <<< "$cseqline" | tr -d '\r') # ; cseqword=${cseqword//'\r\n'$//}
#	cseqword=$(awk '{print $3}' <<< "$cseqline" | tr -d [:cntrl:])

	validate_sipmsg

	if [[ $passed == 0 ]]; then
		ignore_sipmsg

	elif [[ $bINC != 0 ]] || [[ $bEXC != 0 ]]; then
		ipassed=0; xpassed=1; match=0; eventstr=""
		evcheck=0; evseqcheck=0; evtype=0; evmatch=0

		if [[ $passed != 0 ]]; then
			case $sipword in
			INFO)		if [[ $noINFO == 1 ]]; 		then match=1; xpassed=0;	elif [[ $noINFO == 2 ]];	then match=1; ipassed=1; fi;;
			OPTIONS)	if [[ $noOPTIONS == 1 ]];	then match=1; xpassed=0;	elif [[ $noOPTIONS == 2 ]]; then match=1; ipassed=1; fi;;
			REGISTER)	if [[ $noREG == 1 ]];		then match=1; xpassed=0;	elif [[ $noREG == 2 ]];		then match=1; ipassed=1; fi;;
			UPDATE)		if [[ $noUPDATE == 1 ]];	then match=1; xpassed=0;	elif [[ $noUPDATE == 2 ]];	then match=1; ipassed=1; fi;;
			PONG)		if [[ $noPONG == 1 ]];		then match=1; xpassed=0;	elif [[ $noPONG == 2 ]];	then match=1; ipassed=1; fi;;
			SUBSCRIBE)	if [[ $noSUBSCRIBE == 1 ]]; then match=1; xpassed=0;	elif [[ $noSUBSCRIBE == 2 ]]; then match=1; ipassed=1; fi
						if [[ $bEVI == 1 ]]; 		then evcheck=2; evtype=1;	elif [[ $bEVX == 1 ]];		then evcheck=1; evtype=1; fi;;
			PUBLISH)	if [[ $noPUBLISH == 1 ]];	then match=1; xpassed=0;	elif [[ $noPUBLISH == 2 ]]; then match=1; ipassed=1; fi
						if [[ $bEVI == 1 ]];		then evcheck=2; evtype=2;	elif [[ $bEVX == 1 ]]; 		then evcheck=1; evtype=2; fi;;
			NOTIFY)		if [[ $noNOTIFY == 1 ]]; 	then match=1; xpassed=0;	elif [[ $noNOTIFY == 2 ]];	then match=1; ipassed=1; fi
						if [[ $bEVI == 1 ]]; 		then evcheck=2; evtype=3;	elif [[ $bEVX == 1 ]]; 		then evcheck=1; evtype=3; fi
#			*)			if [[ $bINC != 0 ]] && [[ $bAllINC == 1 ]]; then ipassed=1; fi;;
			esac
			if [[ $match == 0 ]] && [[ $evtype == 0 ]]; then
				case $cseqword in
				INFO)		if [[ $noINFO == 1 ]]; 		then match=1; xpassed=0; 	elif [[ $noINFO == 2 ]];	then match=1; ipassed=1; fi;;
				OPTIONS)	if [[ $noOPTIONS == 1 ]];	then match=1; xpassed=0; 	elif [[ $noOPTIONS == 2 ]]; then match=1; ipassed=1; fi;;
				REGISTER)	if [[ $noREG == 1 ]];		then match=1; xpassed=0; 	elif [[ $noREG == 2 ]];		then match=1; ipassed=1; fi;;
				UPDATE)		if [[ $noUPDATE == 1 ]];	then match=1; xpassed=0; 	elif [[ $noUPDATE == 2 ]];	then match=1; ipassed=1; fi;;
				PONG)		if [[ $noPONG == 1 ]];		then match=1; xpassed=0; 	elif [[ $noPONG == 2 ]];	then match=1; ipassed=1; fi;;			
				SUBSCRIBE)	if [[ $noSUBSCRIBE == 1 ]]; then match=1; xpassed=0; 	elif [[ $noSUBSCRIBE == 2 ]]; then match=1; ipassed=1; fi
							if [[ $bEVI == 1 ]]; 		then evseqcheck=2; evtype=1; elif [[ $bEVX == 1 ]]; 	then evseqcheck=1; evtype=1; fi;;
				PUBLISH)	if [[ $noPUBLISH == 1 ]];	then match=1; xpassed=0; 	elif [[ $noPUBLISH == 2 ]]; then match=1; ipassed=1; fi
							if [[ $bEVI == 1 ]]; 		then evseqcheck=2; evtype=2; elif [[ $bEVX == 1 ]]; 	then evseqcheck=1; evtype=2; fi;;
				NOTIFY)		if [[ $noNOTIFY == 1 ]];	then match=1; xpassed=0; 	elif [[ $noNOTIFY == 2 ]];	then match=1; ipassed=1; fi
							if [[ $bEVI == 1 ]]; 		then evseqcheck=2; evtype=3; elif [[ $bEVX == 1 ]]; 	then evseqcheck=1; evtype=3; fi
#				*)			if [[ $bINC != 0 ]] && [[ $bAllINC == 1 ]]; then ipassed=1; fi;;
				esac
			fi
		fi

		case $noPONG in
		1)  siplines=$(wc -l <<< "$linebuf")
			if [[ $((siplines)) -lt 2 ]] || [[ $((siplength)) -le 4 ]]; then
				passed=0
			fi;;
		2)  if [[ $bAllINC != 0 ]]; then
				siplines=$(wc -l <<< "$linebuf")
				if [[ $((siplines)) -gt 2 ]] || [[ $((siplength)) -gt 4 ]]; then
					passed=0
				fi
			fi;;
		esac

		if [[ $passed != 0 ]] && [[ $evcheck != 0 ]]; then
			eventstr=$(egrep -m 1 -e "^Event:" <<< "$linebuf" | tr -d '\r')
			case ${eventstr/Event: /} in 
			dialog)
				if [[ $bEvDialog != 0 ]];	then evmatch=$bEvDialog; fi;;
			avaya-cm-cc-info)
				if [[ $bEvCC != 0 ]]; 		then evmatch=$bEvCC; fi;;
			reg)
				if [[ $bEvReg != 0 ]];		then evmatch=$bEvReg; fi;;
			avaya-cm-feature*)
				if [[ $bEvCMstat != 0 ]];	then evmatch=$bEvCMstat; fi;;
			message*)
				if [[ $bEvMsgSum != 0 ]];	then evmatch=$bEvMsgSum; fi;;
			avaya-ccs*)
				if [[ $bEvCCSprof != 0 ]];	then evmatch=$bEvCCSprof; fi;;
			presence*)
				if [[ $bEvPresence != 0 ]]; then evmatch=$bEvPresence; fi;;
			refer)
				if [[ $bEvRefer != 0 ]];	then evmatch=$bEvRefer; fi;;
			screen-update)
				if [[ $bEvScrUpd != 0 ]];	then evmatch=$bEvScrUpd; fi;;
			ua-profile*)
				if [[ $bEvUAprof != 0 ]];	then evmatch=$bEvUAprof; fi;;
			conf*)
				if [[ $bEvConf != 0 ]];		then evmatch=$bEvConf; fi;;				
			avaya-push*)
				if [[ $bEvPush != 0 ]];	    then evmatch=$bEvPush; fi;;
			*)  evunknown=$((evunknown+1))
				evstrings="$evstrings| ${eventstr/Event: }"
				if [[ $bDebug != 0 ]]; then
					echo "warning: found an unknown \"$eventstr\" in $sipword message in msgno#$sipmsg at $siptime - Contact developer."
				fi
				echo "# warning: found an unknown \"$eventstr\" in $sipword message in msgno#$sipmsg at $siptime - Contact developer." >> "$newfile";;
			esac
# echo -e "\nPH1:$siptime AllINC=$bAllINC EVI=$bEVI EVX=$bEVX INC=$bINC EXC=$bEXC - $sipword - $cseqline - $eventstr - $ipassed - $xpassed - $evcheck - $evseqcheck - $evtype evmatch=$evmatch"
# if [[ $sipword == "SUBSCRIBE" ]] || [[ $cseqword == "SUBSCRIBE" ]]; then
#	echo -e "\n$siptime EVI=$bEVI EVX=$bEVX - $sipword - $cseqword - $eventstr - $ipassed - $xpassed - $evcheck - $evseqcheck - $evtype evmatch=$evmatch"
# fi
			if [[ $evmatch == 1 ]]; then
				passed=0
#			if [[ $ipassed == 0 ]]; then			
				case $evtype in
				1)	if [[ $prevSUBseq1 != "" ]]; then
						if [[ $prevSUBseq2 != "" ]]; then
							if [[ $prevSUBseq3 != "" ]]; then
								if [[ $prevSUBseq4 != "" ]]; then
									echo -e "\n# SUBSCRIBE to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet!\n"	>> "$newfile"
									if [[ $bDebug != 0 ]]; then
										echo -e "\nSUBSCRIBE to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet! Contact developer.\n"
									fi
								fi
								prevSUBseq4="$cseqline"
								prevSUBcallid4=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
							else
								prevSUBseq3="$cseqline"
								prevSUBcallid3=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
							fi
						else
							prevSUBseq2="$cseqline"
							prevSUBcallid2=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
						fi
					else
						prevSUBseq1="$cseqline"
						prevSUBcallid1=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid1=${prevSUBcallid1//'\r\n$'//};;
					fi;;
				2)	if [[ $prevPUBseq != "" ]]; then
						echo -e "\n# PUBLISH to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet!\n" >> "$newfile"
						if [[ $bDebug != 0 ]]; then
							echo -e "\nPUBLISH to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet! Contact developer.\n"
						fi
					fi
					prevPUBseq="$cseqline"
					prevPUBcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevPUBcallid=${prevPUBcallid//'\r\n$'//};;
				3)	if [[ $prevNOTIFYseq != "" ]]; then
						echo -e "\n# NOTIFY to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet!\n" >> "$newfile"
						if [[ $bDebug != 0 ]]; then
							echo -e "\nNOTIFY to be deleted ($eventstr) at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet! Contact developer.\n"
						fi
					fi
					prevNOTIFYseq="$cseqline"
					prevNOTIFYcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevNOTIFYcallid=${prevNOTIFYcallid//'\r\n$'//};
				esac
 
			elif [[ $evmatch == 2 ]]; then
				passed=1
#				if [[ $xpassed == 0 ]] || [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
				if [[ $xpassed == 0 ]] || [[ $ipassed == 0 ]]; then				
# echo -e "\nPH2:$siptime AllINC=$bAllINC EVI=$bEVI EVX=$bEVX INC=$bINC EXC=$bEXC - $sipword - $cseqline - $eventstr - $ipassed - $xpassed - $evcheck - $evseqcheck - $evtype evmatch=$evmatch"			
					case $evtype in			
					1)	if [[ $prevSUBseq1 != "" ]]; then
							if [[ $prevSUBseq2 != "" ]]; then
								if [[ $prevSUBseq3 != "" ]]; then
									if [[ $prevSUBseq4 != "" ]]; then
										if [[ $xpassed == 0 ]]; then
											echo -e "\n# SUBSCRIBE msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet!\n" >> "$newfile"
											if [[ bDebug != 0 ]]; then
												echo -e "\nSUBSCRIBE msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet! Contact developer.\n"
											fi
										elif [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
											echo -e "\n# SUBSCRIBE msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"$prevSUBseq2\" has not been found yet!\n" >> "$newfile"
											if [[ $bDebug != 0 ]]; then
												echo -e "\nSUBSCRIBE msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevSUBseq1\" or \"prevSUBseq2\" has not been found yet! Contact developer.\n"
											fi
										fi
									fi
									prevSUBseq4="$cseqline"
									prevSUBcallid4=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
								else
									prevSUBseq3="$cseqline"
									prevSUBcallid3=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
								fi
							else
								prevSUBseq2="$cseqline"
								prevSUBcallid2=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid2=${prevSUBcallid2//'\r\n$'//};;
							fi
						else
							prevSUBseq1="$cseqline"
							prevSUBcallid1=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')	# prevSUBcallid1=${prevSUBcallid1//'\r\n$'//};;
						fi;;

					2)  if [[ $prevPUBseq != "" ]]; then
							if [[ $xpassed == 0 ]]; then				
								echo -e "\n# PUBLISH msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nPUBLISH msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet! Contact developer.\n"
								fi
							elif [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
								echo -e "\n# PUBLISH msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nPUBLISH msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevPUBseq\" has not been found yet! Contact developer.\n"
								fi
							fi						
						fi	
						prevPUBseq="$cseqline"
						prevPUBcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevPUBcallid=${prevPUBcallid//'\r\n$'//};;

					3)	if [[ $prevNOTIFYseq != "" ]]; then
							if [[ $xpassed == 0 ]]; then				
								echo -e "\n# NOTIFY msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nNOTIFY msg to be deleted ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet! Contact developer.\n"
								fi
							elif [[ $ipassed == 0 ]] && [[ $xpassed == 1 ]]; then
								echo -e "\n# NOTIFY msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet!\n" >> "$newfile"
								if [[ $bDebug != 0 ]]; then
									echo -e "\nNOTIFY msg to be kept ($eventstr) with \"$cseqline\" at $siptime, but a previous (matching) \"$prevNOTIFYseq\" has not been found yet! Contact developer.\n"
								fi
							fi						
						fi
						prevNOTIFYseq="$cseqline"
						prevNOTIFYcallid=$(egrep -m 1 -e "^Call-ID:"  <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r');;	# prevNOTIFYcallid=${prevNOTIFYcallid//'\r\n$'//};
					esac

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi

			elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
				if [[ $ipassed == 0 ]]; then passed=0; fi

			elif [[ $match == 0 ]]; then
				if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
			fi

		elif [[ $passed != 0 ]] && [[ $evseqcheck != 0 ]]; then
			currcallid=$(egrep -m 1 -e "^Call-ID:" <<< "$linebuf" | cut -d' ' -f2 | tr -d '\r')  #; currcallid=${currcallid//'\r\n$'//}
			case $evtype in
			1)	subseqfound=0
				if [[ $prevSUBseq4 != "" ]]; then
					if [[ $cseqline == $prevSUBseq4 ]] && [[ $currcallid == $prevSUBcallid4 ]]; then
						prevSUBseq4=""; subseqfound=1
					fi
				fi
				if [[ $subseqfound == 0 ]] && [[ $prevSUBseq3 != "" ]]; then
					if [[ $cseqline == $prevSUBseq3 ]] && [[ $currcallid == $prevSUBcallid3 ]]; then
						prevSUBseq3=""; subseqfound=1
					fi
				fi
				if [[ $subseqfound == 0 ]] && [[ $prevSUBseq2 != "" ]]; then
					if [[ $cseqline == $prevSUBseq2 ]] && [[ $currcallid == $prevSUBcallid2 ]]; then
						prevSUBseq2=""; subseqfound=1
					fi
				fi		
				if [[ $subseqfound == 0 ]] && [[ $prevSUBseq1 != "" ]]; then
					if [[ $cseqline == $prevSUBseq1 ]] && [[ $currcallid == $prevSUBcallid1 ]]; then
						prevSUBseq1=""; subseqfound=1
					fi
				fi
				if [[ $subseqfound != 0 ]]; then
					if [[ $evseqcheck == 1 ]]; then passed=0; else passed=1; fi
#			else
#				echo -e "\n# SUBSCRIBE anomaly at $siptime: evtype=$evtype cseqword=$cseqword\n" >> "$newfile"			
#				if  [[ $bDebug != 0 ]]; then
#					echo -e "\nSUBSCRIBE anomaly at $siptime: evtype=$evtype cseqword=$cseqword. Contact developer.\n"
#				fi

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi;;

			2)	if [[ $prevPUBseq != "" ]]; then
					if [[ $cseqline == $prevPUBseq ]] && [[ $currcallid == $prevPUBcallid ]]; then
						prevPUBseq=""
						if [[ $evseqcheck == 1 ]]; then passed=0; else passed=1; fi
					elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
						if [[ $ipassed == 0 ]]; then passed=0; fi
					elif [[ $match == 0 ]]; then
						if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi					
					fi

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi;;
#			else
#				echo -e "\n# PUBLISH anomaly at $siptime: evtype=$evtype cseqword=$cseqword\n" >> "$newfile"			
#				if  [[ $bDebug != 0 ]]; then
#					echo -e "\nPUBLISH anomaly at $siptime: evtype=$evtype cseqword=$cseqword. Contact developer.\n"
#				fi
#			fi;;

			3) 	if [[ $prevNOTIFYseq != "" ]]; then
					if [[ $cseqline == $prevNOTIFYseq ]] && [[ $currcallid == $prevNOTIFYcallid ]]; then
						prevNOTIFYseq=""
						if [[ $evseqcheck == 1 ]]; then passed=0; else passed=1; fi
					elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
						if [[ $ipassed == 0 ]]; then passed=0; fi
					elif [[ $match == 0 ]]; then
						if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi					
					fi

				elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
					if [[ $ipassed == 0 ]]; then passed=0; fi

				elif [[ $match == 0 ]]; then
					if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
				fi;;
#			else
#				echo -e "\n# NOTIFY anomaly at $siptime: evtype=$evtype cseqword=$cseqword\n" >> "$newfile"			
#				if  [[ $bDebug != 0 ]]; then
#					echo -e "\nNOTIFY anomaly at $siptime: evtype=$evtype cseqword=$cseqword. Contact developer.\n"
#				fi
#			fi;;
			esac

		elif [[ $bEXC != 0 ]] && [[ $xpassed == 0 ]]; then
			if [[ $ipassed == 0 ]]; then passed=0; fi

		elif [[ $match == 0 ]]; then
			if [[ $bAllINC != 0 ]]; then passed=1; else passed=0; fi
		fi
# echo -e "Found $sipword passed=$passed xpassed=$xpassed ipassed=$ipassed evcheck=$evcheck evseqcheck=$evseqcheck evtype=$evtype EVI=$bEVI EVX=$bEVX\n"
	elif [[ $bDebug == 0 ]]; then
		if [[ $sipword =~ PUB|SUB|NOTIFY ]]; then
			eventstr=$(egrep -m 1 -e "^Event:" <<< "$linebuf" | tr -d '\r')
			eventstr=${eventstr/Event: /}
			case $eventstr in 
			dialog)
				if [[ $evdialog == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evdialog=$((evdialog+1));;
			avaya-cm-cc-info)
				if [[ $evccinfo == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evccinfo=$((evccinfo+1));;				
			reg)
				if [[ $evreg == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evreg=$((evreg+1));;
			avaya-cm-feature*)
				if [[ $evcmfeat == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evcmfeat=$((evcmfeat+1));;
			message*)
				if [[ $evmsgsum == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evmsgsum=$((evmsgsum+1));;
			avaya-ccs*)
				if [[ $evccs == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evccs=$((evccs+1));;
			presence*)
				if [[ $evpres == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evpres=$((evpres+1));;
			refer)
				if [[ $evrefer == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evrefer=$((evrefer+1));;
			screen*)
				if [[ $evscrupd == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evscrupd=$((evscrupd+1));;
			avaya-push*)
				if [[ $evpush == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evpush=$((evpush+1));;
			conf*)
				if [[ $evconf == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evconf=$((evconf+1));;
			ua*)
				if [[ $evuaprof == 0 ]]; then
					evstrings="$evstrings|$eventstr"
				fi
				evuaprof=$((evuaprof+1));;								
			*)	
				if [[ ! $evstrings =~ $eventstr ]]; then
					evstrings="$evstrings|UNKNOWN:$eventstr"
				fi
				evunknown=$((evunknown+1));;
			esac
		fi
	fi

	if [[ $passed == 0 ]]; then
		ignore_sipmsg
	else
		if [[ $findANI != "" ]] && [[ $findCALLID != "" ]]; then
			callid=$(egrep -m 1 -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)
			if [[ $callid != "" ]] && [[ $callid =~ $findCALLID ]]; then
				linefrom=""; lineto=""
				linefrom=$(egrep -e "^From:" <<< "$linebuf" 2>/dev/null)
			
				if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
					callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
					callDIR=$dirdefined; calltime=$siptime
					if [[ $callidtime1 == "" ]]; then
						callidtime1=$siptime; callmsgnum1=$((sipmsg+1))
						callidword1=$sipword
					else
						callidtime2=$siptime; callmsgnum2=$((sipmsg+1))
						callidword2=$sipword
					fi
				else
					lineto=$(egrep -e "^To:" <<< "$linebuf" 2>/dev/null)
					if [[ $lineto != "" ]] && [[ $lineto =~ $findANI ]]; then
						callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
						callDIR=$dirdefined; calltime=$siptime
						if [[ $callidtime1 == "" ]]; then
							callidtime1=$siptime; callmsgnum1=$((sipmsg+1))
							callidword1=$sipword						
						else
							callidtime2=$siptime; callmsgnum2=$((sipmsg+1))
							callidword2=$sipword						
						fi
					fi
				fi
			fi
		else
			if [[ $findANI != "" ]] && [[ $sipword == "INVITE" ]]; then
				linefrom=""; lineto=""
				linefrom=$(egrep -e "^From:" <<< "$linebuf" 2>/dev/null)
			
				if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
					callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
					callDIR=$dirdefined; calltime=$siptime
				else
					lineto=$(egrep -e "^To:" <<< "$linebuf" 2>/dev/null)
					if [[ $lineto != "" ]] && [[ $lineto =~ $findANI ]]; then
						callID=$(egrep -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)							
						callDIR=$dirdefined; calltime=$siptime
					fi
				fi
			fi

			if [[ $findCALLID != "" ]]; then
				callid=$(egrep -m 1 -e "^Call-ID:" <<< "$linebuf" 2>/dev/null)
				if [[ $callid != "" ]] && [[ $callid =~ $findCALLID ]]; then
					if [[ $callidtime1 == "" ]]; then
						callidtime1=$siptime; callmsgnum1=$((sipmsg+1))
						callidword1=$sipword
					else
						callidtime2=$siptime; callmsgnum2=$((sipmsg+1))
						callidword2=$sipword						
					fi
				fi
			fi
		fi

		if [[ $dirdefined == 1 ]] && [[ $sipword =~ PUBLISH|NOTIFY ]]; then				# incoming Presence payload is usually ugly
			if [[ $eventstr == "" ]]; then
				eventstr=$(egrep -m 1 -e "^Event:" <<< "$linebuf" | tr -d '\r')
			fi
			if [[ $eventstr =~ Presence ]]; then
				dummy=0
#				presence_beutify
			fi
		fi

		complete_sipmsg
	fi
fi
# set +x	
} # explore_sipmsg ()

function save_sipline() {
	if [[ $sipnotify != 0 ]] && [[ $line =~ "Event: refer" ]]; then
		notifyrefer=1
	elif [[ $line =~ xml\ version= ]] && [[ ${#line} -gt 80 ]]; then
		line=$(sed 's/>\s*</>\n</g' <<< "$line" | sed -e 's/&amp;/\&/g' | sed 's/&quot;/"/g')
	fi

   	if [[ $linebuf == "" ]] && [[ $line != "" ]]; then
		linebuf="$line"
	elif [[ $line != "" ]]; then
		linebuf="$linebuf\r\n$line"
	fi
} # save_sipline()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

	fsize=$(wc -c < "$file" 2>/dev/null)
	if [[ $((fsize)) -gt 0 ]]; then
		rec=$(egrep -ce "^CSeq:*" "$file" 2>/dev/null)	
		rec2=$(egrep -ce "DBH \[.*SIGNAL" "$file" 2>/dev/null)
		if [[ $((rec2)) == 0 ]]; then
			rec2=$(egrep -ce "DBH:.*SIGNAL:" "$file" 2>/dev/null)
			if [[ $((rec2)) != 0 ]]; then
				vsyslog=11
			fi
		else
			vsyslog=10
		fi
		if [[ $((rec2)) == 0 ]]; then
			rec2=$(egrep -ce "\]\ [RS]E.*bytes " "$file" 2>/dev/null)
			if [[ $((rec2)) != 0 ]]; then			
				vsyslog=12
			fi
		fi		
	fi

	if [[ $((rec2)) == 0 ]]; then
		vsyslog=0
		if [[ $var != $file ]]; then
			echo -e "\nerror: $var -> $basefile does not include any SIP messages in the expected format."
		else
			echo -e "\nerror: $var : No SIP messages have been found in the expected format."
		fi

		if [[ $((rec)) != 0 ]]; then
			if [[ $var != $file ]]; then
				echo -e "Though found a line starting with \"CSeq:\" - so there might be some SIP messages within $var -> $basefile.\n"
			else
				echo -e "Though found a line starting with \"CSeq:\" - so there might be some SIP messages within $var.\n"
			fi

			asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
			if [[ $((asmfile)) != 0 ]]; then
				asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
				if [[ $((asmfile)) != 0 ]]; then
					echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
					echo "This kind of input is not (yet) supported by this tool."
				fi
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

#	elif [[ $((rec)) != 0 ]]; then
	elif [[ $((rec)) == 0 ]] || [[ $((error)) != 0 ]]; then
		return
	elif [[ $((rec)) -lt $((rec2)) ]]; then
		rec=$rec2
	fi

	if [[ $((rec)) != 0 ]]; then
		bakfile=""; output=""; 	bfile=""

		if [[ $basefile != "" ]] && [[ $basefile == *"."* ]]; then
			bfile=${basefile%.*}
		fi

		if [[ $var != $basefile ]] && [[ $basefile != $file ]]; then
			xfile=${bvar%%.*}
			if [[ $bvar == $basefile ]]; then
				output="$bvar"
			elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
				output="$xfile-$basefile"
			else
				output="$bvar"
			fi
		else
			output="$basefile"
		fi

		if [[ $output != "" ]]; then
			newfile="$output.asm.tmp"
			bakfile="$output"
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

		case $vsyslog in
	    10) conv=$(awk -W source='/DBH \[.*SIGNAL/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			if [[ $? != 0 ]]; then
	    		conv=$(awk -e '/DBH \[*/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			fi;;
		11) conv=$(awk -W source='/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			if [[ $? != 0 ]]; then
	    		conv=$(awk -e '/DBH:.*SIGNAL:/{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			fi;;
		12) conv=$(awk -W source='/]\ R|SE.*bytes\ /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			if [[ $? != 0 ]]; then
	    		conv=$(awk -e '/]\ R|SE.*bytes\ /{flag=1} flag; /}/{flag=0}' "$file" 2>/dev/null)
			fi;;
		esac

		logsec=$SECONDS
		base64msg=0
		foundipaddr="";	lastfoundip=""
		nlines=0;		siplines=0;		sipmaxlines=0
		sipyear=0;		sipmonth=0;		sipday=0
		siphour=0;		sipmin=0;		sipmsec=0
		siptime="";		prevsiptime=""
		sipmsg=0;		siptotalmsg=0
		sipbadmsg=0;	sipbadtimemsg=""
		sipbadmsgnum="";sipbadtime=0
		sipword="";		sipwordlist="";	longestsipword="";	prevsipword=""
		currcseq=0;		prevcseq=0;		cseqword=""			
		firstmsg="";	lastmsg="";		longestmsg=0
		timefirst="";	timelast=""
		nPONG=0;		embedded=0
		sipin=0;		sipout=0
		callID="";		calltime="";	callDIR=0
		callidtime1="";	callmsgnum1=0;	callidword1=""
		callidtime2="";	callmsgnum2=0;	callidword2=""
		nINFO=0;		infoin=0;		infoout=0
		notpassed=0; notpassedin=0; 	notpassedout=0

		useragent="";	server=""; 		serverip=""; 	serverua=""
		scua="";		scip=""		
		multimsg=0; 	multimsgin=0;	multimsgout=0
		notifyrefer=0; 	sipnotify=0;	prevline="notempty"

		prevINFOseq=""
		prevNOTIFYseq="";	prevNOTIFYcallid=""		
		prevPUBseq="";		prevPUBcallid=""
		prevSUBseq1=""; 	prevSUBcallid1=""
		prevSUBseq2="";		prevSUBcallid2=""
		prevSUBseq3="";		prevSUBcallid3=""
		prevSUBseq4="";		prevSUBcallid4=""				
		n=0	

		evdialog=0; evccinfo=0; evreg=0; evcmfeat=0; evmsgsum=0
		evunknown=0; evpush=0; evscrupd=0; evrefer=0; evccs=0; evconf=0; evuaprof=0

	    reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo "You may want to execute this script on a more powerful PC or server."
		fi

		while IFS= read -r line
		do
			nlines=$((nlines+1))

#			if [[ $line =~ DBH\ \[.*\]\ SIGNAL ]]; then
#			if [[ $line =~ DBH\ \[.*SIGNAL ]] || [[ $line =~ DBH:.*SIGNAL: ]] || [[ $line =~ \]\ R|SE.*bytes\  ]]; then

			if [[ $line =~ DBH.*Length= ]] || [[ $line =~ bytes\  ]]; then
				if [[ $((sipstart)) != 0 ]]; then
					explore_sipmsg
#					complete_sipmsg
				fi
				insidesip=1
				siptotalmsg=$((siptotalmsg+1))	
				sip_direction
				get_sip_datetime	
															
			elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
				if [[ $line == "{"* ]] || [[ ${#line} == 0 ]]; then
					sipstart=1
				else
					insidesip=0
					if [[ $((bDebug)) != 0 ]]; then
						echo "error: found a new SIP message candidate with invalid 2nd line. Contact developer."
					fi			
				fi

			elif [[ $((sipstart)) == 1 ]]; then
					if [[ $((vsyslog)) == 11 ]] && [[ ${line:0:1} == '[' ]]; then
						line=$(cut -d' ' -f2- <<< "$line")
					fi
					sipmsg_header	
					start_sipmsg
					sipstart=2

			elif [[ $((sipstart)) == 2 ]]; then
				if [[ $line == *"}"* ]]; then
					explore_sipmsg				
#					complete_sipmsg
					continue
				fi

				if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
					base64found=1
					line=$(awk -F"Base64 dump" '{print $1}' <<< "$line")
					save_sipline

				elif [[ $((base64found)) != 0 ]] && [[ $line != "" ]]; then
					if [[ $linebuf64 == "" ]]; then
						linebuf64="$line"
					else
						linebuf64="$linebuf64$line"
					fi

				elif [[ $line =~ ^[[:upper:]]{3,}[^-] ]] && [[ $notifyrefer == 0 ]]; then															# due to multiple SIP msg in the same RX SIPMESSAGE
#				elif [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then								# due to multiple SIP msg in the same RX SIPMESSAGE
#				elif [[ $dirdefined == 1 ]] && [[ ${#prevline} -lt 2 ]] && [[ $line =~ ^[A-Z]{3} ]] && [[ $notifyrefer == 0 ]]; then	# it can occur only in RX direction
					if [[ ! $line =~ ^GUID= ]]; then
						multi_sipmsg
					fi
				else
					save_sipline
					prevline="$line"
				fi
			fi				
		done <<< "$conv"

		if [[ $((sipstart)) != 0 ]]; then
			explore_sipmsg
#			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output="$var"
		fi
		
		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error\n\n"

		elif [[ $((sipmsg)) -lt 1 ]]; then
			echo -e "\nError: No SIP messages have been found in $basefile. Contact developer."

        elif [[ $((sipstat)) != 0 ]]; then
#			if [[ $sipmsg != $n ]]; then n=$((n+1)); fi
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $bvar file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    have been converted for addr=$endptaddr into $output.asm file"
				fi
			fi

			if [[ $useragent != "" ]]; then
				if [[ $lastfoundip != "" ]] && [[ $lastfoundip != "0.0.0.0" ]]; then
					lastfoundip=$(sed -e 's/\.$//g' <<< $lastfoundip)				
					printf "\t%-49s ip.addr == %s\n" "${useragent:0:49}" "$lastfoundip"
				else
					printf "\t%-73s\n" "${useragent:0:73}"
				fi

				if [[ $scua != "" ]]; then
					scua=$(awk -F "Agent: " '{print $2}' <<< "$scua")
					if [[ $scip != "" ]]; then
						printf "\tSC session with %-33s ip.addr == %s\n" "${scua:0:33}" "$scip"
					else
						printf "\tFound SC session with %-51s" "${scua:0:51}"
					fi
				fi

				if [[ $server == "" ]]; then
					serverip=""; server=$(egrep -m 1 -e "^Server:" "$newfile" | tr -d "\r\n")				
				fi
				if [[ $server != "" ]]; then
					serverip=$(sed -e 's/\.$//g' <<< $serverip)
#					if [[ $input != "" ]]; then								# && [[ ${#server} -lt 68 ]]; then
					if [[ $serverip != "" ]]; then
						printf "\t%-49s ip.addr == %s\n" "${server:0:49}" "$serverip"
					else
						printf "\t%-73s\n" "${server:0:73}"
					fi
				fi
			fi

			echo -e "\tTotal # of lines digested:\t\t\t  $nlines"

			if [[ $((error)) != 0 ]]; then
				echo -e "\n\tError found: $error\n\n"

			elif [[ $((sipmsg)) != 0 ]]; then
				echo -e "\tTotal # of SIP messages processed (RX/TX):\t  $siptotalmsg ($sipin/$sipout)"
				if [[ $((notpassed)) != 0 ]]; then
					echo -e "\tTotal # of SIP messages filtered  (RX/TX):\t $notpassed ($notpassedin/$notpassedout)"
				fi
				if [[ $((nINFO)) != 0 ]]; then
					if [[ $noINFO == 1 ]]; then
						echo -e "\tINFO messages ignored:\t\t\t\t  $nINFO ($infoin/$infoout)"
					elif [[ $noINFO == 2 ]]; then
						echo -e "\tINFO messages found:\t\t\t\t  $nINFO ($infoin/$infoout)"
					fi
				fi
				if [[ $((nPONG)) != 0 ]]; then
					echo -e "\tPONG messages found:\t\t\t\t  $nPONG"
				fi
				if [[ $((multimsg)) != 0 ]]; then
					echo -e "\tEmbedded SIP messages:\t\t\t\t  $multimsg ($multimsgin/$multimsgout)"
					echo -e "# Embedded SIP messages:\t\t\t  $multimsg ($multimsgin/$multimsgout)" >> "$newfile"					
				fi
				echo -e "\tLongest SIP message had:\t\t\t  $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
				echo -e "# Longest SIP message had:\t\t\t  $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
				if [[ $((sipbadmsg)) != 0 ]]; then
					if [[ $sipbadmsgnum != 0 ]]; then
						echo -e "\tBad SIP messages (eg partial msg or missing CSeq):\t $sipbadmsg at msg #$sipbadmsgnum"
						echo -e "# Bad SIP messages (eg partial msg or missing CSeq):  $sipbadmsg at msg #$sipbadmsgnum" >> "$newfile"
					else
						echo -e "\tBad SIP messages (eg partial msg or missing CSeq):\t $sipbadmsg"
						echo -e "# Bad SIP messages (eg partial msg or missing CSeq):  $sipbadmsg" >> "$newfile"
					fi
				fi
				if [[ $((sipbadtime)) != 0 ]]; then
					echo -e "\tBad SIP messages (timestamps out of order):\t  $sipbadtime at msg #$sipbadtimemsg"
					echo -e "# Bad SIP messages (timestamps out of order):\t  $sipbadtime at msg #$sipbadtimemsg" >> "$newfile"
				fi
				if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
					echo -e "\tBase64 encoded SIP messages:\t\t\t  $base64msg"
				fi

				if [[ ${#firstmsg} -le 11 ]] && [[ ${#lastmsg} -le 11 ]]; then					
					printf "\tFirst msg: %-11s %s\t  Last msg: %-11s %s\n" "$firstmsg" "$timefirst" "$lastmsg" "$timelast"
				else
					printf "\tFirst msg: %-34s\t  %s\n" "${firstmsg:0:34}" "$timefirst"
					printf "\tLast msg: %-35s\t  %s\n"  "${lastmsg:0:35}"  "$timelast"
				fi

				if [[ $findANI != "" ]] && [[ $callID != "" ]] && [[ $calltime != "" ]]; then
					if [[ $callDIR == 1 ]]; then
					echo -e "\tIncoming call from $findANI at $calltime\t $callID"
				elif [[ $callDIR == 2 ]]; then
					echo -e "\tOutgoing call to $findANI at $calltime\t $callID"
					fi
				fi
				if [[ $findCALLID != "" ]] && [[ $callidtime1 != "" ]]; then
					if [[ $callidtime2 != "" ]]; then
						echo -e "\tCallID= $findCALLID:\tfirst seen at $callidtime1 ($callidword1) / last at $callidtime2 ($callidword2)"
					else
						echo -e "\tCallID= $findCALLID:\tfirst seen at $callidtime1 ($callidword1)"
					fi
				fi

				if [[ $bDebug == 0 ]]; then
					if [[ $evstrings != "" ]]; then
						echo -e "\n# Events found: $evstrings" >> "$newfile"
						echo -en "# " >> "$newfile"
					fi
					if [[ $evdialog != 0 ]]; then
						echo -en "dialog: $evdialog| " >> "$newfile"
					fi
					if [[ $evccinfo != 0 ]]; then
						echo -en "avaya-cm-info: $evccinfo| " >> "$newfile"
					fi
					if [[ $evreg != 0 ]]; then
						echo -en "reg: $evreg| " >> "$newfile"
					fi
					if [[ $evcmfeat != 0 ]]; then
						echo -en "avaya-cm-feature-status: $evcmfeat| " >> "$newfile"
					fi
					if [[ $evmsgsum != 0 ]]; then
						echo -en "message-summary: $evmsgsum| " >> "$newfile"
					fi
					if [[ $evpush != 0 ]]; then
						echo -en "avaya-push-notification: $evpush| " >> "$newfile"
					fi
					if [[ $evrefer != 0 ]]; then
						echo -en "refer: $evrefer| " >> "$newfile"
					fi
					if [[ $evccs != 0 ]]; then
						echo -n "avaya-ccs-profile: $evccs| " >> "$newfile"
					fi
					if [[ $evconf != 0 ]]; then
						echo -en "conference: $evconf| " >> "$newfile"
					fi
					if [[ $evuaprof != 0 ]]; then
						echo -en "us-profile: $evuaprof| " >> "$newfile"
					fi						
					if [[ $evunknown != 0 ]]; then
						echo -e "\n# Unknown events: $evunknown\n" >> "$newfile"
					else
						echo '' >> "$newfile"
					fi
				fi
			fi
		fi

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t $sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
		else
			echo "Conversion of $file has ended with error code: $error n=$n sipwords=$sipwordlist"
		fi	

		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.3f "$(($((n)) * 1000 / $tmpsec))e-3")
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t  Total spent: $SECONDS sec  Avg. SIP msg/sec: $avgmsg\n"
		else
			echo -e "\n\tTask started:  $currtime   completed:  $(date +%R:%S)\t  Avg. SIP msg/sec: N/A\t  Time spent: $SECONDS sec\n"
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
	targetfiles=""; targetX=""
#	targetX=`ls -r -t1 SIPMessages* 2>/dev/null | egrep -v bak`
	targetX=`ls -r -t1 S[Ii][Pp]Messages* 2>/dev/null`	
	if [[ $? != 0 ]]; then
		targetX=""

	elif [[ $((alllogs)) == 0 ]] && [[ $targetX != "" ]]; then
#		targetfiles=$(tail -1 <<< $targetX)
		targetfiles=${targetX##* }							# last word		
	else
		targetfiles="$targetX"
	fi

# echo IFS=$IFS---
	xfile=""; file=""; filelist=""
	if [[ $targetfiles == "" ]]; then
		targetX=""; targetX=`ls -r -t1 H323Station* 2>/dev/null`
		if [[ $targetX != "" ]]; then
			targetX=""
			echo "Found H323Station.txt in lack of SIPMessages.txt in $destdir folder."
			echo "Could this endpoint be using H323 protocol instead of SIP?"
		fi
#	else for xfile in "$targetfiles"
	else while read -r xfile
		do
# echo xfile=$xfile		
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
			elif [ -f "$xfile" ]; then
				echo "Found $xfile in $destdir folder but file is empty (it has 0 size) - ignoring."
			fi
		done <<< "$targetfiles"
	fi
	if [[ $xfile != "" ]] && [ -s "$xfile" ]; then
		file="$destdir/$xfile"
	fi
# echo file=$file filelist=$filelist		
} # explore_logfolder()

function explore_folders() {
if [[ $folder != "" ]] && [[ $destdir != "" ]]; then
	file=""
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
		elif [[ -d "Avaya one-X Communicator" ]]; then
			destdir="$destdir/Avaya one-X Communicator"
			target="$target-Avaya1XC"
			cd "Avaya one-X Communicator"
			probe_logsFromDir				
			if [[ $file == "" ]] && [[ $filelist == "" ]]; then
				if [ -d "Log Files" ]; then
					destdir="$destdir/Log Files"
					target="$target-LogFiles"
					cd logs
					probe_LogsFromDir
				fi
			fi
		fi

	elif [[ -d "Avaya one-X Communicator" ]]; then
		destdir="$destdir/Avaya one-X Communicator"
		target="$target-1XC"
		cd "Avaya one-X Communicator"
		explore_logfolder
		if [[ $file == "" ]] && [[ $filelist == "" ]]; then
			if [ -d "Log Files" ]; then
				destdir="$destdir/Log Files"
				target="$target-LogFiles"
				cd "Log Files"
				explore_logfolder
			elif [ -d "log" ]; then
				destdir="$destdir/log"
				target="$target-log"
				cd log
				explore_logfolder
			elif [ -d "logs" ]; then
				destdir="$destdir/logs"
				target="$target-logs"
				cd logs
				explore_logfolder
			fi
			if [[ $file == "" ]] && [ -d "Backup" ]; then
				destdir="$destdir/Backup"
				target="$target-backup"
				cd Backup
				explore_logfolder
			fi
		fi

	elif [[ -d "Communicator for Microsoft Lync" ]]; then
		destdir="$destdir/Communicator for Microsoft Lync"
		target="$target-ACLync"
		cd "Communicator for Microsoft Lync"
		explore_logfolder
		if [[ $file == "" ]] && [[ $filelist == "" ]]; then
			if [ -d "Log Files" ]; then
				destdir="$destdir/Log Files"
				target="$target-LogFiles"
				cd "Log Files"
				explore_logfolder
			elif [ -d "log" ]; then
				destdir="$destdir/log"
				target="$target-log"
				cd log
				explore_logfolder
			elif [ -d "logs" ]; then
				destdir="$destdir/logs"
				target="$target-logs"
				cd logs
				explore_logfolder
			fi
			if [[ $file == "" ]] && [ -d "backup" ]; then
				destdir="$destdir/backup"
				target="$target-backup"
				cd backup
				explore_logfolder
			fi
		fi

	elif [[ -d "Avaya Communicator for Microsoft Lync" ]]; then
		destdir="$destdir/Avaya Communicator for Microsoft Lync"
		target="$target-ACLync"
		cd "Avaya Communicator for Microsoft Lync"
		explore_logfolder
		if [[ $file == "" ]] && [[ $filelist == "" ]]; then
			if [ -d "Log Files" ]; then
				destdir="$destdir/Log Files"
				target="$target-LogFiles"
				cd "Log Files"
				explore_logfolder
			elif [ -d "log" ]; then
				destdir="$destdir/log"
				target="$target-log"
				cd log
				explore_logfolder
			elif [ -d "logs" ]; then
				destdir="$destdir/logs"
				target="$target-logs"
				cd logs
				explore_logfolder
			fi
			if [[ $file == "" ]] && [ -d "backup" ]; then
				destdir="$destdir/backup"
				target="$target-backup"
				cd backup
				probe_LogsFromDir
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

	elif [[ -d "Log Files" ]]; then
		destdir="$destdir/Log Files"
		cd "Log Files"
		probe_LogsFromDir

	elif [ -d "log" ] || [ -d "logs" ] || [ -d "Logs" ]; then
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
		elif [ -d "Logs" ]; then
			target="$target-Logs"
			if [ -d "logs/Logs" ]; then
				destdir="$destdir/logs/Logs"
				cd "logs/Logs"
				probe_LogsFromDir
			else
				destdir="$destdir/Logs"
				cd "Logs"
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
  while getopts "hbf:sdACI:X:N:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	C)  
		bCAT=1;;
	A)
		alllogs=1;;
    I)
#		noINFO=1;;
		filterI=${OPTARG}
		explore_filters;;
	X)
		filterX=${OPTARG}
		explore_filters;;		
	N)	
		if [[ $OPTARG =~ ^id: ]]; then			
			findCALLID=${OPTARG/id:/}
		elif [[ $OPTARG =~ ^ID: ]]; then			
			findCALLID=${OPTARG/ID:/}
		elif [[ $OPTARG =~ [A-Za-z]+ ]]; then
			findANI=""
		else
			findANI=${OPTARG}									
		fi;;
	s)
		sipstat=0;;
	d)
		bDebug=0;;
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
		elif [[ $var == "-I"* ]]; then
			skipper=3
		elif [[ $var == "-X"* ]]; then
			skipper=4						
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
			if [[ $findANI == "" ]] || [[ $findCALLID == "" ]]; then
				if [[ $OPTARG =~ ^id: ]]; then			
					findCALLID=${OPTARG/id:/}
				elif [[ $OPTARG =~ ^ID: ]]; then			
					findCALLID=${OPTARG/ID:/}
				elif [[ $OPTARG =~ [A-Za-z]+ ]]; then
					findANI=""
				else
					findANI=${OPTARG}									
				fi
			else
				findANI="$findANI"		# findANI=$var
			fi
		elif [[ $((skipper)) == 4 ]] && [[ $filterX == "" ]]; then
			filterX=${OPTARG}
			explore_filters
		elif [[ $((skipper)) == 3 ]] && [[ $filterI == "" ]]; then
			filterI=${OPTARG}
			explore_filters			
		fi
		skipper=0; var=""
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
		echo -en "\nExploring content in \"$bvar\" folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders
		cd "$currdir"		

	elif [ -s "$var" ];then
		echo -en "\nExploring content in $bvar... stand by\r"
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
					error=7; cd "$currdir"; input=""; continue
				fi
			fi

#			target=$(basename "$input")
#			target=${target%%.*}
			mkdir "$input.tmp" 2>/dev/null
			if [[ $? != 0 ]]; then
				echo -e "\nerror: could not create $input.tmp folder in $PWD."
				echo -e "Check manually \"mkdir $input.tmp\" command and find cause."
				echo -e "Unable to unzip $bfile into a temp folder. Skipping this file...\n"
				input=""; error=7; cd "$currdir"; continue
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
				fi

			elif [[ $filetype == "Zip archive"* ]]; then
				cd ..; rm -rf "$input.tmp" 2>/dev/null
				cd "$currdir"; input=""
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

					if [[ $input2 == $zfile ]]; then input2="$input2.uncompressed"; fi

					if [ -d "$input2" ]; then
						input2="$input2-tmp"
						if [ -f "$input2" ]; then
							rm "$input2" 2>/dev/null
						fi
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
						error=7; cd "$currdir"; input=""; continue
					fi
				fi

				mkdir "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd "$currdir"; input=""; continue
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
							error=8; cd "$currdir"; input=""; continue
						else
							tar xf $input 2>/dev/null										# TODO verify the exact new filename after gunzip
							if [[ $? != 0 ]]; then
								cd ..; rm -rf "$input.tmp"						
								echo -e "\nerror: failed to uncompress $bfile, using \"tar\" utility.\n"
								error=8; cd "$currdir"; input=""; continue
							fi
						fi
					else 
						cd ..; rm -rf "$input.tmp"						
						echo -e "error: failed to uncompress $bfile, using \"tar\" utility.\n"
						error=8; cd "$currdir"; input=""; continue
					fi
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"					
					explore_folders
				fi
				cd "$currdir"				
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

	if [[ $bDebug != 0 ]]; then
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