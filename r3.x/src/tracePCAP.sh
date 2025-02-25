#!/bin/bash
version="2.0.0.3"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
tsharkversion=""
AWKSRCFLAG="-W source="
today=$(date +%m/%d/%Y)
year=$(date +%Y)
sipstat=1
noINFO=0
bDelTemp=1
adjusthour=0
base64decode=1
protoPCAP=""
protocol="TLS" # here use lowercase for tshrak -e tcp.srcport
endptaddr="" # 135.105.129.244"
srvraddr=""
voutput=3  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0
PS4='${LINENO}: '

function usage ()  {
    echo "tracePCAP.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
	echo 'Usage: tracePCAP.sh [OPTIONS] [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the Wireshark capture of SIP messages (using UDP and/or TCP transport)"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d (endpoint)"
	echo -e "\t-s ipaddr:\tconvert only messages which were sent to/received from IP addr: a.b.c.d (server)"
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-p [UDP | TCP]:\tspecify protocol used by SIP transport, by default using both"	
	echo -e "\t-I\t\tignore all SIP INFO messages (used in sharedcontrol session, DTMF or in CCMSoverSIP)"
	echo -e "\t-N ANI:\t\tfind a call with the ANI matching to number (digit string) in To: or From: headers"
	echo -e "\t-S \t\tdo not provide statistics/progress on execution or upon completion of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
} # usage()

function hex2str () {
  I=0;   line=""
  while [ $I -lt ${#sipcont} ];
  do
     line2=$(echo -en "\x"${sipcont:$I:2})
	 line=$line$line2
	 let "I += 2"
  done
} # hex2str()

function reset_sipmsg () {
	sipyear=""; dirdefined=0; infofound=0
	insidesip=0; sipstart=0; siplines=0	
	localip=""; localip1=""; localip2=""
	base64found=0; insidemsg=0		
	ip=""; ip1=""; ip2=""
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

function complete_sipmsg2 () {
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
		base64 -d $newfile.b64 >> "$newfile"
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

	infofound=0
fi
} # complete_sipmsg2()

function complete_sipmsg () {
	complete_sipmsg2
	reset_sipmsg	
} # complete_sipmsg()

function sipmsg_header () {
if [[ $((dirdefined)) != 0 ]]; then
	if [[ $foundipddr != "" ]] && [[ $endptaddr != "" ]] && [[ $foundipaddr != *$endptaddr* ]]; then
		reset_sipmsg
	elif [[ $sipdate == "" ]] || [[ $siptime == "" ]] || [[ $ip == "" ]]; then
		echo -e "\nerror: failed to grab message header items at msg# $((n+1)) at line# $nlines of $bvar"
		echo "sipdate=$sipdate siptime=$siptime ip=$ip dirdefined=$dirdefined dirstring=$dirstring1 vsyslog=$vsyslog"
		echo "line=$line"; echo "Contact developer."; exit 1
	else	
		sipstart=0; n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$file => $n/$rec Msgs converted            \r"
		fi
		case $voutput in
		1)	echo -e "# msgno: $((sipmsg+1)), pktid: $pktid${NL}[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile";;
		2)	echo -e "# msgno: $((sipmsg+1)), pktid: $pktid${NL}[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile";;
		3)	echo -e "# msgno: $((sipmsg+1)), pktid: $pktid${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$ip/R${localip}/$protocol/ }${NL}--------------------" >> "$newfile";;
		esac
	fi
fi
} # sipmsg_header() 

function sip_direction () {
# if [[ $((dirdefined)) == 0 ]]; then		
	sipline1=""; sipline2=""; sipcont=""; proto=""
	siprequest=""; sipstatus=""; sipmsghdr=""; 	pktid=""

	if [[ $line =~ \#17\# ]]; then
		proto=17; protocol="UDP"
	    localip1=$(cut -d'#' -f3 <<< "$line")
		localip2=$(cut -d'#' -f5 <<< "$line")
		ip1=$(cut -d'#' -f6 <<< "$line")
		ip2=$(cut -d'#' -f8 <<< "$line")
#	    sipline1=$(cut -d'#' -f10 <<< "$line")
#		sipline2=$(cut -d'#' -f12 <<< "$line")
	    siprequest=$(cut -d'#' -f10 <<< "$line")
	    sipstatus=$(cut -d'#' -f11 <<< "$line")
#		sipmsghdr=$(cut -d'#' -f12 <<< "$line" | sed 's/\\r\\n/\n/g')
		sipmsghdr=$(cut -d'#' -f12 <<< "$line")		
#		sipmsghdr=$(cut -d'#' -f12 <<< "$line")		
	    sipcont=$(cut -d'#' -f13 <<< "$line")
		pktid=$(cut -d'#' -f1 <<< "$line")
	elif [[ $line =~ \#\#6\# ]]; then
		proto=6; protocol="TCP"		
	    localip1=$(cut -d'#' -f3 <<< "$line")
		localip2=$(cut -d'#' -f4 <<< "$line")
		ip1=$(cut -d'#' -f6 <<< "$line")
		ip2=$(cut -d'#' -f7 <<< "$line")
#	    sipline1=$(cut -d'#' -f10 <<< "$line")
#		sipline2=$(cut -d'#' -f12 <<< "$line")
	    siprequest=$(cut -d'#' -f10 <<< "$line")
	    sipstatus=$(cut -d'#' -f11 <<< "$line")
#		sipmsghdr=$(cut -d'#' -f12 <<< "$line" | sed 's/\\r\\n/\n/g')
		sipmsghdr=$(cut -d'#' -f12 <<< "$line")		
#		sipmsghdr=$(cut -d'#' -f12 <<< "$line")		
	    sipcont=$(cut -d'#' -f13 <<< "$line")				# if $sipcont is empty, than it has length = 1 and content \r\n (0a0d)
		pktid=$(cut -d'#' -f1 <<< "$line")
	else
		proto=0; protocol="TLS"
	fi

#	proto=$(cut -d'#' -f9 <<< "$line")
#	siplength=$(echo $line | cut -d'#' -f10)

	if [[ $proto == 0 ]]; then 
		ip=""; localip=""; dirdefined=0
	elif [[ $srvraddr != "" ]]; then
		if [[ $localip1 == $srvraddr ]]; then
			sipstream=5f70; dirdefined=1
			case $voutput in
			1|2) dirstring1="RECEIVED"; dirstring2="from";;
			3)	 dirstring1="-->"; 	 	dirstring2="ingress";;
			esac
			ip="$localip1:$localip2"; localip="$ip1:$ip2"
		elif [[ $ip1 == $srvraddr ]]; then
			sipstream=1474;	dirdefined=2
			case $voutput in
			1)	dirstring1="SENT";		dirstring2="to";;
			2)	dirstring1="SENDING";	dirstring2="to";;
			3)	dirstring1="<--"; 		dirstring2="egress";;
			esac
    		ip="$ip1:$ip2"; localip="$localip1:$localip2"			
		fi

		if [[ ${#siprequest} == 0 ]]; then
#	    	sipline1=$(cut -d'#' -f11 <<< "$line")
			sipline1=$sipstatus
		else
			sipline1=$siprequest
		fi

#		if [[ ${#sipline2} == 0 ]]; then
#		   sipline2=""
#		   sipcont=$(awk -F'#' '{print $NF}' <<< "$line")
#		else
#		   sipline2=$(awk -F'#' '{print $NF}' <<< "$line")
#	   	   sipcont=""
#		fi

	elif [[ ${#siprequest} != 0 ]]; then
		sipstream=5f70; 			dirdefined=1
		sipline1=$siprequest
		case $voutput in
		1|2) dirstring1="RECEIVED"; dirstring2="from";;
		3)	 dirstring1="-->"; 		dirstring2="ingress";;
		esac

		ip="$localip1:$localip2"; localip="$ip1:$ip2"
#    	ip="$ip1:$ip2"; localip="$localip1:$localip2"

#	   	sipline1=$(cut -d'#' -f11 <<< "$line")
##		if [[ ${#sipmsghdr} == 0 ]]; then
##		   sipline2=""
##		   sipcont=$(awk -F'#' '{print $NF}' <<< "$line")
#			sipcont=$(echo "$line" | cut -d'#' -f12)
##		else
##		   sipline2=$(awk -F'#' '{print $NF}' <<< "$line")
			   # sipline2=$(echo "$line" | cut -d'#' -f12)
##		   sipcont=""
##		fi
	elif [[ ${#sipstatus} != 0 ]]; then
		sipstream=1474;				dirdefined=2
		sipline1=$sipstatus
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
   		ip="$ip1:$ip2"; localip="$localip1:$localip2"
#	    sipline1=$(cut -d'#' -f11 <<< "$line")

##		if [[ ${#sipmsghdr} == 0 ]]; then
##		   sipline2=""
##		   sipcont=$(awk -F'#' '{print $NF}' <<< "$line")
		   # sipcont=$(echo "$line" | cut -d'#' -f12)
##		else
##		   sipline2=$(awk -F'#' '{print $NF}' <<< "$line")
		   # sipline2=$(echo "$line" | cut -d'#' -f12)
##		   sipcont=""
##		fi

#			ip="$localip1:$localip2"
#			localip="$ip1:$ip2"

		# 	sipline1=$(echo $line | cut -d'#' -f11)
#			sipline2=$(awk -F'#' '{print $NF}' <<< "$line")
		# 	sipline2=$(echo "$line" | cut -d'#' -f12)

#			sipcont=""
	elif [[ $sipmsghdr == "" ]] && [[ ${#sipcont} -lt 2 ]]; then
		echo -e "\nerror: at pkt $pktid found an invalid SIP message: without Msg_hdr or Continuation"
		echo "line:$line"; echo "file:$file"
		error=10; exit $error
	fi

# if [[ ${#sipcont} -gt 1 ]]; then
#	echo "pktid=$pktid siprequest=$siprequest"
#	echo "sipstatus=$sipstatus"
#	echo "sipmsghdr=$sipmsghdr"
#	echo "sipcont=$sipcont"
#	xxd -r -p <<< "$sipcont"
# fi

#        ip="$ip1:$ip2"
#		localip="$localip1:$localip2"
#		if [[ $((voutput)) == 3 ]]; then
#			ip="$localip1:$localip2"
#			localip="$ip1:$ip2"
#		fi
#fi	
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
		fi
	fi
} # get_useragent()

function get_useragent2 () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		ualine=$(egrep -m 1 "User-Agent" <<< "$linex")
		if [[ $ualine != "" ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$ualine")
		fi
	fi
} # get_useragent2()

function get_useragent3 () {
	if [[ $((dirdefined)) == 2 ]]; then
		useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$lineX")
	fi
} # get_useragent3()

function get_sip_datetime () {
# @2022-01-18 10:26:22,699||FINEST|SIP|539122|FileName=sip/SIPTCP.cpp,LineNumber=426|RCV sock=136:0 src=10.134.48.67:5060 dst=10.134.142.36:31000 <SIP/2.0 200 OK

    tepoch=$(cut -d'#' -f2  <<< "$line")
	sipday=$(date --date="@$tepoch" +"%m/%d/%Y %T.%N")
	sipmsec=$(cut -d' ' -f2 <<< "$sipday")
	sipday=$(cut -d' ' -f1  <<< "$sipday")
	#sipday=$(echo "$prevline" | cut -d':' -f1 | cut -d'[' -f2)
	sipyear=$(cut -d'/' -f3  <<< "$sipday")
	sipmonth=$(cut -d'/' -f1 <<< "$sipday")
	sipday=$(cut -d'/' -f2   <<< "$sipday")
#	sipday=$(echo $sipday | cut -d' ' -f1)

	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2  <<< "$sipmsec")
	sipsec=$(cut -d':' -f3  <<< "$sipmsec")
	sipmsec=$(awk -F'.' '{printf "%03i",$2/1000000}' <<< "$sipsec")
    sipsec=$(cut -d'.' -f1  <<< "$sipsec")

	case $voutput in
	1)	sipdate=$(echo $sipmonth/$sipday/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec);;
	2)	sipdate=$(echo $sipyear/$sipmonth/$sipday)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec);;
	3)	sipdate=$(echo $sipday/$sipmonth/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec.$sipmsec);;
	esac
} # get_sip_datetime()

function explore_sipmsghdr () {         # $line equals the startline of new sipmsg, $linex includes the rest of SIP 
	linebuf=""
	if [[ $noINFO == 1 ]]; then
		if [[ $linex == "INFO"* ]]; then
			nINFO=$((nINFO+1)); infofound=1
#		elif [[ $sipmsghdr != "" ]] && [[ $sipmsghdr =~ .*CSeq:\ [0-9]+\ INFO* ]]; then
        else
            infox=0; infox=$(egrep -m 1 -c ".*CSeq:\ [0-9]+\ INFO*" <<< "$linex")               # this is for 200OK INFO
            if [[ $((infox)) != 0 ]]; then
			    infofound=1
            fi
		fi
	fi

    if [[ $((infofound)) == 0 ]]; then
#	   	sipmsg_header    
#  		start_sipmsg
#		get_useragent2    
		nlinex=$(wc -l <<< "$linex")
	   	let "siplines += $((nlinex))"
		if [[ $((base64decode)) != 0 ]]; then
			base64found=$(egrep -m 1 -c "^Base64 dump*" <<< "$linex")
	        if [[ $((base64found)) != 0 ]]; then
    			echo "# Base64 dump found" >> "$newfile"
	    		if [[ -f "$newfile.b64" ]]; then                                            # TODO: print lines until Base64, then rest goes into "$newfile.b64"
	        		rm "$newfile.b64"
	        	fi
    	        # awk '{ if $NF == "Base64 dump" then b64found=1 else print $NF ...}'
	    	else
		    	echo "$linex" >> "$newfile"
	        fi
		else
   			echo "$linex" >> "$newfile"
		fi

		if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
			if [[ $calltime == "" ]]; then
				linefrom=$(egrep -e "^From:|^To:" <<< "$linex" 2>/dev/null)
				lineid=$(egrep -e "^Call-ID:" <<< "$linex" 2>/dev/null)
				if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
   					calltime=$siptime
				fi
#				elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $sipline2 =~ ^Call-ID: ]]; then
#					callID=$line; callDIR=$dirdefined
			elif [[ $callDIR == 0 ]] && [[ $lineid != "" ]]; then
				callID=$lineid; callDIR=$dirdefined
	    	fi
		fi
	fi
} # explore_sipmsghdr()

function explore_sipmsg () {
	let nlinesX=0
	let insidesipX=0
	let currcseq=0
	let prevcseq=0
	cseqword=""
	currsipword=""; prevsipword=""
	linebufX=""; 	lineX=""
	linebkup=$line

	linebuf=$(sed 's/\\r\\n/\n/g' <<< "$linebuf")

	while IFS= read -r lineX
	do
		nlinesX=$((nlinesX+1))
		if [[ $lineX =~ ^[A-Z]+\ |^[1-7][0-9][0-9]\ |^SIP\/2.0\ |^,[A-Z].* ]]; then
			if [[ $((insidesipX)) != 0 ]]; then
				if [[ $prevsipword == $currsipword ]] && [[ $prevcseq == $currcseq ]]; then	# tshark extract repeated same SIP msg
					insidesipX=0; linebufX=""
					currcseq=0; cseqword=""
				elif [[ $currcseq == 0 ]] || [[ $cseqword == "" ]]; then					# SIP msg without CSeq: is considered invalid
					insidesipX=0; linebufX=""
					currcseq=0; cseqword=""
				else
			 	    siptotalmsg=$((siptotalmsg+1))				
					linebufX=$(sed 's/\\r\\n/\n/g' <<< "$linebufX")
					line=$(head -1 <<< "$linebufX")

					sipmsg_header; start_sipmsg

					tail -n +2 <<< "$linebufX" >> "$newfile"
					nlinesX=$(wc -l <<< "$linebufX")
				   	let "siplines += $((nlinesX-1))"
					if [[ $findANI != "" ]] && [[ $callDIR == 0 ]] && [[ $currsipword == "INVITE" ]]; then
						linefrom=$(egrep -e "^From:|^To:" <<< "$linebufX")
						if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
							callID=$(egrep -e "^Call-ID:" <<< "$linebufX")							
							callDIR=$dirdefined; calltime=$siptime							
						fi
					fi

					complete_sipmsg2
					insidesipX=0; linebufX=""
					prevcseq=$currcseq
					prevsipword=$currsipword
					currcseq=0; cseqword=""
				fi
			fi

			if [[ $lineX =~ ^,[A-Z].* ]]; then 								# tshark bug: starting line with ", From:"
				continue
			elif [[ $((insidesipX)) != 0 ]]; then
				currsipword=$(cut -d' ' -f1 <<< "$lineX" | sed -e 's/[[:space:]]*$//')
				if [[ $noINFO == 1 ]] && [[ $currsipword == "INFO" ]]; then
					nINFO=$((nINFO+1))
					insidesipX=0; linebufX=""
					currcseq=0; cseqword=""
				else
					insidesipX=1; linebufX="$lineX"
				fi
			fi

		elif [[ $((insidesipX)) != 0 ]]; then
			if [[ $cseqword == "" ]] && [[ $lineX =~ ^CSeq: ]]; then
				currcseq=$(cut -d' ' -f2 <<< "$lineX")
				cseqword=$(awk '{print $3}' <<< "$lineX")					# would be better taking whole line or rest of string $3 inclusive
				if [[ $noINFO == 1 ]] && [[ $cseqword == "INFO" ]]; then
					nINFO=$((nINFO+1))
					insidesipX=0; linebufX=""
					currcseq=0; cseqword=""
				fi
			elif [[ $useragent == "" ]] && [[ $lineX =~ ^User-Agent: ]]; then
				get_useragent3			
			fi

			if [[ $((insidesipX)) != 0 ]]; then
				linebufX="$linebufX\r\n$lineX"
			fi
		fi
	done <<< "$linebuf"

	if [[ $((insidesipX)) != 0 ]] && [[ $linebufX != "" ]]; then
		if [[ $prevcseq != 0 ]] && [[ $prevcseq == $currcseq ]] && [[ $prevsipword == $currsipword ]]; then
			insidesipX=0; linebufX=""
		elif [[ $currcseq != 0 ]] && [[ $cseqword != "" ]]; then
			siptotalmsg=$((siptotalmsg+1))		
			linebufX=$(sed 's/\\r\\n/\n/g' <<< "$linebufX")		
			line=$(head -1 <<< "$linebufX")

			sipmsg_header; start_sipmsg

			tail -n +2 <<< "$linebufX" >> "$newfile"
			nlinesX=$(wc -l <<< "$linebufX")
		   	let "siplines += $((nlinesX-1))"
			if [[ $findANI != "" ]] && [[ $callDIR == 0 ]] && [[ $currsipword == "INVITE" ]]; then
				linefrom=$(egrep -e "^From:|^To:" <<< "$linebufX")
				if [[ $linefrom != "" ]] && [[ $linefrom =~ $findANI ]]; then
					callID=$(egrep -e "^Call-ID:" <<< "$linebufX")							
					callDIR=$dirdefined; calltime=$siptime							
				fi
			fi
			complete_sipmsg
		fi
	else
		reset_sipmsg
	fi

	line=$linebkup
} # explore_sipmsg ()

function explore_sipcont () {
   	if [[ $((xxdexist)) == 1 ]]; then
#		line=$(echo $sipcont | xxd -r -p | sed 's/\\r\\n/\n/g')
#		line=$(echo $sipcont | sed 's/0d0a/0a/g' | xxd -r -p)
		linex=$(xxd -r -p <<< "$sipcont")
	else
	   	hex2str 								# converts $sipcont to $line - this will be much slower than xxd
		linex=$line
	fi

#	if [[ $prevline != "" ]]; then
#       	linex="$prevline$line"; prevline=""
#  	fi
	line=$(head -1 <<< "$linex")
	linex=$(tail -n +2 <<< "$linex")
	sipcont=""
} # explore_sipcont()

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":e:hbdf:Ss:p:N:I" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	S)
		sipstat=0;;	
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;		
	e)
		endptaddr=${OPTARG};;
	s)
		srvraddr=${OPTARG};;
    I)
		noINFO=1;;	
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	f)
		voutput=${OPTARG}
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi;;
	p)
		if [[ ${OPTARG} == "UDP" ]] || [[ ${OPTARG} == "udp" ]] || [[ ${OPTARG} == "Udp" ]]; then
			protoPCAP="UDP"
		elif [[ ${OPTARG} == "TCP" ]] || [[ ${OPTARG} == "tcp" ]] || [[ ${OPTARG} == "Tcp" ]]; then
			protoPCAP="TCP"
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

skipper=0; var=""

if [[ $((base64decode)) != 0 ]]; then
	base64 --help >/dev/null 2>&1
	if [[ $? != 0 ]]; then
		base64decode=0
	fi
fi

xxd --version 2>/dev/null
if [[ $? != 0 ]]; then
  xxdexist=0
else
  xxdexist=1
fi

for var in "$@"
	do

	if [[ $var == "-"* ]]; then
  		if [[ $var == "-f"* ]]; then
			skipper=1
		elif [[ $var == "-e"* ]]; then
			skipper=2
		elif [[ $var == "-p"* ]]; then
			skipper=3
		elif [[ $var == "-N"* ]]; then
			skipper=4
		elif [[ $var == "-s"* ]]; then
			skipper=5
		else
			skipper=0
		fi
		var="": continue
	elif [[ $skipper != 0 ]]; then
		case $skipper in
		1)	voutput="$var"
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
				voutput=1
			fi;;
		2)	endptaddr="$var";;
		3)	protoPCAP="$protoPCAP";;
		4)	findANI=$findANI;;		# findANI=$var
		5)  srvraddr="$var";;
		esac
		skipper=0; var=""		
		continue
	fi
	
	file="$var"
	bvar=$(basename "$var")
	currtime=$(date +%R:%S)
	error=0; vsyslog=0
	rec=0; tmpfile=0
	sipfile=""

	if [ -s "$file" ]; then
		echo -en "\nExploring content in $bvar... stand by\r"

		filetype=$(file -b "$file")
# J139_C81FEAE671EE_202302151422.pcap.sip.txt: ASCII text, with very long lines, with CRLF line terminators		
		if [[ $filetype == *"tcpdump capture file"* ]] || [[ $filetype == *"pcap-ng capture file"* ]]; then
			sharkfilter=""
			if [[ $endptaddr != "" ]]; then
				if [[ $srvraddr == "" ]]; then
					sharkfilter="ip.addr==$endptaddr"
				else
					sharkfilter="ip.addr==$endptaddr && ip.addr==$srvraddr"
				fi
			elif [[ $srvraddr != "" ]]; then
					sharkfilter="ip.addr==$srvraddr"
			fi

			if [[ $protoPCAP == "TCP" ]]; then
				sharkfilter="$sharkfilter && tcp"
			elif [[ $protoPCAP == "UDP" ]]; then
				sharkfilter="$sharkfilter && tcp"
			fi
			if [[ $sharkfilter == "" ]]; then
				sharkfilter="sip"
			else
				sharkfilter="$sharkfilter && sip"
			fi

			TSHARK="tshark"
			line=$(whereis $TSHARK 2>&1)
			tsharkversion=$($TSHARK --version 2>&1 | head -1)

			if [[ $tsharkversion =~ found ]]; then
				if [[ $line =~ tshark\.exe ]]; then
					echo LINE=$line
				else
					echo tsharkversion=$tsharkversion
				fi
			elif [[ $? != 0 ]] || [[ ${#line} -lt 8 ]]; then
			echo TSharkversion=$tsharkversion				
		    	echo -e "\nerror: unable to locate 'tshark' command - 'tshark' is required to convert $bvar wireshark capture into text file.\n"
				error=10; exit $error
			elif [[ ${#line} -gt 10 ]]; then
				sipfile="$file.sip.txt"
# tshark -r "$file" -S=== -2Y "$sharkfilter" -t ad -T fields -E separator="#" -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e ip.proto -e sip.Request-Line -e sip.Status-Line -e sip.msg_hdr -e sip.continuation > "$sipfile.tmp"
#				tshark -r "$file" -S=== -2Y "$sharkfilter" -t ad -T fields -E separator="#" -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e ip.proto -e sip.Request-Line -e sip.Status-Line -e sip.msg_hdr -e sip.continuation | sed 's/\\r\\n/\n/g' > "$sipfile"
				tshark -r "$file" -S=== -2Y "$sharkfilter" -t ad -T fields -E separator="#" -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e ip.proto -e sip.Request-Line -e sip.Status-Line -e sip.msg_hdr -e sip.continuation > "$sipfile"
				if [ -f "$sipfile" ]; then
					file="$sipfile"; tmpfile=2
					nlines=$(wc -l < "$file")
					rec2=$(egrep -ce "CSeq:" < "$file" 2>/dev/null)
					rec=$(egrep -ce "^[0-9]+\#.*" < "$file" 2>/dev/null)									
#        	    	rec=$(egrep -ce ".*CSeq:.*" "$sipfile")
					if [[ $rec != $nlines ]] || [[ $rec2 == 0 ]]; then
						echo -e "\nerror: could not extract any valid SIP messages from this wireshark capture file: $bvar"
						if [[ $((rec2)) -gt 0 ]]; then
							echo "Though found $rec2 records of SIP message."
						fi
						echo -e "Verify source and content of $bvar.\n"
						error=1; continue
					fi
				fi
			fi

		elif [[ $filetype =~ ASCII|text|data ]]; then
			nlines=$(wc -l < "$file")
			rec=$(egrep -ce "^[0-9]+\#.*" "$file" 2>/dev/null)
			rec2=$(egrep -ce "CSeq:" "$file" 2>/dev/null)
			if [[ $rec != $nlines ]] || [[ $rec2 == 0 ]]; then
				echo -e "\nerror: $bvar is an ASCII text file, but it does not appear to be a valid SIP extract from a wireshark capture file."
				if [[ $((rec2)) -gt 0 ]]; then
					echo "Though found $rec2 records of SIP message."
					asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
					if [[ $((asmfile)) != 0 ]]; then
						asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
						if [[ $((asmfile)) != 0 ]]; then
							echo "It appears $bvar is a traceSM file (or a converted file using 3rd output format)."
							echo "This kind of input is not (yet) supported by this tool."
						fi
					fi
				fi
				echo -e "Verify source and content of $bvar.\n"
				error=1; continue
			fi
		else 
			echo -e "\nerror: $bvar does not appear to be a wireshark capture file."
			echo -e "Verify source and content of $bvar.\n"
			error=1; continue
        fi

		if [[ $rec == 0 ]];	then
			error=2
		 	echo  -e "\nerror: no SIP messages have been found in $bvar"
			echo  "This wireshark capture does not include any SIP messages using either UDP or TCP transport."
			echo  "Was SIP transport using TLS perhaps?"

			if [[ $tsharkversion != "" ]]; then
				echo  "Checking syslog packets..."
				echo ''; sample=""			

				tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog"
				sample=$(egrep -m 10 "User-Agent:" "$file.syslog")
				if [[ $sample =~ B199 ]]; then
					echo "Nonetheless, found syslog sent by B199 conferencing phone."
					echo "Try to execute 'traceB199.sh $var'"
				elif [[ $sammple =~ B179 ]]; then
					echo "Nonetheless, found syslog sent by B179 conferencing phone."
					echo "Try to execute 'traceB179.sh $var'"
				elif [[ $sample =~ Deskphone ]] || [[ $sample =~ J1 ]] || [[ $sample =~ 96 ]]; then
					echo "Nonetheless, found syslog sent by 96x1SIP or J100SIP deskphone."
					echo "Try to execute 'trace96x1.sh $var'"
				elif [[ $sample =~ VDI ]]; then
					echo "Nonetheless, found syslog sent by VDI-C or Equinox/Workplace VDI client."
					echo "Try to execute 'traceVDIC.sh $var'"
				elif [[ $sample =~ H175 ]]; then				
					echo "Nonetheless, found syslog sent by H175 video deskphone."
					echo "Try to execute either 'traceVDIC.sh $var' or 'trace96x1.sh $var'"
				elif [[ $sample =~ IPDECT ]]; then				
					echo "Nonetheless, found syslog sent by IPDECT SC box."
					echo "Try to execute 'traceB169.sh $var'"
				elif [[ $sample =~ Session ]]; then				
					echo "Nonetheless, found syslog sent by ASM."
					echo "Try to execute 'traceASM.sh $var'"
				elif [[ $sample =~ Border ]] || [[ $sample =~ SBC ]]; then				
					echo "Nonetheless, found syslog sent by SBC."
					echo "Try to execute 'traceSBC.sh $var'"
				fi
				rm "$file.syslog" 2>/dev/null
				echo ''; continue
			fi

		else
			echo ''
#			echo "Found $rec SIP messages in $var."
#			if [[ $protoPCAP != "" ]]; then
#				echo "Filtered for $protoPCAP only transport"
#			fi
#			echo "Refer to $sipfile"
#			echo ''

			logsec=$SECONDS
			base64msg=0
			foundipaddr=""
			useragent=""
			line=""
			nlines=0
			sipmonth=""
			sipday=""
			siphour=""
			sipmin=""
			sipsec=""
			sipmsec=""
			n=0
			nINFO=0
			infofound=0
			nCont=0
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
			sipline1=""; siprequest=""
			sipline2=""; sipstatus=""
			sipcont=""; sipmsghdr=""
			sipin=0
			sipout=0
			insidemsg=0
			linebuf=""
	
			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo -e "You may want to execute this script on a more powerful PC or server.\n"
			fi

			newfile="$file.asm.tmp"
			if [ -f "$newfile" ]; then
				rm "$newfile"
			fi
			echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
			echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
			echo "# Command line: $args" >> "$newfile"
    		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
			echo "# $tsharkversion" >> "$newfile"			
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
			if [[ $protoPCAP != "" ]]; then
				echo "# Protocol selected: $protoPCAP" >> "$newfile"
			fi

			if [[ $sipfile != "" ]]; then
				echo -e "# Input/output file history: $var -> $sipfile -> $var.asm\n" >> "$newfile"
			else
				echo -e "# Input/output file history: $var -> $var.asm\n" >> "$newfile"
			fi

			while IFS= read -r line
			do
				nlines=$((nlines+1))
                if [[ $((insidemsg)) != 0 ]] && [[ ${line: -2:1} == "#" ]]; then
					explore_sipmsg
				fi
			    
				if [[ $line =~ ^[0-9]+\#[0-9]+\.[0-9]{9}\#.* ]]; then
			   		sip_direction                                      # this sets $siprequest, $sipstatus, $sipmsghdr, $sipcont
					if [[ $dirdefined == 0 ]]; then
						reset_sipmsg; continue
					elif [[ $ip1 != "" ]] && [[ $endptaddr != "" ]] && [[ $ip1 != $endptaddr ]]; then
						if [[ $localip1 != "" ]] && [[ $endptaddr != "" ]] && [[ $localip1 != $endptaddr ]]; then
							reset_sipmsg; continue
						fi
				   	elif [[ $((insidemsg)) != 0 ]]; then
						if [[ $sipmsghdr != "" ]] && [[ ${#sipcont} -lt 2 ]]; then
							explore_sipmsg
						elif [[ $sipmsghdr == "" ]] && [[ ${#sipcont} -gt 1 ]]; then
						   	if [[ $((xxdexist)) == 1 ]]; then
								line=$(xxd -r -p <<< "$sipcont")
							else
						   		hex2str 								# converts $sipcont to $line - this will be much slower than xxd
							fi

							if [[ $linebuf == "" ]]; then
								linebuf="$line"
							elif [[ $line != "" ]]; then
								linebuf="$linebuf\r\n$line"
							fi

							nCont=$((nCont+1))
							continue
						fi				   	
					fi

					if [[ $sipmsghdr != "" ]]; then
			 	   		insidemsg=1
			 	    	get_sip_datetime
				    	line=$(cut -d',' -f1 <<< "$sipline1")			# multiple requests (or status) separated by comma
#						linex=$(sed 's/\\r\\n/\n/g' <<< "$sipmsghdr")
#			 	    	siptotalmsg=$((siptotalmsg+1))
#						linebuf="$line\r\n$linex"	
						linebuf="$line\r\n$sipmsghdr"
#						explore_sipmsghdr								# collect SIPmsg into $linebuf only, instead of writing into $newfile

#						if [[ ${#sipcont} -lt 2 ]] && [[ $((infofound)) == 0 ]]; then
#							complete_sipmsg
						if [[ ${#sipcont} -gt 1 ]]; then
#							if [[ $((infofound)) != 0 ]]; then
#								complete_sipmsg2
#							fi
#							explore_sipcont
							if [[ $((xxdexist)) == 1 ]]; then
								line=$(xxd -r -p <<< "$sipcont")
							else
							   	hex2str 								# converts $sipcont to $line - this will be much slower than xxd
							fi
							linebuf="$linebuf\r\n$line"
							nCont=$((nCont+1))							
						fi

#						linebuf=$(sed 's/\\r\\n/\n/g' <<< "$linebuf")
#						explore_sipmsg							# find unique SIP messages from $linebuf and write into $newfile

				   	elif [[ ${#sipcont} -gt 1 ]]; then
#						if [[ $((sipstart)) == 1 ]]; then
#							complete_sipmsg2
#						fi
						if [[ $((xxdexist)) == 1 ]]; then
							line=$(xxd -r -p <<< "$sipcont")
						else
						   	hex2str 								# converts $sipcont to $line - this will be much slower than xxd
						fi
						linebuf="$linebuf\r\n$line"
						nCont=$((nCont+1))						
#						explore_sipcont
				   	fi           
				fi
			done < "$file"		

			if [[ $((insidemsg)) != 0 ]]; then					# TODO: verify
				explore_sipmsg				
			fi
			echo '' >> "$newfile"

			if [[ $output == "" ]]; then
				output=$var
			fi
		
			if [[ $((error)) != 0 ]]; then
				echo -e "\n\tError found: $error\n\n"

			elif [[ $((sipmsg)) -lt 1 ]]; then
				echo -e "\nError: No SIP messages have been found in $bvar. Contact developer."

	        elif [[ $((sipstat)) != 0 ]]; then
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
						if [[ ${#server} -lt 68 ]]; then
							echo -e "\t\t$server"
						else
							echo -e "\t$server"
						fi
					fi
				fi

				echo -e "\n\tTotal # of SIP packets digested:\t\t $nlines"

				if [[ $((sipmsg)) != 0 ]]; then
					if [[ $((nCont)) != 0 ]]; then
						echo -e "\tEmbedded SIP messages (Continuation):\t\t $nCont"
					fi
					echo -e "\tTotal # of SIP messages processed (RX/TX):\t $siptotalmsg ($sipin/$sipout)"
					echo -e "\tLongest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)"
					echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
					if [[ $((nINFO)) != 0 ]]; then
						echo -e "\tINFO messages ignored:\t\t\t $nINFO"
					fi
					if [[ $((base64decode)) != 0 ]] && [[ $base64msg != 0 ]]; then
						echo -e "\tBase64 encoded SIP messages:\t\t\t$base64msg"
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
				echo -e "\nConversion of $file has ended with error code=$error num of SIP msg=$n sipwords=$sipwordlist"
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
			pwd;ls -l "$var.asm"
			echo ''
			if [[ $bDelTemp != 0 ]]; then
				if [[ $tmpfile == 2 ]] && [[ $var != $file ]] && [ -f "$file" ]; then
					rm "$file" 2>/dev/null
				fi
			fi
		fi

	elif [ -f "$var" ]; then
		echo -e "\nerror: $bvar is an empty file."
		ls -l "$var"
		error=3; continue
	elif [ -d "$var" ]; then
		echo -e "\nerror: $bvar is a folder.  Folder is not a supported input."
		error=3; continue
	else
		echo -e "\nerror: $bvar was not found. Verify path and filename."
		error=3; continue		
	fi
done

if [[ $var == "" ]] && [[ $output == "" ]]; then
	usage
fi
exit 0