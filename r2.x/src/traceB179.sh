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
pattern2="^\-\-\-.*\-\-\-$"
sipstat=1
findANI=""
bCAT=0
bDelTemp=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0
sipstart=0

## b179-siptraces-r2435.txt or B179-syslog4.log
## Sep 16 13:24:16: TX 699 bytes Request msg REGISTER/cseq=8992 (tdta0x32ec60) to tcp 10.133.93.42:5060:
## 31 = ade_b179_syslog.txt - where line starts with <13x> or <14x>
##<142>Jan  1 01:06:02 konfsip[1166:1166]: TX 713 bytes Request msg REGISTER/cseq=31564 (tdta0x341fb8) to tls 135.124.168.107:5061:
## 32 = B179-syslog[123].txt - maybe SyslogCatchALL? to be confirmed // SIP msg in single line
##10.240.171.142	Jul  4 10:57:56		local1	info	konfsip[1047:1047]	TX 723 bytes Request msg REGISTER/cseq=55548 (tdta0x3558e0) to tcp 10.159.23.135:5060: REGISTER sip:10.159.23.135;transport=tcp SIP/2.0 Via: SIP/2.0/tcp 10.240.171.142:16385;rport;branch=z9hG4bKPjZVo1Z5hYxl46LKSawzaTxQ0n7UOnnrqf;alias Route: <sip:10.159.23.135;transport=tcp;lr> Max-Forwards: 70 From: <sip:48221281884@10.159.23.135>;tag=mLqeboODq4PzUPm.doTlY1h7qL8p.H5G To: <sip:48221281884@10.159.23.135> Call-ID: oeiVVBOOWsI6DK718nWPTwPe9LapZ1SX CSeq: 55548 REGISTER User-Agent: Avaya B179 2.4.1.4 Supported: outbound, path Contact: <sip:48221281884@10.240.171.142:5060;transport=TCP;ob>;reg-id=1;+sip.instance="<urn:uuid:00000000-0000-0000-0000-0000d55b02c6>" Expires: 1800 Allow: PRACK, INVITE, ACK, BYE, CANCEL, UPDATE, INFO, SUBSCRIBE, NOTIFY, REFER, MESSAGE, OPTIONS Content-Length:  0   --------------------------------------------------------------------------------- 

function usage ()  {
    echo "traceB179.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t       created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceB179.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the SIP message text buffer extracted from Konftel 300IP(x) or Avaya B179"
	echo -e '\t\t\tor a syslog file collected by a remote syslog server (KIWI, tftpd64, MEGA, etc.),'
	echo -e '\t\t\tor a syslog txt stream extracted from network pcap trace (using Follow UDP stream),'
	echo -e '\t\t\tor a native pcap network trace including unsecure syslog traffic (requires "tshark")'
	echo -e "\n  Options:"
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"		
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"	
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"		
	echo -e "\t-s \t\tdo not provide statistics/progress on execution or result of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
	echo -e '  Note:\t\t\tB179 does not log year & millisecond values in date/timestamps'
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	sipsplit=0
	dirdefined=0	
#	sipyear=""; localip=""
	ip=""
	partnum="00"; maxpart="99"
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

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile".b64 ]]; then
		blines=$(base64 -d "$newfile.b64" | wc -l)
		siplines=$((siplines+$blines))
		base64 -d "$newfile.b64" >> "$newfile"
		rm "$newfile.b64"
		base64found=0
		base64msg=$((base64msg+1))
	fi

	if [[ $((sipsplit)) != 0 ]]; then
		sipmaxsplit=$((sipmaxsplit+1))
		if [[ ${maxpart#0} -gt $((sipmaxpart)) ]]; then
			sipmaxpart=${maxpart#0}
		fi
		partnum="00"; maxpart="99"
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
		sipstart=0; 	n=$((n+1))
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

function sip_partnum () {
	if [[ $line == *"[Part "* ]]; then
		partnum=$(awk -F "Part " '{print $2}' <<< "$line" | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
			maxpart=$(awk -F "Part " '{print $2}' <<< "$line" | cut -d' ' -f3 | cut -d']' -f1)
			# maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d ' ' -f 3)
		fi	
		sipsplit=1
	fi
} # sip_partnum

function sip_direction () {
#B179: Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
#B199: Sep 30 11:20:40 phoneapp[1064]: pjsip: 11:20:40.606   pjsua_core.c  ....TX 1252 bytes Request msg INVITE/cseq=15681 (tdta0x53a3314) to TLS 10.134.117.194:5061:
if [[ $((dirdefined)) == 0 ]]; then	
	if [[ $line == *" Response "* ]]; then
		sipstream=5f70; 		dirdefined=1
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)	dirstring1="-->"; 	dirstring2="ingress";;
		esac

	elif [[ $line == *" Request "* ]]; then
		sipstream=1474; 		dirdefined=2
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

# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:			!!no konfsip !!!			  
# Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
# 10.158.86.187	Jul  4 12:57:39		local1	info	konfsip[1031:1031]	TX 714 bytes Request msg REGISTER/cseq=19364 (tdta0x348368) to tcp 10.154.75.7:5060: REGISTER sip:10.154.75.7;transport=tcp SIP/2.0 Via: 
# <142>Jan  1 01:07:45 konfsip[1367:1367]: TX 712 bytes Request msg REGISTER/cseq=3361 (tdta0x335f10) to tls 135.124.168.107:5061:

    if [[ $((dirdefined)) != 0 ]]; then
		case $vsyslog in
	    1)
		    siplength=$(awk '{print $7}' <<< "$line")  # cut -d' ' -f7)      not good due to multiple spaces at DAY
		    ip=$(awk '{print $(NF)}' <<< "$line");;
	    30)
		    siplength=$(awk '{print $5}' <<< "$line")  # cut -d' ' -f5)      not good due to multiple spaces at DAY
		    ip=$(awk '{print $(NF)}' <<< "$line");;
		31)
			siplength=$(awk '{print $9}' <<< "$line")  # cut -d' ' -f9) 
			ip=$(awk '{print $17}' <<< "$line");;      # cut -d' ' -f17)
	    38)
# Jan 1 01:06:02 konfsip[1166:1166]: TX 713 bytes Request msg REGISTER/cseq=31564 (tdta0x341fb8) to tls 135.124.168.107:5061:
    	    siplength=$(awk '{print $6}' <<< "$line")  # cut -d' ' -f6)   
		    ip=$(awk '{print $NF}' <<< "$line");;
		39)
            siplength=$(awk '{print $6}' <<< "$line")  # cut -d' ' -f6)   
		    ip=$(awk '{print $NF}' <<< "$line");;
		esac

	    ip1=$(cut -d':' -f1 <<< "$ip")              # awk -F ":" '{print $1}')
	    ip2=$(cut -d':' -f2 <<< "$ip")              # awk -F ":" '{print $2}')
	    ip=$ip1:$ip2		
		foundipaddr=""		
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
	if [[ $sipmonth == "666" ]]; then
		echo -e "\nerror: found non-english MONTH: $month - contact developer.\n"
		echo -e "line=$line\n"; exit 1
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
   	if [[ $((vsyslog)) == 1 ]]; then
# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:			!!no konfsip !!!			  
# Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
# 10.158.86.187	Jul  4 12:57:39		local1	info	konfsip[1031:1031]	TX 714 bytes Request msg REGISTER/cseq=19364 (tdta0x348368) to tcp 10.154.75.7:5060: REGISTER sip:10.154.75.7;transport=tcp SIP/2.0 Via: 
# <142>Jan  1 01:07:45 konfsip[1367:1367]: TX 712 bytes Request msg REGISTER/cseq=3361 (tdta0x335f10) to tls 135.124.168.107:5061:

       month=$(awk '{print $3}' <<< "$line")
       sipday=$(awk '{printf "%02i",$2}' <<< "$line")     # cut -d' ' -f2)							
	   sipmsec=$(awk '{print $3}' <<< "$line")             # cut -d' ' -f3) not good due to multiple spaces

	elif [[ $((vsyslog)) == 30 ]]; then
# Jun 20 09:49:09: TX 561 bytes Request msg REGISTER/cseq=2811 (tdta0x2d59c8) to UDP 10.134.117.194:5060:
# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:	
	   month=$(awk '{print $1}' <<< "$line")
	   sipday=$(awk '{printf "%02i",$2}' <<< "$line")     # cut -d' ' -f2)
	   sipmsec=$(awk '{print $3}' <<< "$line")

    elif [[ $((vsyslog)) == 31 ]]; then
# 10.158.86.187	Jul  4 12:57:39		local1	info	konfsip[1031:1031]	TX 714 bytes Request msg 
	   month=$(awk '{print $2}' <<< "$line")
	   sipday=$(awk '{printf "%02i",$3}' <<< "$line")     # cut -d' ' -f2)
	   sipmsec=$(awk '{print $4}' <<< "$line")

    elif [[ $((vsyslog)) == 38 ]]; then
# Jan 1 01:06:02 konfsip[1166:1166]: TX 713 bytes Request msg REGISTER/cseq=31564 (tdta0x341fb8) to tls 135.124.168.107:5061:
	   month=$(cut -d' ' -f1 <<< "$line")
	   sipday=$(awk '{printf "%02i",$2}' <<< "$line")     # cut -d' ' -f2)
	   sipmsec=$(awk '{print $3}' <<< "$line")
  
    elif [[ $((vsyslog)) == 39 ]]; then
# <142>Jan  1 01:07:45 konfsip[1367:1367]: TX 712 bytes Request msg REGISTER/cseq=3361 (tdta0x335f10) to tls 135.124.168.107:5061:
	   month=$(cut -d' ' -f1 <<< "$line" | cut -d'>' -f2)
	   sipday=$(awk '{printf "%02i",$2}' <<< "$line")     # cut -d' ' -f2)
	   sipmsec=$(awk '{print $3}' <<< "$line")				# TODO should be 3 instead of 4?
    fi

	get_sipmonth
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

function convert_siplog() {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

#	echo "                                                                                                                                                  "
    rec=$(egrep -c " bytes Re" < "$file")
    if [[ $rec == 0 ]]; then
	   	echo "error: $basefile file is empty - no TX/RX SIP messages found in the expected format."
	   	error=1; rec=$(egrep -c -e "^CSeq:*" "$file" 2>/dev/null)
	    if [[ $rec == 0 ]]; then
		    echo "In fact, no sign of any \"CSeq:\" lines within $basefile"
		    rec=0; error=2
		else
		    echo "Though, found $rec lines with \"CSeq:\" - so there might be some SIP messages within $basefile"
			rec=0; error=3
		fi
    else
        prevline=$(egrep -m 1 " bytes Re" "$file" 2>/dev/null)
 	    if [[ $prevline == *"konfsip"* ]]; then
	        n=$(egrep -c -e "^<[0-9]{3}>" <<< "$prevline" 2>/dev/null)
	        if [[ $((n)) != 0 ]]; then
		       vsyslog=39
	        elif [[ $prevline == *"local1"* ]]; then
		        vsyslog=31
			elif [[ $prevline =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then				# syslog extracted via tshark
				vsyslog=38			
		    else
                line=$(awk '{print $6}' <<< "$prevline")
	            if [[ $line =~ TX|RX ]]; then
			       vsyslog=1
			 	fi
	      	fi
        else
# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:  !!! no konfsip !!! eg. this is a 300IP phone
# Jun 20 09:49:09: TX 561 bytes Request msg REGISTER/cseq=2811 (tdta0x2d59c8) to UDP 10.134.117.194:5060:
# Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
	         #vsyslog=30
			 line=$(awk '{print $4}' <<< "$prevline")
			 if [[ $line =~ TX|RX ]]; then
                vsyslog=30
			 fi
	    fi
	fi

   	if [[ $((vsyslog)) == 0 ]]; then
		if [[ $file =~ \.asm$ ]] || [[ $file =~ \.casm$ ]] || [[ $file =~ \.asm\.bak$ ]]; then
			footprint=$(egrep -c -m 1 "SIPlog2traceSM" "$file")
			if [[ $footprint == 1 ]]; then
				echo "$basefile appears to be an .asm file created by SIPlog2traceSM tool."
			fi
		else
			echo -e "\nerror: $basefile file does not appear to be related to a valid B179 log."
		    echo -e "Verify source and content of this file.\n"
		fi
	else
	    line=""
		prevline=""
        localip="1.1.1.1:1111"
	    sipyear=$(cut -d'/' -f3 <<< "$today")			  

		logsec=$SECONDS
		base64msg=0
		foundipaddr=""
		useragent=""
		prevline=""
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
		sipin=0
		sipout=0
		nlines=0
		n=0
		sipmsg=0
		sipmatch=0	

        reset_sipmsg

		if [[ $rec -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo "You may want to execute this script on a more powerful PC or server."
		fi		

#	    conv=$(awk -e '/bytes Re/{flag=1} flag; /}/{flag=0}' "$file")
	    conv=$(awk -W source='/bytes Re/{flag=1} flag; /}/{flag=0}' "$file")

		if [[ $file == *"/"* ]]; then 
#			basefile=$(echo "${file#*/}")
			basefile=$(basename "$file")			
		else
			basefile=$file
		fi
		bfile=""
		if [[ $basefile != "" ]] && [[ $basefile == *"."* ]]; then
			bfile=${basefile%.*}
		fi

		if [[ $var != $basefile ]] && [[ $basefile != $file ]]; then
			xfile=$(echo "${var%%.*}")
			if [[ $var == $basefile ]]; then
				output=$var
			elif [[ $xfile != $basefile ]] && [[ $xfile != "" ]]; then
				output="$xfile-$basefile"
			else
				output=$var
			fi
		else
			output=$basefile
		fi

		bakfile=""
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
			echo -e "# Input/output file history: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file history: $var -> $output.asm\n" >> "$newfile"
		fi

		while IFS= read -r line
			do
				nlines=$((nlines+1))
				if [[ $line == *" bytes Re"* ]] && [[ $line != *"pjsip"* ]]; then		# ignore pjsip from B199, in mixed syslog
				    if [[ $((sipstart)) != 0 ]]; then
				        complete_sipmsg
				    fi
					insidesip=1
					siptotalmsg=$((siptotalmsg+1))	
					sip_direction
					get_sip_datetime
                    sipmsg_header

					if [[ $((vsyslog)) == 31 ]] && [[ $((dirdefined)) != 0 ]]; then 	# syslog from pcap manually
						linex=$(awk -F "$ip1:$ip2: " '{print $2}' <<< "$line")
						line=$(awk -F '---' '{print $1}' <<< "$linex")
						start_sipmsg
						get_useragent
						if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
							if [[ $calltime == "" ]] && [[ $line =~ From:|To: ]] && [[ $line =~ $findANI ]]; then
								calltime=$siptime
							elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
								callID=$line; callDIR=$dirdefined
							fi
						fi

						complete_sipmsg
						siplines=$((siplines+1))
					fi		

				elif [[ $((insidesip)) == 0 ]]; then
					continue

				elif [[ $line == "---------------------------------------------------------------------------------"* ]]; then
				    complete_sipmsg
				elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
			    	start_sipmsg					
				elif [[ $((sipstart)) != 0 ]];	then
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
				    elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
					    echo "$line" >> "$newfile.b64"
				    else					
					    echo "$line" >> "$newfile"
					    siplines=$((siplines+1))
					    get_useragent
					fi
				fi
#				prevline=$line
			done <<< "$conv"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi

		if [[ $((sipstat)) == 1 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm file"
			elif [[ $((sipmsg)) == 0 ]]; then 
				echo "==> no SIP messages were found for addr=$endptaddr in $var file"
			else
				echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
				echo "    have been converted for addr=$endptaddr into ""$output.asm"" file"
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
						echo -e "\tLast  msg:\t$lastmsg\t\t $timelast"
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

		if [[ $bDelTemp != 0 ]] && [[ $tmpfile == 1 ]] && [[ $file != $var ]] && [ -f "$file" ]; then
			rm "$file"
		fi
		echo ''
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
  while getopts ":e:hbf:sdCN:" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
	d)
		bDelTemp=0;;
	b)
		base64decode=0;;
	e)
		endptaddr=${OPTARG};;
	C)
		bCAT=1;;
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

	file=""; 	filelist=""
	currtime=$(date +%R:%S)
	currdir=$PWD
	tmpfile=0; 	output=""; 	target=""
	n=0; 	error=0;		vsyslog=0

	filetype=$(file -b "$var")
	filetype2=$(file -bZ "$var")		
	filecontent="B199"
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
	elif [[ $var == "." ]]; then
		target="B179"
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
	
	if [ -s "$var" ] && [ ! -d "$var" ]; then
		echo -en "\nExploring content in $var... stand by\r"
		##rec=$(grep -E "::SIP|\] PPM\:" $file| wc -l)
#		rec=$(egrep -m 1 -c "konfsip" < $file)
#        if [[ $rec == 0 ]]; 		then
#		   echo "error: $file is definetely not a B179 log file."
#		   echo "Verify source and content of this file."		
#        else

		if [[ $filetype1 =~ text ]] || [[ $filetype1 == "data" ]]; then
			file="$var"; filelist=""
			bSinglefile=1

		elif [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $var file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $var file."

		elif [[ $filetype =~ compressed ]]; then
				if [[ $filetype2 =~ ASCII|text|data ]]; then
				if [[ $file == *"."* ]]; then
					input=${file%.*}
				else
					input="$file"
				fi
				if [[ $bGunzip != 0 ]]; then
					echo "Uncompressing $file into $input ..."							
					gunzip -q -c "$file" > "$input" 2>/dev/null
					if [[ $? -le 1 ]]; then
						tmpfile=1
						file="$input"
						filetype=$(file -b "$file")
						filecontent="ASCII"
					else
#						filecontent="error"
						echo -e "\nerror: failed to uncompress $var, using \"gunzip\" utility.\n"
						error=8; continue
					fi
				else
					echo -e "error: unable to uncompress $var, \"gunzip\" utility not found.\n"
					error=8; continue
				fi
			fi
		fi

		if [[ $filetype =~ capture ]]; then
			if [[ $filetype =~ tcpdump ]] || [[ $filetype =~ pcap ]]; then
		  		line=$(whereis tshark)
				tshark --version >/dev/null 2>&1

				if [[ $? != 0 ]] || [[ ${#line} -le 10 ]]; then
		     		echo -e "\nerror: unable to locate 'tshark' command."
					echo  -e "'tshark' is required to extract syslog messages from $var wireshark capture into text file.\n"
					error=10; continue
				else
					if [[ $endptaddr != "" ]]; then
				    	tshark -r $file -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2" 2>/dev/null
					else
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2" 2>/dev/null
					fi
					if [ -s "$file.syslog2" ]; then					
						sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"					
					else
						echo -e "\nerror: could not extract any SYSLOG packets from $file using \"tshark\" command."
						echo ''; error=11; continue
					fi
					if [ -s "$file.syslog" ]; then
#						outfile="$file"
						rm "$file.syslog2" 2>/dev/null
						file="$file.syslog"; tmpfile=1
#						vsyslog=38
					else
						echo -e "\nerror: problem occured transforming $file.syslog2 into $file.syslog. Contact developer.\n"
						error=12; continue						
					fi
				fi
	  		fi

		elif [[ $file == "" ]] && [[ $error == 0 ]]; then
			echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
		fi

		if [[ $error != 0 ]]; then
			continue
		fi

		if [[ $input != "" ]]; then
			ctarget="$target.casm"
		elif [[ $ctarget == "" ]]; then
			ctarget="$target.casm"
		fi

		convert_siplog

		if [[ $error == 0 ]] && [[ $((bCAT)) != 0 ]] && [[ $output != "" ]] && [[ $((n)) != 0 ]]; then
			if  [ -f "$ctarget" ]; then
				mv "$ctarget" "$ctarget.bak"
			fi
			echo -e "Concatenating $var into $ctarget\n"
			echo -e "# Concatenating for $var\n" > "$ctarget"
			echo "# CAT $file" >> "$ctarget"
			echo -e "# ///////////////////////////////////////////////////////////////////////////////////////\n" >> "$ctarget"
			cat "$output.asm" >> "$ctarget"		
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

		if [[ $tmpfile == 1 ]] && [ -f "$file" ]; then
			rm "$file" 2>/dev/null
	fi
done

if [[ $((bCAT)) != 0 ]] && [ -f "$ctarget" ]; then
	echo -e "All ($converted) converted files have been concatenated into $ctarget."
	ls -l "$ctarget"; echo ''
elif [[ $((bCAT)) != 0 ]] && [[ $((converted)) == 0 ]]; then
	echo -e "No files have been converted."
fi
exit 0