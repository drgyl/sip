#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
pattern2="^\-\-\-.*\-\-\-$"
sipstat=1

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
    echo 'traceB179.sh v1.0 @ 2022 : converting SIP messages into a format required by traceSM tool'
	echo -e "\t\t\t\t\t\t\t   created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceB179.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the SIP message txt buffer taken from B179 SIP conference phone,"
	echo -e '\t\t\tor a syslog file collected by a remote syslog server (KIWI, tftpd64, MEGA, etc.),'
	echo -e '\t\t\tor a syslog txt stream extracted from network pcap trace (using Follow UDP stream),'
	echo -e '\t\t\tor a native pcap network trace including unsecure syslog traffic'
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"		
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution or result of this conversion"
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
#	sipyear=""
    emptyline=0
	dirdefined=0
#	localip=""
	ip=""
	partnum="00"
	maxpart="99"
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	emptyline=0
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
		partnum="00"
		maxpart="99"
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
		sipstart=0
		n=$((n+1))
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

function sip_partnum () {
	if [[ $line == *"[Part "* ]]; then
		partnum=$(echo "$line"     | awk -F "Part " '{print $2}' | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
			maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d' ' -f3 | cut -d']' -f1)
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

	elif [[ $line == *" Request "* ]]; then
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
	else
		insidesip=0
		dirdefined=0
	fi

# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:			!!no konfsip !!!			  
# Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
# 10.158.86.187	Jul  4 12:57:39		local1	info	konfsip[1031:1031]	TX 714 bytes Request msg REGISTER/cseq=19364 (tdta0x348368) to tcp 10.154.75.7:5060: REGISTER sip:10.154.75.7;transport=tcp SIP/2.0 Via: 
# <142>Jan  1 01:07:45 konfsip[1367:1367]: TX 712 bytes Request msg REGISTER/cseq=3361 (tdta0x335f10) to tls 135.124.168.107:5061:

    if [[ $((dirdefined)) != 0 ]]; then
	    if [[ $((vsyslog)) == 30 ]]; then
		    siplength=$(echo "$line" | awk '{print $5}')  # cut -d' ' -f5)      not good due to multiple spaces at DAY
		    ip=$(echo "$line" | awk '{print $(NF)}')
	    elif [[ $((vsyslog)) == 1 ]]; then
		    siplength=$(echo "$line" | awk '{print $7}')  # cut -d' ' -f7)      not good due to multiple spaces at DAY
		    ip=$(echo "$line" | awk '{print $(NF)}')
		elif [[ $((vsyslog)) == 31 ]]; then
			siplength=$(echo "$line" | awk '{print $9}')  # cut -d' ' -f9) 
			ip=$(echo $line | awk '{print $17}')          # cut -d' ' -f17)
	    elif [[ $((vsyslog)) == 38 ]]; then
# Jan 1 01:06:02 konfsip[1166:1166]: TX 713 bytes Request msg REGISTER/cseq=31564 (tdta0x341fb8) to tls 135.124.168.107:5061:
    	    siplength=$(echo "$line" | awk '{print $6}')  # cut -d' ' -f6)   
		    ip=$(echo $line | awk '{print $NF}')
		elif [[ $((vsyslog)) == 39 ]]; then
            siplength=$(echo "$line" | awk '{print $6}')  # cut -d' ' -f6)   
		    ip=$(echo $line | awk '{print $NF}')
		fi
		foundipaddr=""
	    ip1=$(echo $ip | cut -d':' -f1)              # awk -F ":" '{print $1}')
	    ip2=$(echo $ip | cut -d':' -f2)              # awk -F ":" '{print $2}')
	    ip=$ip1:$ip2		
	fi
fi	
} # sip_direction()

function get_sipmonth () {
   sipmonth="66"  
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
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
   if [[ $((vsyslog)) == 1 ]]; then
# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:			!!no konfsip !!!			  
# Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
# 10.158.86.187	Jul  4 12:57:39		local1	info	konfsip[1031:1031]	TX 714 bytes Request msg REGISTER/cseq=19364 (tdta0x348368) to tcp 10.154.75.7:5060: REGISTER sip:10.154.75.7;transport=tcp SIP/2.0 Via: 
# <142>Jan  1 01:07:45 konfsip[1367:1367]: TX 712 bytes Request msg REGISTER/cseq=3361 (tdta0x335f10) to tls 135.124.168.107:5061:

       month=$(echo "$line"   | awk '{print $3'})
       sipday=$(echo "$line"  | awk '{printf "%02i",$2}')     # cut -d' ' -f2)							
	   sipmsec=$(echo "$line" | awk '{print $3'})             # cut -d' ' -f3) not good due to multiple spaces

# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:	
    elif [[ $((vsyslog)) == 31 ]]; then
# 10.158.86.187	Jul  4 12:57:39		local1	info	konfsip[1031:1031]	TX 714 bytes Request msg 
	   month=$(echo "$line"   | awk '{print $2'})
	   sipday=$(echo "$line"  | awk '{printf "%02i",$3}')     # cut -d' ' -f2)
	   sipmsec=$(echo "$line" | awk '{print $4'})

    elif [[ $((vsyslog)) == 38 ]]; then
# Jan 1 01:06:02 konfsip[1166:1166]: TX 713 bytes Request msg REGISTER/cseq=31564 (tdta0x341fb8) to tls 135.124.168.107:5061:
	   month=$(echo "$line"   | cut -d' ' -f1)
	   sipday=$(echo "$line"  | awk '{printf "%02i",$2}')     # cut -d' ' -f2)
	   sipmsec=$(echo "$line" | awk '{print $3'})
  
    elif [[ $((vsyslog)) == 39 ]]; then
# <142>Jan  1 01:07:45 konfsip[1367:1367]: TX 712 bytes Request msg REGISTER/cseq=3361 (tdta0x335f10) to tls 135.124.168.107:5061:
	   month=$(echo "$line"   | cut -d' ' -f1 | cut -d'>' -f2)
	   sipday=$(echo "$line"  | awk '{printf "%02i",$2}')     # cut -d' ' -f2)
	   sipmsec=$(echo "$line" | awk '{print $4'})				# TODO should be 3 instead of 4?
    fi

	get_sipmonth
	siphour=$(echo $sipmsec | cut -d':' -f1)
	sipmin=$(echo $sipmsec  | cut -d':' -f2)
	sipsec=$(echo $sipmsec  | cut -d':' -f3)
	sipmsec="000"		

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
  while getopts ":e:hbf:s" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
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
		elif [[ $var == "-e"* ]]; then
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
	currdir=$PWD
	tmpfile=0
	outfile=""
	n=0
	error=0
	tmpfile=0
	vsyslog=0
	
	if [ -f $file ];then
		echo -en "Exploring content in $var... stand by\r"
		##rec=$(grep -E "::SIP|\] PPM\:" $file| wc -l)
#		rec=$(egrep -m 1 -c "konfsip" < $file)
#        if [[ $rec == 0 ]]; 		then
#		   echo "error: $file is definetely not a B179 log file."
#		   echo "Verify source and content of this file."		
#        else

		filetype=$(file -b "$file")
		filecontent="B119"

		if [[ $filetype == *"capture"* ]]; then
			if [[ $filetype == *"tcpdump"* ]] || [[ $filetype == *"pcap"* ]]; then
		  		line=$(whereis tshark)

				if [[ ${#line} -gt 10 ]]; then
					if [[ $endptaddr != "" ]]; then
				    	tshark -r $file -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi
					sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"					
					outfile="$file"
					rm "$file.syslog2"
					file="$file.syslog"
					tmpfile=1
#					vsyslog=38
		      	else
		     		echo "error: unable to locate 'tshark' command."
					echo  "'tshark' is required to extract syslog messages from $var wireshark capture into text file"
					echo ''
					error=10; #exit $error
					continue
				fi
	  		fi
		else
			outfile=$var
		fi

	    rec=$(egrep -c " bytes Re" < "$file")
	    if [[ $rec == 0 ]]; then
		   	echo "error: $var file is empty - no TX/RX SIP messages found."
		   	error=1			  
		   	rec=$(egrep -c -e "^CSeq:*" "$file")
		    if [[ $rec == 0 ]]; then
			    echo 'In fact, no sign of any "CSeq:" lines in '$var
			    error=2
			else
			    echo "Though, found "$rec' lines with "CSeq:" - so there might be some SIP messages in '$var
				rec=0
			fi
			echo "Verify source and content of $var"
			echo ''; continue		   
	    else
	        prevline=$(egrep -m 1 " bytes Re" "$file")
   	  	    if [[ $prevline == *"konfsip"* ]]; then
		        n=$(echo $prevline | egrep -c -e "^<[0-9]{3}>")
		        if [[ $((n)) != 0 ]]; then
			       vsyslog=39
		        elif [[ $prevline == *"local1"* ]]; then
			        vsyslog=31
				elif [[ $prevline =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then				# syslog extracted via tshark
					vsyslog=38			
			    else
                    line=$(echo $prevline | awk '{print $6}')
		            if [[ $line =~ TX|RX ]]; then
				       vsyslog=1
				 	fi
		      	fi
	        else
# Sep 16 13:25:19: TX 700 bytes Request msg REGISTER/cseq=29894 (tdta0x33f1b0) to tcp 10.133.93.42:5060:			!!no konfsip !!!			  
# Jun  7 11:53:54 4923172593589.voip.gfi.ihk.de konfsip[968:968]: TX 710 bytes Request msg REGISTER/cseq=57082 (tdta0x332028) to tcp 10.189.28.33:5060:
			         #vsyslog=30
				 line=$(echo $prevline | awk '{print $4}')
				 if [[ $line =~ TX|RX ]]; then
	                vsyslog=30
				 fi
		    fi
 	    fi

      	if [[ $((vsyslog)) == 0 ]]; then
        	 echo "error: $var file does not appear to be related to a valid B179 log."
	         echo 'Verify source and content of this file.'
		else
	        line=""
		    prevline=""
        	localip="1.1.1.1:1111"
	        sipyear=$(echo $today | cut -d'/' -f3)			  

# echo "VSYSLOG=" $vsyslog

			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			prevline=""
			siptotalmsg=0
			sipmaxlines=0
			sipmaxpart=0
			sipmaxsplit=0
			sipwordlist=""				
			longestmsg=0
			nlines=0
			n=0
			sipmsg=0
			sipmatch=0	

        	reset_sipmsg

#	    conv=$(awk -e '/bytes Re/{flag=1} flag; /}/{flag=0}' "$file")
	    conv=$(awk -W source='/bytes Re/{flag=1} flag; /}/{flag=0}' "$file")

		if [[ $outfile != "" ]]; then
			newfile="$outfile.asm.tmp"
		else
			newfile="$file.asm.tmp"
		fi
		if [ -f "$newfile" ]; then
			rm "$newfile"
		fi
		echo "# This file had been created by $0 v$version on $today at $currtime." >"$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var --> $file -> $outfile.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"
		fi

		while IFS= read -r line
			do
				nlines=$((nlines+1))
				if [[ $line == *" bytes Re"* ]] && [[ $line != *"pjsip"* ]]; then		# ignore pjsip from B199, in mixed syslog
				    if [[ $((sipstart)) != 0 ]]; then
				        complete_sipmsg
				    fi
					siptotalmsg=$((siptotalmsg+1))	
					sip_direction
					get_sip_datetime
                    sipmsg_header

					if [[ $((vsyslog)) == 31 ]] && [[ $((dirdefined)) != 0 ]]; then # syslog from pcap manually
						linex=$(echo "$line" | awk -F "$ip1:$ip2: " '{print $2}')
						line=$(echo $linex   | awk -F '---' '{print $1}')				
						start_sipmsg
						get_useragent
						complete_sipmsg
						siplines=$((siplines+1))
					fi									
				else
					if [[ $line == "---------------------------------------------------------------------------------"* ]]; then
					    complete_sipmsg
					elif [[ $((dirdefined)) != 0 ]] && [[ $((sipstart)) == 0 ]]; then
					        start_sipmsg					
					elif [[ $((sipstart)) !=  0 ]];	then
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
				fi
#				prevline=$line
			done <<< "$conv"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $outfile == "" ]]; then
			outfile=$var
		fi

		if [[ $((sipstat)) == 1 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $outfile.asm file"
			elif [[ $((sipmsg)) == 0 ]]; then 
				echo "==> no SIP messages were found for addr=$endptaddr in $var file"
			else
				echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
				echo "    have been converted for addr=$endptaddr into ""$outfile.asm"" file"
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
		echo "Task started: $currtime - completed: $(date +%R:%S)"
		echo ''

		if [ -f "$outfile.asm" ]; then
			mv "$outfile.asm" "$outfile.asm.bak"
		fi
		mv "$newfile" "$outfile.asm"
		pwd;ls -l "$outfile.asm"
		if [[ $tmpfile == 1 ]] && [[ $file != $var ]]; then
			rm "$file"
		fi
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done