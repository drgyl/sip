#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
sipstat=1
noINFO=0
adjusthour=0
base64decode=1
protocol="TCP" # here use lowercase for tshrak -e tcp.srcport
endptaddr="" # 135.105.129.244"
voutput=3  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

## 21) PCAP

function usage ()  {
    echo "tracePCAP.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: tracePCAP.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the Wireshark capture of SIP messages (using UDP or TCP transport)"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"		
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-p [UDP | TCP]:\tspecify protocol used by SIP transport"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function hex2str () {
  I=0
  line=""
  while [ $I -lt ${#sipcont} ];
  do
     line2=$(echo -en "\x"${sipcont:$I:2})
	 line=$line$line2
	 let "I += 2"
  done
} # hex2str()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	sipyear=""
	dirdefined=0
	localip=""
	ip=""
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

function complete_sipmsg2 () {
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
		base64 -d $newfile.b64 >> "$newfile"
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
fi
}

function complete_sipmsg () {
	complete_sipmsg2
	reset_sipmsg	
} # complete_sipmsg()

function sipmsg_header () {
	if [[ $((dirdefined)) != 0 ]]; then
		sipstart=0
		n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then
			echo -en "$file => $n/$rec Msgs converted            \r"
		fi
		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip. Length= $siplength." >> "$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip}/TLS/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} # sipmsg_header() 

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	sipline1=""
	sipline2=""
	sipcont=""
    ip1=$(echo "$line" | cut -d'#' -f3)
	ip2=$(echo "$line" | cut -d'#' -f4)
	if [[ ${#ip2} == 0 ]]; then
       ip2=$(echo "$line" | cut -d'#' -f5)
	fi
	
	localip1=$(echo "$line" | cut -d'#' -f6)
	localip2=$(echo "$line" | cut -d'#' -f7)
	if [[ ${#localip2} == 0 ]]; then
       localip2=$(echo "$line" | cut -d'#' -f8)
	fi

	proto=$(echo "$line" | cut -d'#' -f9)
#	siplength=$(echo $line | cut -d'#' -f10)

	if [[ $proto == "6" ]]; then
	  protocol="TCP"
	elif [[ $proto == "17" ]]; then
	  protocol="UDP"
	else
	  protocol="TLS"
	fi

    sipline1=$(echo "$line" | cut -d'#' -f10)

	if [[ ${#sipline1} == 0 ]]; then
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
        ip="$ip1:$ip2"
		localip="$localip1:$localip2"
		sipline1=$(echo "$line" | cut -d'#' -f11)
		if [[ ${#sipline1} == 0 ]]; then
		   sipline2=""
		   sipcont=$(echo "$line" | awk -F'#' '{print $NF}')
		   # sipcont=$(echo "$line" | cut -d'#' -f12)
		else
		   sipline2=$(echo "$line" | awk -F'#' '{print $NF}')
		   # sipline2=$(echo "$line" | cut -d'#' -f12)
		   sipcont=""
		fi
	else
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
		ip="$localip1:$localip2"
		localip="$ip1:$ip2"
		# sipline1=$(echo $line | cut -d'#' -f11)
		sipline2=$(echo "$line" | awk -F'#' '{print $NF}')
		# sipline2=$(echo "$line" | cut -d'#' -f12)
		sipcont=""
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
# @2022-01-18 10:26:22,699||FINEST|SIP|539122|FileName=sip/SIPTCP.cpp,LineNumber=426|RCV sock=136:0 src=10.134.48.67:5060 dst=10.134.142.36:31000 <SIP/2.0 200 OK

    tepoch=$(echo "$line"   | cut -d'#' -f2)
	sipday=$(date --date="@$tepoch" +"%m/%d/%Y %T.%N")
	sipmsec=$(echo $sipday  | cut -d' ' -f2)
	sipday=$(echo $sipday   | cut -d' ' -f1)
	#sipday=$(echo "$prevline" | cut -d':' -f1 | cut -d'[' -f2)
	sipyear=$(echo $sipday  | cut -d'/' -f3)
	sipmonth=$(echo $sipday | cut -d'/' -f1)
	sipday=$(echo $sipday   | cut -d'/' -f2)
#	sipday=$(echo $sipday | cut -d' ' -f1)

	siphour=$(echo $sipmsec  | cut -d':' -f1)
	sipmin=$(echo $sipmsec   | cut -d':' -f2)
	sipsec=$(echo $sipmsec   | cut -d':' -f3)
	sipmsec=$(echo $sipsec   | awk -F'.' '{printf "%03i",$2/1000000}')
    sipsec=$(echo $sipsec    | cut -d'.' -f1)

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
  while getopts ":e:hbf:sp:" options; do
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
	p)
		if [[ ${OPTARG} == "UDP" ]] || [[ ${OPTARG} == "udp" ]]; then
			protocol="UDP"
		elif [[ ${OPTARG} == "TCP" ]] || [[ ${OPTARG} == "tcp" ]]; then
			protocol="TCP"
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
	error=0
	vsyslog=0

	rec=0
	sipfile="$file.sip.txt"

	if [ -f "$file" ]; then
		echo -en "Exploring content in $var... stand by\r"

		line=$(file "$file")
		if [[ $line == *"tcpdump capture file"* ]] || [[ $line == *"pcap-ng capture file"* ]]; then
		  line=$(whereis tshark)

		  if [[ ${#line} -gt 10 ]] && [[ $protocol == "TCP" ]]; then
		    tshark -r "$file" -S=== -2Y "tcp && sip" -t ad -T fields -E separator="#" -e frame.number -e frame.time_epoch -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e ip.proto -e sip.Request-Line -e sip.Status-Line -e sip.msg_hdr -e sip.continuation | sed 's/\\r\\n/\n/g' > $sipfile
            rec=$(egrep -c -e ".*CSeq:.*" "$sipfile")
    	  elif [[ ${#line} -gt 10 ]] && [[ $protocol == "UDP" ]]; then
		    tshark -r "$file" -S"===" -2Y "udp && sip" -t ad -T fields -E separator="#" -e frame.number -e frame.time_epoch -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e ip.proto -e sip.Request-Line -e sip.Status-Line -e sip.msg_hdr -e sip.continuation | sed 's/\\r\\n/\n/g' > $sipfile
            rec=$(egrep -c -e ".*CSeq:.*" "$sipfile")
          else
		     echo "error: unable to locate 'tshark' command - 'tshark' is required to convert $var wireshark capture into text file"
			 error=10
			 continue
		  fi
		else 
			echo "error: $var does not appear to be a capture file. Verify source and content of this file."
			error=1
			continue
        fi

		if [[ $rec == 0 ]];	then
			error=2
		 	echo -e "error: no SIP messages have been found in $var."
			echo -e "Perhaps this wireshark capture does not include any SIP messages... or SIP transport was TLS instead of UDP or TCP\n"
			continue
		else

echo "Found $rec SIP messages in $var - refer to $sipfile"		

			base64found=0
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
			sipmsg=0
			siptotalmsg=0
			sipmaxlines=0
			sipmaxsplit=0
		    sipwordlist=""									
			longestmsg=0
			sipline1=""
			sipline2=""
			sipcont=""
			sipin=0
			sipout=0
	
			reset_sipmsg

			if [[ $rec -gt 500 ]]; then 
				echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
				echo "You may want to execute this script on a more powerful PC or server."
				echo ''
			fi

			newfile="$file.asm.tmp"
			if [ -f $newfile ]; then
				rm $newfile
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"

#           conv=$(awk -W source='/^\-\-\-\-\-\-\-\-\-\-\-\-\-.*\-\-\-\-\-\-\-$/{flag=1} flag; /}/{flag=0}' "$file")

			while IFS= read -r line
			do
				linelength=${#line}
				nlines=$((nlines+1))

                if [[ $((sipstart)) == 1 ]] && [[ $line == "#"* ]]; then
				   complete_sipmsg
			    elif [[ $line =~ ^[0-9]+\#[0-9]+\.[0-9]{9}\#.* ]]; then
				   sip_direction                                              # this sets $sipcont

					if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
						if [[ $localip != "" ]] && [[ $endptaddr != "" ]] && [[ $localip != *$endptaddr* ]]; then
							reset_sipmsg; continue
						fi
					fi

				   if [[ $((insidesip)) == 1 ]] && [[ $sipcont == "" ]]; then
				      complete_sipmsg2
				   fi
			 	   insidesip=1			   
				   
				   if [[ $sipcont == "" ]]; then
			 	      siptotalmsg=$((siptotalmsg+1))	
				      base64found=0		   
			 	      get_sip_datetime
				      sipmsg_header
				      line=$sipline1
				      start_sipmsg
					  if [[ $sipline2 != "" ]]; then
					     echo "$sipline2" >> "$newfile"
					     siplines=$((siplines+1))
					  fi
				   else
                      if [[ $((xxdexist)) == 1 ]]; then
				        # line=$(echo $sipcont | xxd -r -p | sed 's/\\r\\n/\n/g')
						# line=$(echo $sipcont | sed 's/0d0a/0a/g' | xxd -r -p)
						line=$(echo $sipcont | xxd -r -p)
					  else
				        hex2str # this will be much slower than xxd
					  fi

					  if [[ $prevline != "" ]]; then
                         line="$prevline$line"
                         prevline=""
					  fi
					  echo "$line" >> "$newfile"
					  contlines=$(echo "$line" | wc -l)
					  let "siplines += $((contlines))"
					  sipcont=""
				   fi
            
				elif [[ $((sipstart)) == 1 ]]; then
					if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
						base64found=1
						echo "# Base64 dump found" >> $newfile
						if [[ -f "$newfile.b64" ]]; then
							rm "$newfile.b64"
						fi
					elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
						echo "$line" >> "$newfile.b64"
					elif [[ ${#line} -gt 2 ]] && [[ $line =~ \#.$ ]]; then
					# elif [[ ${#line} -gt 2 ]] && [[ $line == *"#" ]]; then
				        prevline=$(echo "$line" | cut -d'#' -f1)
					else			
						echo "$line" >> "$newfile"
						siplines=$((siplines+1))
						get_useragent
						prevline=""
					fi
				fi
#	    done <<< "$conv"
		done < "$sipfile"

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
		echo "Task started: $currtime - completed: $(date +%R:%S)"
		echo ''
		if [ -f "$var.asm" ]; then
			mv "$var.asm" "$var.asm.bak"
		fi
		mv "$newfile" "$var.asm"
#		rm $sipfile					# this is already a tmp file, can be removed
		pwd;ls -l "$var.asm"
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done