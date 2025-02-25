#!/bin/bash
version="1.0.2"
NL=$'\n'
echo ''
today=$(date +%m/%d/%Y)
endptaddr="" # 135.105.129.203
localip="1.1.1.1:1111"
protocol="TLS"
siplength=666
sipstat=1
longestmsg=0
adjusthour=0
base64decode=1
alllogs=0
vsyslog=0
voutput=1

## 20) b199-siptraces-r10109.txt - taken from B199 SIP buffer
## 15:58:39.516   pjsua_core.c  ...TX 668 bytes Request msg REGISTER/cseq=61127 (tdta0xc9237c) to TLS 135.64.253.72:5061:
## 21) syslog_newB199.txt, or tftpd64-syslog.txt which was created by tftpd64, or from wireshark SYSLOG UDP stream
## <30>Dec  3 09:41:49 phoneapp[1033]: pjsip: 09:41:49.069   pjsua_core.c  ...TX 706 bytes Request msg REGISTER/cseq=65380 (tdta0xd501b4) to TLS 11.222.1.32:5061:
## 15:58:39.516   pjsua_core.c  ...TX 668 bytes Request msg REGISTER/cseq=61127 (tdta0xc9237c) to TLS 135.64.253.72:5061:
## 22) b199-iso-SyslogCatchAll.txt, created by KIWI Syslog r8.x, default ISO log file format
## 2022-02-07 19:01:46	Daemon.Info	135.105.129.203	Feb  7 19:01:46 phoneapp[1088]: pjsip: 19:01:46.418   pjsua_core.c  ....TX 1350 bytes Request msg INVITE/cseq=15118 (tdta0x53f345c) to TLS 135.64.253.72:5061:
## 2022-02-07 19:01:46	Daemon.Info	135.105.129.203	Feb  7 19:01:46 phoneapp[1088]: INVITE sip:1200@135.64.253.72;transport=tls SIP/2.0
## 23) Mega syslog rfc3614 or auto-detect: Mega-rfc3164-B199-Syslog.txt
## 2022-02-07 18:12:59	3	6	1	135.105.129.203				Feb  7 19:12:59 phoneapp[1088]: pjsip: 19:12:59.471   pjsua_core.c  ....TX 1346 bytes Request msg INVITE/cseq=21691 (tdta0x53b31d4) to TLS 135.64.253.72:5061:				
## 24) visualsyslog-B199.txt / not good because phoneapp[1088]  / there is no ]: in the line
## 135.105.129.203	Feb  7 19:14:29		daemon	info	phoneapp[1088]	pjsip: 19:14:29.838   pjsua_core.c  ....TX 1350 bytes Request msg INVITE/cseq=26302 (tdta0x551c104) to TLS 135.64.253.72:5061: 

function usage ()  {
    echo "traceB199.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceB199.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either the SIP message buffer taken from B199 SIP conference phone, or"
	echo -e "\t\tLogs.zip downloaded from B199 phone (which includes \"siptraces\" buffer, requires \"unzip\")"
	echo -e "\t\tor a syslog capture taken using either a remote syslog server (KIWI, tftpd64, or MEGA),"
	echo -e "\t\tor a syslog txt stream collected from network packet trace (via Follow UDP stream function)"
	echo -e "\t\tor a native pcap network trace including unsecure syslog traffic (requires \"tshark\")"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d"
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-A:\t\tconvert all logs in logreport where SIP message found (phoneapp.log, pjsip.log)"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
#	echo -e "\t-v X:\t\tenforce input format to X (=vsyslog)"
	echo ''
} # usage()

function reset_sipmsg () {
	dirdefined=0
	insidesip=0
	sipstart=0
	sipsplit=0
	siplines=0
	siphour=0
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	siplines=$((siplines+1))
	siptotalmsg=$((siptotalmsg+1))

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
	uptime=""

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile.b64" ]]; then
		blines=$(wc -l < "$newfile.b64")
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

	if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then	
		sipmaxlines=$siplines
		longestmsg=$sipmsg
	fi

	if [[ $((dirdefined)) == 1 ]]; then	
		sipin=$((sipin+1))
	else
		sipout=$((sipout+1))
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
} #complete_sipmsg

function sipmsg_header () {
	if [[ $((dirdefined)) != 0 ]]; then
		n=$((n+1))
		sipstart=0
		echo -en "$var => $n/$rec Msgs converted               \r"
		if [[ $((voutput)) == 1 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] DBH:     SIGNAL: [$sipstream] $dirstring1 $dirstring2 $ip1:$ip2. Length= $siplength." >> "$newfile"
		elif [[ $((voutput)) == 2 ]]; then
			echo -e "# msgno: $((sipmsg+1))$NL[$sipdate $siptime] $dirstring1 $siplength bytes $dirstring2 $ip1:$ip2 {" >> "$newfile"
		elif [[ $((voutput)) == 3 ]]; then
			echo "# msgno: $((sipmsg+1))${NL}com.avaya.asm  SIPMSGT ${NL}--------------------${NL}$sipdate ${siptime} $dirstring1 ${NL}$dirstring2: { L$localip/R${ip1:$ip2}/$protocol/ }${NL}--------------------" >> "$newfile"
		fi
	fi
} #sipmsg_header

function sip_partnum () {
	if [[ $line == *"[Part "* ]]; then
		partnum=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d' ' -f1)
		if [[ $partnum == "01" ]]; then
			maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d' ' -f3 | cut -d']' -f1)            # awk '{print $3}' | awk -F ']' '{print $1}')
			# maxpart=$(echo "$line" | awk -F "Part " '{print $2}' | cut -d ' ' -f 3)
		fi	
		sipsplit=1
	fi
} # sip_partnum

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $((vsyslog)) -gt 19 ]]; then
		if [[ $line == *"Request"* ]]; then
			if [[ $line == *" to "* ]]; then
				dirdefined=2
					## header=$(echo -e $direction "to" $ip1":"$ip2". Length=" $siplength".")
					## elif [[ $direction == 'Response' ]]; then
			elif [[ $line == *" from "* ]]; then
				dirdefined=1
			fi
		elif [[ $line == *"Response"* ]]; then
			if [[ $line == *" to "* ]]; then
				dirdefined=2
					## header=$(echo -e $direction "to" $ip1":"$ip2". Length=" $siplength".")
					## elif [[ $direction == 'Response' ]]; then
			elif [[ $line == *" from "* ]]; then
				dirdefined=1
			fi
					## header=$(echo -e $direction "from" $ip1":"$ip2". Length=" $siplength".")
		fi
	fi

	if [[ $((dirdefined)) == 1 ]]; then	
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="RECEIVED"
			dirstring2="from"
			sipstream=5f70
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="RECEIVED"
			dirstring2="from"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="-->"
			dirstring2="ingress"
		fi
	elif [[ $((dirdefined)) == 2 ]]; then
		if [[ $((voutput)) == 1 ]]; then
			dirstring1="SENT"
			dirstring2="to"
			sipstream=1474
		elif [[ $((voutput)) == 2 ]]; then
			dirstring1="SENDING"
			dirstring2="to"
		elif [[ $((voutput)) == 3 ]]; then
			dirstring1="<--"
			dirstring2="egress"			
		fi
	fi

	if [[ $((vsyslog)) -gt 19 ]] && [[ $((dirdefined)) != 0 ]]; then
#		if [[ $((vsyslog)) == 20 ]]; then
#			ip=$(echo $line | cut -d' ' -f15)
		if [[ $((vsyslog)) == 23 ]]; then
			ip=$(echo "$line" | awk '{print $23}')
		elif [[ $((vsyslog)) == 24 ]]; then
			ip=$(echo "$line" | awk '{print $20}')
		else
			ip=$(echo "$line" | awk '{print $(NF)}')
		fi
		ip1=$(echo $ip | cut -d':' -f1) # awk -F ":" '{print $1}')
		ip2=$(echo $ip | cut -d':' -f2) # awk -F ":" '{print $2}')

		if   [[ $((vsyslog)) == 20 ]]; then
#			siplength=$(echo "$line" | cut -d' ' -f7) # awk '{print $9}')
			if [[ $line == *"AvayaB199-"* ]]; then
				siplength=$(echo "$line" | awk '{print $11}')
			else
				siplength=$(echo "$line" | awk '{print $4}')
			fi
			foundipaddr="" 				
		elif [[ $((vsyslog)) == 21 ]]; then
			siplength=$(echo "$line" | cut -d' ' -f9) # awk '{print $9}')
			foundipaddr=""		
		elif [[ $((vsyslog)) == 22 ]]; then
			siplength=$(echo "$line"   | cut -d' ' -f13) # awk '{print $13}')
			foundipaddr=$(echo "$line" | cut -d' ' -f4)
		elif [[ $((vsyslog)) == 23 ]]; then
			siplength=$(echo "$line"   | cut -d' ' -f15) # awk '{print $15}')
			foundipaddr=$(echo "$line" | cut -d' ' -f6)
		elif [[ $((vsyslog)) == 24 ]]; then
			siplength=$(echo "$line"   | cut -d' ' -f12) # awk '{print $12}')
			foundipaddr=$(echo "$line" | cut -d' ' -f1)
		elif [[ $((vsyslog)) == 25 ]]; then
#			siplength=$(echo "$line"   | cut -d' ' -f9) # awk '{print $12}')
			siplength=$(echo "$line"   | awk '{print $9}')		
#			siplength=$(echo "$line"   | awk -F"pjsua_core.c" '{print $2}' | awk '{print $2}')    #cut -d' ' -f3) # awk '{print $12}')
#			foundipaddr=$(echo "$line" | cut -d' ' -f6)
		fi
	fi
fi	
} #sip_direction

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
	if [[ $((vsyslog)) == 20 ]]; then
		sipyear=$(echo $today  | cut -d'/' -f3)			
## 15:58:39.516   pjsua_core.c  ...TX 668 bytes Request msg REGISTER/cseq=61127 (tdta0xc9237c) to TLS 135.64.253.72:5061:
## Sep 28 14:48:16 AvayaB199-C81FEAA88DDE daemon.info phoneapp[7262]: pjsip: 14:48:16.470   pjsua_core.c  ....TX 1252 bytes Request msg INVITE/cseq=27165 (tdta0x539d99c) to TLS 10.134.117.194:5061:
		if [[ $line == *"AvayaB199-"* ]]; then						# this is a logs_phoneapp.log file
			sipday=$(echo "$line"  | awk '{print $2}')				#cut -d' ' -f2)
			month=$(echo "$line"   | cut -d' ' -f1)
			get_sipmonth
			convtime=$(echo "$line"| awk '{print $8}')				# cut -d' ' -f1)
		else			
			sipday=$(echo $today   | cut -d'/' -f2)
			sipmonth=$(echo $today | cut -d'/' -f1)					
			convtime=$(echo "$line"| cut -d' ' -f1)
		fi

	elif [[ $((vsyslog)) == 21 ]]; then
		sipyear=$(echo $today  | cut -d'/' -f3)
		sipday=$(echo "$line"  | awk '{print $2}')					# cut -d' ' -f2)
		sipmonth=$(echo "$line"| cut -d' ' -f1)
		month=$(echo $sipmonth | cut -d'>' -f2)
		get_sipmonth
						
		convtime=$(echo "$line"  | cut -d' ' -f6)
	elif [[ $((vsyslog)) == 22 ]]; then
		convdate=$(echo "$line"  | cut -d' ' -f1)
		sipyear=$(echo $convdate | cut -d'-' -f1)
		sipmonth=$(echo $convdate| cut -d'-' -f2)
		sipday=$(echo $convdate  | cut -d'-' -f3)
		
		convtime=$(echo "$line"   | cut -d' ' -f10) 				# awk '{print $10}')
	elif [[ $((vsyslog)) == 23 ]]; then
		convdate=$(echo "$line"   | cut -d' ' -f1)
		sipyear=$(echo $convdate  | cut -d'-' -f1)
		sipmonth=$(echo $convdate | cut -d'-' -f2)
		sipday=$(echo $convdate   | cut -d'-' -f3)

#		sipdate=$(echo $convdate | awk -F '-' '{print $2"/"$3"/"$1}')
		convtime=$(echo "$line" | cut -d' ' -f12) 					# awk '{print $12}')
	elif [[ $((vsyslog)) == 24 ]]; then
		sipyear=$(echo $today   | cut -d'/' -f3)
		sipday=$(echo "$line"   | awk '{print $3}')					# cut -d' ' -f3)
		month=$(echo "$line"    | cut -d' ' -f2)
		get_sipmonth		

		convtime=$(echo "$line" | cut -d' ' -f9) # awk '{print $9}')
#		convtime=$(echo "$line" | awk -F"pjsip: " '{print $2}' | cut -d' ' -f1) 					# awk '{print $9}')
	elif [[ $((vsyslog)) == 25 ]]; then								# syslog extrectad via tshark
		sipyear=$(echo $today   | cut -d'/' -f3)
		sipday=$(echo "$line"   | awk '{print $2}')					# cut -d' ' -f2)
		month=$(echo "$line"    | cut -d' ' -f1)
		get_sipmonth		

		convtime=$(echo "$line" | awk -F"pjsip: " '{print $2}' | cut -d' ' -f1) 					# awk '{print $9}')
#		convtime=$(echo "$line" | cut -d' ' -f9) # awk '{print $9}')
	fi

	# foundipaddr=$(echo "$line" | cut -d' ' -f5)
	if [[ ${#sipmonth} -lt 2 ]]; then
		sipmonth="0$sipmonth"
	fi

	if [[ ${#sipday} -lt 2 ]]; then
		sipday="0$sipday"
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

	if   [[ $((voutput)) == 1 ]]; then
		sipdate=$(echo $sipmonth/$sipday/$sipyear)
		siptime=${convtime//./:}  ## replace "." with ":"							
	elif [[ $((voutput)) == 2 ]]; then
		sipdate=$(echo $sipyear/$sipmonth/$sipday)
		siptime=${convtime//./:}  ## replace "." with ":"							
	elif [[ $((voutput)) == 3 ]]; then
		sipdate=$(echo $sipday/$sipmonth/$sipyear)
		siptime=convtime # $(echo $siphour:$sipmin:$sipsec.$sipmsec)		
	fi
	# siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec)
} # get_sip_datetime()


function convert_siplog () {
if [[ $file != "" ]]; then
	if [ -f "$file" ]; then

	rec=$(egrep -c '\-\-end msg\-\-' "$file")
	if [[ $((rec)) == 0 ]]; then
		echo "error: $file is not a B199 logfile"
		error=1; continue
	fi

	n=$(egrep -c -m 1 "pjsua_core" "$file")
	if [[ $((n)) == 1 ]]; then
		prevline=$(egrep -m 1 "phoneapp" "$file")

		if [[ $prevline =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then				# syslog extracted via tshark
			vsyslog=25		
		else
			vsyslog=20
		fi
	else
		n=$(egrep -c -m 1 "^<[0-9]{2}>" "$file")
		if [[ $((n)) == 1 ]]; then
			vsyslog=21
		else
			n=$(egrep -c -m 1 "Daemon\.Info" "$file")
			if [[ $((n)) == 1 ]]; then
				vsyslog=22
			else
				n=$(egrep -m 1 "daemon" "$file" | egrep -c -m 1 "info")
				if [[ $((n)) == 1 ]]; then
					vsyslog=24
				else
					prevline=$(egrep -m 1 "phoneapp" "$file" | cut -d' ' -f5)		# cut -d' ' -f6)
					if [[ $prevline == "phoneapp"* ]]; then
						vsyslog=23
					fi
	                prevline=""						
				fi
			fi
		fi
	fi

echo "VSYSLOG= " $vsyslog

	# rec=$(egrep "\-\-end msg\-\-" "$file" | wc -l)
	if [[ $rec == 0 ]]; then
		rec=$(egrep -c -e "^CSeq:.*" "$file")
		if [[ $rec == 0 ]]; then
			echo 'In fact, no sign of any "CSeq:" lines in '$file
			echo ''; error=2
		else
			echo "Though, found $rec lines with "CSeq:" - so there might be some SIP messages within $file"
			echo "Verify source and content of $file"
			echo ''; rec=0
		fi
	elif [[ $((vsyslog)) == 0 ]]; then
        error=4
	   	echo "error: unknown file formwat - could not detect input file as valid B199 log source."
		echo "Verify source and content of $file"
		echo ''
	else
		base64found=0
		base64msg=0
		foundipaddr=""
		useragent=""
		output=""
		newfile=""
		prevline=""
		siptotalmsg=0
		sipmaxlines=0
		sipmaxpart=0
		sipmaxsplit=0
		sipwordlist=""			
		nlines=0
		n=0
		sipin=0
		sipout=0
		sipmsg=0

        reset_sipmsg

		##conv=$(awk -e '/CSDK::SIP.*{|CSDK] PPM:.*{/{flag=1} flag; /}/{flag=0}' $file)
#    	conv=$(awk -e '/bytes R/{flag=1} flag; /}/{flag=0}' "$file")		# not good for AWK v3.1.7 on SM7.0.1
	   	conv=$(awk -W source='/bytes R/{flag=1} flag; /}/{flag=0}' "$file")			

		if [[ $file == *"/"* ]]; then 
			basefile=$(echo "${file#*/}")
		else
			basefile=$file
		fi
		if [[ $file == *"."* ]]; then
			basefile=$(echo "${basefile%.*}")
		fi

		if [[ $var == *"."* ]]; then
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

		if [[ $output != "" ]]; then
			newfile="$output.asm.tmp"
		elif [[ $file != "" ]]; then
			newfile="$file.asm.tmp"
		fi
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
			if [[ $line == *" bytes R"* ]] && [[ $line != *"konfsip"* ]]; then 						# ignore konfsip from B179, in mixed syslog			
				if [[ $endptaddr != "" ]] && [[ $line != *$endptaddr* ]]; then
					 continue
				fi
				get_sip_datetime
				sip_direction
				sipmsg_header
			# elif [[ $line == *"]:"* ]] || [[ $line == *"]"* ]]; then
			elif [[ $((vsyslog)) == 20 ]] || [[ $line == *"]"* ]]; then
				if [[ $((vsyslog)) == 24 ]]; then
				#echo "LINE1:" $line
					line=$(echo "$line" | awk -F '] ' '{print $2}')
				#echo "LINE2:" "$line"
				elif [[ $((vsyslog)) != 20 ]] || [[ $line == *"AvayaB199-"* ]]; then
					line=$(echo "$line" | awk -F ']: ' '{print $2}')
				fi
				if [[ $line == "--end msg--"* ]]; then
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
					echo "    has been converted for addr=$endptaddr into $output.asm file"
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
#		if [[ $tmpfile == 1 ]] && [[ $file != $var ]]; then
#			rm "$file"
#		fi
		echo ''
		fi
	else
		error=7
		echo "error: $file was not found"
		echo ''; 	
	fi
else
	error=6
	echo "convert_siplog() received null string for input"
	echo ''
fi
} # convert_siplog()

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":he:bf:sv:A" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
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
	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 20 ]] || [[ $((vsyslog)) -gt 24 ]]; then
			vsyslog=1
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
		elif [[ $var == "-v"* ]]; then
			skipper=2
		elif [[ $var == "-e"* ]]; then
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
			vsyslog=$var
			if [[ $((vsyslog)) -lt 20 ]] || [[ $((vsyslog)) -gt 24 ]]; then
				vsyslog=1
			fi
		elif [[ $((skipper)) == 3 ]]; then
			endptaddr=$var
		fi
		skipper=0
		continue
	fi

	file=$var
	currtime=$(date +%R:%S)
	currdir=$PWD
	filelist=""
	tmpfile=0
	basefile=""
	input=""
	file2=""
	basefile2=""
	file3=""
	basefile3=""
	file4=""
	basefile4=""
	error=0
	n=0
	vsyslog=0
	
	if [ -f $var ]; then
		echo -en "Exploring content in $var... stand by\r"

		filetype=$(file -b "$file")
		filecontent="B199"

		if [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "B199" ]]; then
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
			unzip -qq -v 2>1 >/dev/null
			if [[ $? == 0 ]]; then
				unzip -qq "../$file" 2>/dev/null
				if [[ $? -gt 1 ]]; then
					tar --version >/dev/null
					if [[ $? == 0 ]]; then
						tar xf "../$file"
						if [[ $? != 0 ]]; then
							error=8
							echo "error: could not uncompress $var, using \"tar\" utility."
							echo ''; cd ..; continue
						fi
					else
						error=8
						echo "error: could not uncompress $var, using \"unzip\".  Suggest to validate \"unzip\" in your environment."
						echo ''; cd ..; continue
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
						echo ''; cd ..; continue
					fi
				fi
			fi

			file=""; filelist=""
			targetfiles="siptraces siptraces.log logs_phoneapp.log logs_pjsip.log messages.log"
			for xfile in $targetfiles
			do
				if [ -d "tmp" ] && [-f tmp/$xfile ]; then
					n=$(egrep -c "CSeq:" tmp/$xfile)	
					if [[ $((n)) -gt 0 ]]; then
						if [[ $file == "" ]]; then
							file="$input.tmp/tmp/$xfile"
#						tmpfile=2
						fi
						filelist="$filelist $input.tmp/tmp/$xfile"
					fi
				elif [ -f $xfile ]; then
					n=$(egrep -c "CSeq:" siptraces)
					if [[ $((n)) -gt 0 ]]; then
						if [[ $file == "" ]]; then								
							file="$input.tmp/$xfile"
#						tempfile=2
						fi
						filelist="$filelist $input.tmp/$xfile"
					fi
				fi
			done

			if [[ $file == "" ]]; then
				error=9
				echo "error: could not find either \"siptraces.log\", or \"logs_phoneapp.log\", or \"logs_pjsip.log\" or \"messages.log\" files"
				echo ''; cd ..; continue
			fi

			cd ..; 	n=0

		elif [[ $filetype == *"capture"* ]]; then
			if [[ $filetype == *"tcpdump"* ]] || [[ $filetype == *"pcap"* ]]; then
		  		line=$(whereis tshark)
				if [[ ${#line} -gt 10 ]]; then
					if [[ $endptaddr != "" ]]; then
				    	tshark -r $file -S=== -2Y "ip.src==$endptaddr && syslog" -t ad -T fields -E separator="#" -e syslog.msg > "$file.syslog2"
					else
		    			tshark -r "$file" -S=== -2Y "syslog" -t ad -T fields -E separator="#" -e syslog.msg  > "$file.syslog2"
					fi
					sed 's/\\r\\n/\'$'\n''/g' < "$file.syslog2" | sed 's/\\n\\n/\'$'\n''/g' | sed 's/\\n/\'$'\n''/g' > "$file.syslog"
					input="$file"
#					rm "$file.syslog2"
					file="$file.syslog"
					filecontent="syslog"
					tmpfile=1
#					vsyslog=25
		      	else
		     		echo "error: unable to locate 'tshark' command."
					echo "'tshark' is required to extract syslog messages from $var wireshark capture into text file"
					echo ''; error=10; continue
				fi
	  		fi
		fi

# echo "filetype=$filetype input=$input filename=$file" filelist=HUHU$filelist $PWD

	nfiles=0
	if [[ $((alllogs)) != 0 ]]; then
		if [[ $filelist != "" ]]; then
			nfiles=$(echo $filelist | wc -w)
		fi

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x EndpointLog or avaya_phone.log) found in $var"
			echo "This may take a while... you may want to execute this script on a more powerful PC or server."
			echo ''

			for file in $filelist;
			do
#			echo "Executing file=$file from filelist=$filelist"
#				file="$input.tmp/$file"
				convert_siplog
			done
		elif [[ $((nfiles)) -eq 1 ]]; then
			if [[ $file == "" ]]; then
				file=$filelist
			fi
			convert_siplog				
		fi
	elif [[ $file != "" ]]; then
		convert_siplog	
	fi

	else
		echo "error: file $var was not found."
		echo ''; error=3
	fi
done