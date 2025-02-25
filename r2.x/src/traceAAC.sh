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
pattern1='.*MX Sigtrace.*'
pattern2=""
# pattern2='^FINE.*% $'
# pattern3='^% '
# pattern4='^INFO|^FINE|^FINER|^FINEST'
findANI=""
sipstat=1
alllogs=0
bCAT=0
bDelTemp=1
converted=0
adjusthour=0
base64decode=1
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
# vsyslog=7 

## 5) AAC SIP Message Trace : sipmcDebug
## 6) AAC SIP Message Trace : sip.txt
## 7) AAC SIP Message Trace : AACtraceForWin.log

# TODO: AAC logreport/logarchive  .zip : logs/log/sipmcDebug.txt[.X.bak] or sip*.txt[.X.bak]

function usage ()  {
    echo "traceAAC.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t      created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAAC.sh <options> [<LOG_FILE> | folder, ...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either sip.txt, sipmcdebug.txt file or trace_XXXX.log"
	echo -e "\t\t\tcollected from an AAC or AS5300 server LogArchive"
	echo -e "\t<folder>\tincludes one or more of the log files extracted from LogArchive"	
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
	insidesip=0
	dirdefined=0
	sipstart=0
	siplines=0
	emptyline=0
	base64found=0
	sipyear=""
	ip=""
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

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile.b64" ]]; then
		if [[ $((base64found)) == 1 ]]; then
			base64 -d "$newfile.b64" >> "$newfile"
			blines=$(base64 -d "$newfile.b64" | wc -l)
		elif [[ $((base64found)) == 2 ]]; then					# gzip
# https://unix.stackexchange.com/questions/22834/how-to-uncompress-zlib-data-in-unix
# The trick is to prepend the gzip magic number and compress method to the actual data from zlib.compress:
# printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" |cat - /tmp/data |gzip -dc >/tmp/out
# Edits: @d0sboots commented: For RAW Deflate data, you need to add 2 more null bytes:
# → "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00"	
# zlibd() (printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" | cat - "$@" | gzip -dc)
# inverse operation: cat input.txt | gzip -c | tail -c +9 >compressed.gzbody to remove the first 8 bytes –
# zlib-flate -uncompress < IN_FILE > OUT_FILE
# zlib-flate can be found in package qpdf (in Debian Squeeze, Fedora 23, and brew on MacOS according to comments in other answers)
# openssl zlib -d -in /tmp/data
# openssl enc -z -none -d < /file/to/deflate

# The gzip footer is 8 bytes long. It consists the CRC32 of the uncompressed file, plus the size of the file uncompressed mod 2^32, both in big endian format. If you don't know these but have means of getting an uncompressed file:

# generate_crcbig() {
#     crc=$(crc32 $uncompressedfile)
#     crcbig=$(echo "\x${crc:6:2}\x${crc:4:2}\x${crc:2:2}\x${crc:0:2}")
# }
# generate_lbig () {
#    leng=$(ls -l $uncompressedfile | awk '{print $5}')
#    lmod=$(expr $leng % 4294967296) # mod 2^32
#    lhex=$(printf "%x\n" $lmod)
#    lbig=$(echo "\x${lhex:6:2}\x${lhex:4:2}\x${lhex:2:2}\x${lhex:0:2}")
#}
# And then the footer may be appended as such:
# printf $crcbig$lbig | cat tmp3.z - > outfile.gz

			gunzip -q -S .b64 "$newfile.$n.b64" >> "$newfile"
			blines=$(gunzip -q -S .b64 "$newfile.$n.b64" | wc -l)

		elif [[ $((base64found)) == 3 ]]; then					# deflate
			uncompress "$newfile.$n.b64" >> "$newfile"
			blines=$(uncompress "$newfile.$n.b64" | wc -l)
		fi
		siplines=$((siplines+$blines))
#		rm "$newfile.b64"
#		base64found=0
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
				echo -en "$basefile => $n/$rec Msgs converted             \r"
			else
				echo -en "$var => $n/$rec Msgs converted             \r"
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
# (03-14 18:08:29.552)<I,sip,33319792,00000000-0000-0000-0000-000000000000> INCOMING (10.16.172.186:50806) TLS
	## direction=$(echo $line | egrep -Eo "Inbound|Outbound")
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $((vsyslog)) == 6 ]]; then
		if [[ $line == *" INCOMING "* ]]; then
		## if [[ $direction == "Inbound" ]]; then
			sipstream=5f70;				dirdefined=1
			case $voutput in
			1|2) dirstring1="RECEIVED"; dirstring2="from";;
			3)	 dirstring1="-->"; 		dirstring2="ingress";;
			esac
			##ip=$(echo $line | awk '{print $5}')
		elif [[ $line == *" OUTGOING "* ]]; then
			## elif [[ $direction == 'Outbound' ]]; then
			sipstream=1474;				dirdefined=2
			case $voutput in
			1)	dirstring1="SENT";		dirstring2="to";;
			2)	dirstring1="SENDING";	dirstring2="to";;
			3)	dirstring1="<--"; 		dirstring2="egress";;
			esac
		##ip=$(echo $line | awk '{print $5}')
		else
			insidesip=0
			dirdefined=0
		fi

		protocol=$(awk '{print $(NF)}' <<< "$line")
		ip=$(cut -d' ' -f4 <<< "$line" | cut -d')' -f1 | cut -d'(' -f2)		# 000000000000> INCOMING (10.20.32.81:36143) TCP
#		ip=$(echo "$line" | awk '{print $(NF-1)}')
#		ip1=$(echo $ip | cut -d '(' -f2 | cut -d':' -f1)
#		ip2=$(echo $ip | cut -d':' -f2 | cut -d')' -f1)
#		ip="$ip1:$ip2"

# (03-14 18:08:29.552)<I,eng,33319792,5d2ca2ad-4994-3046-891f-b3ed1ba047a4> ENG[002:A] <idle> Incoming SIP Message: OPTIONS sip:resource_query@10.16.172.183:5063
# Tue, October 31, 2017 13:11:02.495 : 1509430262495
# SIP Message Trace : Incoming

	elif [[ $((vsyslog)) == 5 ]] || [[ $((vsyslog)) == 7 ]]; then
		if [[ $line == *" Incoming"* ]]; then
			## if [[ $direction == "Inbound" ]]; then
			sipstream=5f70;				dirdefined=1
			case $voutput in
			1|2) dirstring1="RECEIVED";	dirstring2="from";;
			3)	 dirstring1="-->"; 		dirstring2="ingress";;
			esac
			##ip=$(echo $line | awk '{print $5}')
		elif [[ $line == *" Outgoing"* ]]; then
			## elif [[ $direction == 'Outbound' ]]; then
			sipstream=1474;				dirdefined=2
			case $voutput in
			1)	dirstring1="SENT";		dirstring2="to";;
			2)	dirstring1="SENDING";	dirstring2="to";;
			3)	dirstring1="<--"; 		dirstring2="egress";;
			esac
			##ip=$(echo $line | awk '{print $5}')
		else
			insidesip=0
			dirdefined=0
		fi
	fi
	if [[ $((dirdefined)) != 0 ]]; then
		if [[ $((vsyslog)) == 5 ]] || [[ $((vsyslog)) == 7 ]]; then
			protocol=TLS
			ip="6.6.6.6:6666"
		elif [[ $((vsyslog)) == 6 ]]; then
			protocol=$(awk '{print $(NF)}' <<< "$line")
			ip=$(cut -d' ' -f4 <<< "$line" | cut -d')' -f1 | cut -d'(' -f2)		# 000000000000> INCOMING (10.20.32.81:36143) TCP
		fi
		siplength="666"	
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
		echo $line; echo ''; exit 1
	fi
} # get_sipmonth()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			if [[ $line =~ "Conferencing" ]] || [[ $line =~ "Media" ]]; then
				useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
			else
				useragent=""
			fi
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
	as5300=0	
	if [[ $((vsyslog)) == 6 ]] || [[ $((vsyslog)) == 5 ]]; then 
		sipyear=$(cut -d' ' -f1 <<< "$line")
		sipmonth=$(cut -d'(' -f2 <<< "$sipyear" | cut -d'-' -f1)
		sipday=$(cut -d'-' -f2 <<< "$sipyear")
		sipyear=$(cut -d'/' -f3 <<< "$today")

		sipmsec=$(cut -d')' -f1 <<< "$line" | cut -d' ' -f2) 
	
	elif [[ $((vsyslog)) == 7 ]]; then
# AAC: Tue, October 31, 2017 13:11:02.495 : 1509430262495
# AAC: Wed, August 02, 2017 17:30:30.392 : 1501709430392
# AS5300: Mar 6, 2017 7:51:02 PM : 1488851462374
##		if [[ $((n)) == 0 ]]; then
##			foundipaddr=$(echo $line | cut -d' ' -f5)

		if [[ $prevline =~ ^[FMTSW][aehoru][deintu],\  ]]; then
			sipyear=$(cut -d' ' -f4 <<< "$prevline") 
			month=$(cut -d' ' -f2 <<< "$prevline")
			sipday=$(cut -d' ' -f3 <<< "$prevline" | cut -d',' -f1)
			get_sipmonth

# echo "DATETIME:" "$prevline" "y=$sipyear sipm=$sipmonth mo=$month sipd=$sipday sipdate=$sipdate VEGE"
##		fi

####		siphour=$(echo $line | cut -d' ' -f3)
####		sipmin=$(echo $siphour | cut -d ':' -f2) # awk -F ':' '{print $2}')
####		sipsec=$(echo $siphour | cut -d ':' -f3) # awk -F ':' '{print $3}')
####		siphour=$(echo $siphour |cut -d ':' -f1) # awk -F ':' '{print $1}')
			sipmsec=$(cut -d' ' -f5 <<< "$prevline")

		elif [[ $prevline =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
			as5300=1
			sipyear=$(cut -d' ' -f3 <<< "$prevline") 
			month=$(cut -d' ' -f1 <<< "$prevline")
			sipday=$(cut -d' ' -f2 <<< "$prevline" | cut -d',' -f1)
			get_sipmonth
			sipmsec=$(cut -d' ' -f4 <<< "$prevline")
		fi

		# siptime=$(echo $line | awk '{print $3":"$8}')  ## msec included in $8
####		siptmp=$(echo $line | awk '{print $6}')
####		tzhour=$(echo $siptmp |cut -d':' -f 1) # awk -F ':' '{print $1}')  ## adjusting only the hour value based on TZ
####		tzmin=$(echo $siptmp | cut -d':' -f 2) # awk -F ':' '{print $2}')	
		if [[ $((sipday)) -lt 10 ]] && [[ ${#sipday} -lt 2 ]]; then
			sipday="0$sipday"
		fi
	fi

	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")
	if [[ $((as5300)) == 0 ]]; then
		sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
		sipsec=$(cut -d'.' -f1 <<< "$sipsec")
	else
		sipmsec=$(cut -d' ' -f7 <<< "$prevline" | tr -d '\r')			# awk '{print $NF}')
		sipmsec=${sipmsec: -3}
		if [[ $((siphour)) -lt 10 ]]; then
			siphour="0$siphour"
		fi
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
} # get_sip_datetime()

function convert_siplog5 () {
	while IFS= read -r line
	do
		linelength=${#line}
		nlines=$((nlines+1))

		if [[ $line == *")<I,eng,"* ]] && [[ $line == *"ing SIP Message:"* ]]; then
			if [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
			fi

			siptotalmsg=$((siptotalmsg+1))	
			insidesip=1                                                            # this is a new SIP msg
			get_sip_datetime
			sip_direction							

		elif [[ $((insidesip)) != 0 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -lt 2 ]]; then
			insidesip=2
		elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -gt 1 ]]; then
			sipmsg_header		
			start_sipmsg
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
				if [[ -f "$newfile.b64" ]]; then
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
		else
			insidesip=0
			sipstart=0						
		fi
		prevline=$line	
	done < "$file"
} # convert_siplog5()

function convert_siplog6 () {
	while IFS= read -r line
	do
		linelength=${#line}
		nlines=$((nlines+1))

		if [[ $line == *")<I,sip,"* ]]; then
			if [[ $((sipstart)) != 0 ]]; then
				complete_sipmsg
			fi

			siptotalmsg=$((siptotalmsg+1))	
			insidesip=1                                                       # this is a new SIP msg
			get_sip_datetime
			sip_direction							
			
		elif [[ $((insidesip)) != 0 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -lt 2 ]]; then
			if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
				reset_sipmsg
			else						
				insidesip=2
			fi
		elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]] && [[ $((linelength)) -gt 1 ]]; then
			sipmsg_header		
			start_sipmsg
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
		prevline=$line	
	done < "$file"
} # convert_siplog6()

function convert_siplog7 () {
	while IFS= read -r line
	do
		linelength=${#line}
		nlines=$((nlines+1))

		if [[ $((sipstart)) != 0 ]]; then
			if [[ $line =~ ^SIP\/2\.0\  ]]; then
				continue
	 		elif [[ $((linelength)) == 1 ]]; then
				emptyline=$((emptyline+1))
				if [[ $((emptyline)) == 2 ]]; then
					complete_sipmsg
				fi
			elif [[ $line =~ ^[FMTSW][aehoru][deintu],\  ]] || [[ $line =~ ^[JFMASOND][[:lower:]][[:lower:]]\  ]]; then
				complete_sipmsg
			else
				emptyline=0
			fi
		fi

		if [[ $((dirdefined)) == 0 ]] && [[ $line == *"SIP Message Trace :"* ]]; then
			ip=""
			sip_direction
			siptotalmsg=$((siptotalmsg+1))	
			insidesip=1													# this is a new SIP msg candidate
			get_sip_datetime			 								# calculated based on $prevline			

		elif [[ $((dirdefined)) != 0 ]] && [[ $line =~ ^SipSignalAnswer ]]; then
			reset_sipmsg

			elif [[ $((dirdefined)) != 0 ]] && [[ $line =~ ^Transaction: ]]; then
				prevline=$line; ip=""
				continue
			elif [[ $((dirdefined)) != 0 ]] && [[ $line =~ ^SIP_CB ]]; then
				prevline=$line; ip=""	
				continue
			elif [[ $((dirdefined)) != 0 ]] && [[ $line =~ ^IPDest: ]]; then # sed strips off ^M
				line=$(sed 's/.*[[:blank:]]//g' <<< "$line")
#				line=$(echo "$line" | sed 's/.*\^M$//g')
				protocol=$(cut -d' ' -f2 <<< "$line")
				ip1=$(cut -d':' -f2 <<< "$protocol")
				ip2=$(awk -F':' '{printf "%i",$3}' <<< "$protocol") # because of final ^M
#				ip2=$(echo $protocol| cut -d':' -f3)
				ip="$ip1:$ip2"
#				ip=$(echo $protocol | awk -F':' '{print $2":"$3}')
				protocol=$(cut -d':' -f1 <<< "$protocol")
				if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip == *$endptaddr* ]]; then
					reset_sipmsg
#				else
#					sipmsg_header
				fi

		elif [[ $((sipstart)) == 0 ]] && [[ $ip != "" ]]; then
			sipmsg_header
			start_sipmsg

		elif [[ $((sipstart)) != 0 ]]; then
			if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
				if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
					calltime=$siptime
				elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
					callID=$line; callDIR=$dirdefined
				fi
			fi

			if [[ $((base64decode)) != 0 ]] && [[ $line =~ ^Content-Encoding:\ deflate ]]; then
				base64found=3
				echo "# Content-Encoding: deflate found" >> "$newfile"
				if [[ -f "$newfile.$n.b64" ]]; then
					rm "$newfile.$n.b64"
				fi		
#			elif [[ $((base64decode)) != 0 ]] && [[ $line =~ ^Content-Encoding:\ gzip ]]; then
#				base64found=2
#				echo "# Content-Encoding: gzip found" >> "$newfile"
#				if [[ -f "$newfile.$n.b64" ]]; then
#					rm "$newfile.$n.b64"
#				fi
			elif [[ $((base64decode)) != 0 ]] && [[ $line == *"Base64 dump"* ]]; then # TODO: handle content type : gzip
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64found)) != 0 ]] && [[ $((linelength)) -gt 1 ]]; then
				echo "$line" >> "$newfile.$n.b64"
			else					
				echo "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi
		fi
		prevline=$line	
	done < "$file"
} # convert_siplog7()

function explore_logfolder() {
	targetfiles=""

	targetX=""; targetX=$(ls -r -t1 sipmcDebug.txt.[0-9]*.bak 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	else
		targetfiles=$targetX
	fi

	targetX=""; targetX=$(ls -r -t1 trace_*.log 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetfiles != "" ]]; then
		targetfiles="$targetfiles $targetX"
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

	if [ -f "AACtraceForMac.log" ]; then
		targetfiles="$targetfiles AACtraceForMac.log"	
	fi
	if [ -f "AACtraceForWin.log" ]; then
		targetfiles="$targetfiles AACtraceForWin.log"
	fi	

	if [[ $((alllogs)) == 0 ]] && [[ $targetfiles != "" ]]; then
		targetfiles=$(tail -1 <<< $targetfiles)
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
		echo -e "\nerror: could not find any AAC related logs in $folder\n"
		error=1
	fi
	cd $currdir
else
	echo -e "\nerror: explore_folders() was called with null string - contact developer.\n"
	error=98
fi
} # explore_folders()

function convert_siplog() {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

	echo "                                                                                                                                                  "
	## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
	rec=$(egrep -c -e "^SIP Message Trace :.*" "$file")
	if [[ $rec == 0 ]];	then
		# rec=$(egrep -c -e "^\([0-9]{2}\-[0-9]{2} [0-9]{2}.*<I,sip,.*" < "$file")
		rec=$(egrep -c -e "^\([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,sip," "$file")
		if [[ $rec == 0 ]]; then
			# rec=$(egrep -c -e "^\([0-9]{2}\-[0-9]{2} [0-9]{2}.*<I,eng,.*ing SIP Message:.*" <$file)
			rec=$(egrep -c -e "^\([0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}\)<I,eng,.*ing SIP Message:.*" "$file")
			if [[ $rec == 0 ]]; then 
				error=2
				echo -e "\nerror: No SIP messages have been found in $basefile in the expected format."
				echo "This file may not be an AAC logfile... or, DEBUG loglevel was not enabled."
				rec=$(egrep -c -e "^CSeq:.*" "$file")
				if [[ $rec == 0 ]]; then
					echo "In fact, no sign of any "CSeq:" lines within $basefile."
				else
					echo "Though, found $rec lines with "CSeq:" - so there might be some SIP messages included within $basefile."
					rec=0; error=3
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
				vsyslog=5
			fi
		else
			vsyslog=6
		fi
	else
		rec=$(egrep -c -e "^CSeq:.*" "$file")
		vsyslog=7
	fi

	if [[ $((vsyslog)) != 0 ]] && [[ $rec != 0 ]]; then
		logsec=$SECONDS
		base64msg=0
		foundipaddr=""
		useragent=""
		prevline=""
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
		sipmaxpart=0
	    sipwordlist=""									
		longestmsg=0
		longestsipword=""
		firstmsg=""
		lastmsg=""
		timefirst=""
		timelast=""
		callID=""
		calltime=""
		callDIR=0
		sipin=0
		sipout=0
#		timestamp=""
	
		reset_sipmsg

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
		echo "# Input: $var" >> "$newfile"		

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var --> $file -> $output.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $output.asm\n" >> "$newfile"
		fi

		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error - Contact developer\n\n"
		fi

		case $vsyslog in
		5) convert_siplog5;;
		6) convert_siplog6;;
		7) convert_siplog7;;
		esac

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output=$var
		fi
		
		if [[ $((error)) != 0 ]]; then
			echo -e "\n\tError found: $error - Contact developer\n\n"

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
				echo -e "# Longest SIP message had:\t\t\t $sipmaxlines lines at msg# $longestmsg ($longestsipword)" >> "$newfile"
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
					elif [[ ${#firstmsg} -lt 14 ]]; then
						echo -e "\tFirst msg:\t$firstmsg\t\t\t $timefirst"
					elif [[ ${#firstmsg} -lt 17 ]]; then
						echo -e "\tFirst msg:\t$firstmsg\t\t $timefirst"
					else
						echo -e "\tFirst msg:\t$firstmsg\t $timefirst"
					fi
					if [[ ${#lastmsg} -lt 8 ]]; then				
						echo -e "\tLast  msg:\t$lastmsg\t\t\t\t $timelast"
					elif [[ ${#lastmsg} -lt 14 ]]; then
						echo -e "\tLast  msg:\t$lastmsg\t\t\t $timelast"
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
			avgmsg=$(printf %.2f "$(($n * 100 / $tmpsec))e-2")
			echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: $avgmsg\t Time spent: $SECONDS sec\n"
		else
			echo -e "\n\tTask started: $currtime - completed: $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t Time spent: $SECONDS sec\n"
		fi
		currtime=$(date +%R:%S)	

		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
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

################################# Execution starts here #####################################
		argarray=($@)
		arglen=${#argarray[@]}
		args=${argarray[@]:0:$arglen}

if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts "e:hbdf:sACN:v" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	e)
		endptaddr=${OPTARG};;
	s)
		sipstat=0;;
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;
	A)
		alllogs=1;;
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
	v) vsyslog=${OPTARG}
		if [[ $((vsyslog)) -lt 5 ]] || [[ $((vsyslog)) -gt 7 ]]; then
			vsyslog=7
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
		elif [[ $var == "-v"* ]]; then
			skipper=2
		elif [[ $var == "-e"* ]]; then
			skipper=3	
		elif [[ $var == "-N"* ]]; then
			skipper=4
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
			if [[ $((vsyslog)) -lt 5 ]] || [[ $((vsyslog)) -gt 7 ]]; then
				vsyslog=7
			fi
		elif [[ $((skipper)) == 3 ]]; then
			endptaddr=$var
		elif [[ $((skipper)) == 4 ]]; then
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
	filetype2=""; filecontent="AAC"
	
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
		target="AAC"
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

		sample=""; sample2=""
		input=""; input2=""		
		filelist=""; file="$var"
		destdir="."; filecontent=""

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

		elif [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "MX" ]]; then
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
				fi

			elif [[ $bUnzip == 0 ]]; then
				cd ..; rm -rf "$input.tmp" 2>/dev/null
				echo -e "\nWarning: \"unzip\" package was not found."
				echo -e "If using Ubuntu, execute \"sudo apt-get unzip install\" to deploy and re-try.\n"
				cd $currdir; input=""; error=8; continue
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
						echo "Uncompressing $zfile into $input2 ...                                                       "
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
			echo -e "\nWarning: about to convert multiple files ($nfiles x sip.txt/sipmcDebug.txt/trace.log)."
			echo "This may take a while... You may want to execute the script on a more powerful PC or server."

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