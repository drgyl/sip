#!/bin/bash
version="1.0.2"
let linelength=0
let siplength=666
let sipmonth=12

NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
pattern1=": [TR]: [0-9]{1,3}.*\([A-Z]{3}\)*"
pattern2="\(UDP\)$"
sipstat=1
adjusthour=0
base64decode=1
protocol="TLS"
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=1  ## 1 = 1XC SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

function usage ()  {
    echo "traceBRIA.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t\t\t\t     created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceBRIA.sh [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis the Log.txt or Output.txt file (collected from Bria@CounterPath softclient)"	
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
	sipyear=""
	dirdefined=0
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

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile.b64" ]]; then
		base64 -d "$newfile.b64" >> "$newfile"
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

function sip_direction () {
if [[ $((dirdefined)) == 0 ]]; then		
	if [[ $((dirdefined)) == 1 ]]; then
#	if [[ $line == *" incoming from: "* ]]; then
		sipstream=5f70
#		dirdefined=1
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
#       ip=$(echo $line | cut -d' ' -f14)
# 	    protocol=$(echo $line | cut -d' ' -f15)

    elif [[ $((dirdefined)) -gt 1 ]]; then
#	elif [[ $line == *"Transmitting to"* ]]; then
		sipstream=1474
#		dirdefined=2
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

	if [[ $((dirdefined)) == 1 ]] || [[ $((dirdefined)) == 2 ]]; then
       	ip=$(echo "$line"       | cut -d' ' -f16)
	    protocol=$(echo "$line" | cut -d' ' -f17)
	fi
fi	
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) -gt 1 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(echo "$line" | awk -F'User-Agent: ' '{print $2}')
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
# 2022-05-24 10:21:10.754 | INFO |   RESIP:TRANSPORT | 110164 t44372 Transmitting to [ V4 10.134.117.194:5060 TCP target domain=10.134.117.194 mFlowKey=0 ] tlsDomain= via [ V4 135.105.163.42:62851 TCP target domain=10.134.117.194 mFlowKey=0 ]
# 2022-05-24 10:37:11.274 | INFO |   RESIP:TRANSPORT | 110164 t328 incoming from: [ V4 10.134.117.194:47389 TCP target domain=unspecified mFlowKey=4512 ]

    sipday=$(echo "$line"   | cut -d' ' -f1)
	sipyear=$(echo $sipday  | cut -d'-' -f1)
    sipmonth=$(echo $sipday | cut -d'-' -f2)
	sipday=$(echo $sipday   | cut -d'-' -f3)
	
	sipmsec=$(echo "$line"  | cut -d' ' -f2)
	siphour=$(echo $sipmsec | cut -d':' -f1)
	sipmin=$(echo $sipmsec  | cut -d':' -f2)
	sipsec=$(echo $sipmsec  | cut -d':' -f3)
	sipmsec=$(echo $sipsec  | cut -d'.' -f2)
	sipsec=$(echo $sipsec   | cut -d'.' -f1)

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
  while getopts ":hbf:s" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
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
		else
			skipper=0
		fi
		continue
	elif [[ $skipper != 0 ]]; then
		skipper=0
		voutput=$var
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi
		continue
	fi
		
	file=$var
	currtime=$(date +%R:%S)
	error=0
	vsyslog=0
	
	if [ -f $file ]; then
		echo -en "Exploring content in $var... stand by\r"

		## rec=$(egrep " SIPMESSAGE: " $file| wc -l)
		rec=$(egrep -m 1 -c -e ".*Bria.*" "$file")

		if [[ $rec == 0 ]]; then
		    echo "error: $var does not appear to be a BRIA logfile. Verify source and content of this file."
			echo ''			
			error=1
			continue
		else
			rec=$(egrep -c -e "^CSeq:.*" "$file")
			if [[ $rec == 0 ]];	then
				echo "error: No SIP messages have been found in $var."
				echo "Perhaps this file is not an DebugSIP.txt logfile... or, FINEST debug was not enabled"
				echo "Verify source and content of this file."
				echo ''
	    		error=2
				continue
			else
				rec2=$(egrep -c -e "* Transport failure: " "$file")
				rec=$((rec-$rec2))
				vsyslog=3				
			fi
		fi
    
		if [[ $rec -gt 0 ]] && [[ $((vsyslog)) != 0 ]]; then
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			ip=""
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
			sipin=0
			sipout=0

			reset_sipmsg
			vsyslog=3			

			newfile=$file.asm.tmp
			if [ -f $newfile ]; then
				rm $newfile
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"

#            conv=$(awk -e '/^\-\-\-\-\-\-\-\-\-\-\-\-\-.*\-\-\-\-\-\-\-$/{flag=1} flag; /}/{flag=0}' "$file")
            # conv=$(awk -W source='/.*Transmitting to.*|.*incoming from:.*"/{flag=1} flag; /}/{flag=0}' "$file")
# ----------------------------------------------------------------------------------------			

			while IFS= read -r line
			do
				nlines=$((nlines+1))

				if [[ $((insidesip)) == 0 ]]; then
                	if [[ $line =~ RESIP.*incoming\ from: ]]; then
				   		dirdefined=1
                	elif [[ $line =~ RESIP.*Transmitting\ to ]]; then
				   		dirdefined=2
					elif [[ $line =~ RESIP.*Making.*request: ]]; then
						dirdefined=3
# 2022-05-24 10:29:35.968 | DEBUG |         RESIP:DUM | 110164 t328 Making subscription (from creator) request: SUBSCRIBE sip:8811135@lab.bud.avaya.com:5061 SIP/2.0
# Via: SIP/2.0/ ;branch=z9hG4bK-524287-1---e4057f49a97d0a6b;rport
					fi

					if [[ $((dirdefined)) != 0 ]]; then
#			    if [[ $((insidesip)) == 0 ]]; then
#				  if [[ $line == *"Transmitting to"* ]] || [[ $line == *" incoming from: "* ]]; then

				#  && [[ $line =~ $pattern2 ]]

				  	  	if [[ $((sipstart)) != 0 ]]; then
                    	  complete_sipmsg
				    	fi
			 	    	insidesip=1
			 	    	siptotalmsg=$((siptotalmsg+1))	
				    	base64found=0
				    	sip_direction
			 	    	get_sip_datetime

						if [[ $((dirdefined)) == 3 ]]; then
						  ip="6.6.6.6:6666"
						  protocol="TLS"
						  line=$(echo "$line" | awk -F"request: " '{print $2}')
					      sipmsg_header
		                  start_sipmsg
						  insidesip=2
						fi
					fi			   
                elif [[ $((insidesip)) == 1 ]] && [[ $((dirdefined)) != 0 ]]; then
				   insidesip=2
				elif [[ $((insidesip)) == 2 ]] && [[ $((sipstart)) == 0 ]]; then
				   if [[ $((dirdefined)) == 2 ]] && [[ ${#line} -lt 2 ]]; then # since "Transmitting to " lines often have no SIP msg
#				   if [[ $linelength -l 3 ]]; then
				      insidesip=0
					  dirdefined=0
				   elif [[ $((dirdefined)) -lt 3 ]]; then
				      sipmsg_header
	                  start_sipmsg
				   fi
				elif [[ $((sipstart)) == 1 ]]; then
					if [[ $line == " | "* ]] || [[ $line == "sigcomp "* ]]; then
				       complete_sipmsg
					elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
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
#	    done <<< "$conv"
		done < "$file"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

        if [[ $((sipstat)) != 0 ]]; then
			if [[ ${#endptaddr} == 0 ]]; then
				echo "==> $sipmsg out of $n/$rec SIP messages has been converted into $var.asm file"
			else
				if [[ $((sipmsg)) == 0 ]]; then 
					echo "==> no SIP messages were found for addr=$endptaddr in $var file"
				else
					echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
					echo "    has been converted for addr=$endptaddr into $var.asm file"
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
#		rm $file					# this is already a tmp file, can be removed
		pwd;ls -l "$var.asm"
		echo ''
	fi
else
	echo "error: file $var was not found."
	error=3
fi
done