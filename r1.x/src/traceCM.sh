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
voutput=3  ## 1 = SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

## 1) input file: decoded CM MST trace file (.m)
## 10)input file: raw CM MST trace file (.M)

function usage ()  {
    echo "traceCM.sh v$version @ 2022 : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t     created by <gbaross@avaya.com> & <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceCM.sh [OPTIONS] [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either a raw or a decoded MST file collected from Communication Manager server"
	echo '  OPTIONS:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d (for decoded MST only)"		
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
#	sipyear=""
    emptyline=0
	dirdefined=0
	localip=""
	localip1=""
	localip2=""
	ip=""
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then		
	sipstart=1
	emptyline=0
	siplines=$((siplines+1))
	if [[ $((voutput)) == 1 ]]; then 
		echo -en "{$NL[$sipstream] $line$NL" >> "$newfile"
	elif [[ $((voutput)) == 2 ]]; then
		echo -en "$NL$line\0xd$NL" >> "$newfile"
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
		rm "$newfile.b64"
		base64found=0
		base64msg=$((base64msg+1))
	fi

	if [[ $((voutput)) == 1 ]]; then
		echo -e "$NL[$sipstream] }\x0d$NL" >> "$newfile"
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
#	if [[ $line == *"==> SIP In" ]]; then
#		dirdefined=1
		sipstream=5f70
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

	elif [[ $((dirdefined)) == 2 ]]; then
#	elif [[ $line == *"<-- SIP Out" ]]; then
#		dirdefined=2
		sipstream=1474
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
#	else
#		insidesip=0
#		dirdefined=0
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
#     1  15:01:00.215  8B          <-- SIP Out
#   sipmonth=$(echo $today | cut -d'/' -f1)
# 	sipday=$(echo "$today" | cut -d'/' -f2)
# 	sipyear=$(echo $today | cut -d'/' -f3)
									
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

function convert_rawMST () {
	conv=$(awk -W source='/M\s[0-9]*\s8[ab]/{flag=1} flag; /N/{flag=0}' "$file" | sed -e '/^D/ s/D[\t]*//' | sed ':a;$!{N;/\n[MN]/!{s/\n/ /;ba}};P;D')
	awk '{

	if ($1 =="M" )
		{
	counter++	
#	msgtag="1474"
	if ($3 =="8b"){
		 printf "[" substr($6,1,6);
		 printf "20";
		 printf substr($6,7,2);
		 printf " ";
		 sub(/\./,":",$5);
		 printf $5"] DBH:     SIGNAL: ["counter"] SENT to ";
#		 printf $5"] DBH:     SIGNAL: ["msgtag"] SENT to ";
		 printf "%d",strtonum("0x"$15); printf "."
		 printf "%d",strtonum("0x"$16); printf "."
		 printf "%d",strtonum("0x"$17); printf "."
		 printf "%d",strtonum("0x"$18); printf ":"
		 printf "%d",strtonum("0x"$19 $20);
		}
		else
		{
		 printf "[" substr($6,1,6);
		 printf "20";
		 printf substr($6,7,2); 
		 printf " ";
		 sub(/\./,":",$5);
		 msgtag="5f70"
		 printf $5"] DBH:     SIGNAL: ["counter"] RECEIVED from ";
#         printf $5"] DBH:     SIGNAL: ["msgtag"] RECEIVED from ";
		 printf "%d",strtonum("0x"$8); printf "."
		 printf "%d",strtonum("0x"$9); printf "."
		 printf "%d",strtonum("0x"$10); printf "."
		 printf "%d",strtonum("0x"$11); printf ":"
		 printf "%d",strtonum("0x"$12 $13);
		}
	  	printf "\n\n{\n["counter"] " 		
#	  	printf "\n\n{\n["msgtag"] " 				  

		for(i=23;i<=NF-1;i++) printf "%c",strtonum("0x"$i); print ""
		printf "\r\n["counter"] }\r\n\n"
		} 
	}' <<< "$conv" >> "$newfile"
} # convert_rawMST()

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
	error=0
	vsyslog=0
	
	if [ -f "$file" ]; then
		echo -en "Exploring content in $var... stand by\r"
		rec=$(egrep -c -e "^CSeq:*" "$file")
		rec2=$(egrep -m 1 -c "==> SIP In|<-- SIP Out" "$file")

		if [[ $rec == 0 ]] || [[ $rec2 == 0 ]];	then
			rec=$(egrep -E "M[[:blank:]][[:digit:]]*[[:blank:]]8[ab]" "$file" | wc -l)
			if [[ $(($rec)) == 0 ]]; then
				echo "error: No SIP messages have been found in $var. Looks like this file is neither a raw nor a decoded CM MST."
				echo ''; error=1; continue
			else
				vsyslog=10
				voutput=2
			fi
		else
			vsyslog=1
		fi
		if [[ $((vsyslog)) != 0 ]]; then
			base64found=0
			base64msg=0
			foundipaddr=""
			useragent=""
			nlines=0
			sipyear=$(echo $today | cut -d'/' -f3)
			sipmonth=$(echo $today| cut -d'/' -f1)
			sipday=$(echo $today  | cut -d'/' -f2)
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

			newfile="$file.asm.tmp"
			if [ -f $newfile ]; then
				rm $newfile
			fi
			echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		    echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		    echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"


		if [[ $((vsyslog)) == 10 ]]; then
			convert_rawMST
		elif [[ $((vsyslog)) == 1 ]]; then			
			while IFS= read -r line
			do
				linelength=${#line}
				nlines=$((nlines+1))

#                if [[ $((insidesip)) == 0 ]]; then
#			        if [[ $line == *"==> SIP In" ]] || [[ $line == *"<-- SIP Out" ]]; then
                if [[ $line =~ "<-- SIP Out" ]]; then
				    if [[ $((sipstart)) != 0 ]]; then complete_sipmsg; fi
					dirdefined=2
				elif [[ $line =~ "==> SIP In" ]]; then
				    if [[ $((sipstart)) != 0 ]]; then complete_sipmsg; fi
				    dirdefined=1
				fi

				if [[ $((insidesip)) == 0 ]] && [[ $((dirdefined)) != 0 ]]; then
#			        if [[ $line == *"==> SIP In" ]] || [[ $line == *"<-- SIP Out" ]]; then

				        if [[ $((sipstart)) != 0 ]]; then
				    	    complete_sipmsg
				        fi

					    insidesip=1
			 		    get_sip_datetime
						sip_direction
#                    fi
			    elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^\#.* ]]; then
				    complete_sipmsg
				elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
				    insidesip=2
			    elif [[ $((insidesip)) == 2 ]] && [[ $line == *"From IPAddr:"* ]]; then
                    insidesip=3
					localip1=$(echo "$line" | cut -d' ' -f3)
					localip2=$(echo "$line" | cut -d' ' -f6)
					proto=$(echo "$line"    | cut -d' ' -f8)
					protocol=${proto:0:3}
					
                elif [[ $((insidesip)) == 3 ]] && [[ $line == *"To IPAddr:"* ]]; then
				    insidesip=4
					ip1=$(echo "$line" | cut -d' ' -f3)
#					ip2=$(echo $line | cut -d' ' -f6 | sed 's/CTRLVM//g')             # it appends ^M to the end of string
					ip2=$(echo "$line" | awk '{printf "%i",$6}')
			    elif [[ $((insidesip)) == 4 ]] && [[ $((sipstart)) == 0 ]]; then
				    insidesip=5
					if [[ $((dirdefined)) == 1 ]]; then
					   ip=$localip1:$localip2
					   localip=$ip1:$ip2
					else
					   ip=$ip1:$ip2
					   localip=$localip1:$localip2
				    fi
                elif [[ $((insidesip)) == 5 ]] && [[ $((sipstart)) == 0 ]]; then
					if [[ $ip != "" ]] && [[ $endptaddr != "" ]] && [[ $ip != *$endptaddr* ]]; then
						if [[ $localip != "" ]] && [[ $endptaddr != "" ]] && [[ $localip != *$endptaddr* ]]; then
							reset_sipmsg
							continue
						fi
				  	else
						siptotalmsg=$((siptotalmsg+1))	
						base64found=0
						sipmsg_header
						start_sipmsg
					fi
				elif [[ $((sipstart)) == 1 ]]; then
                    if [[ $((linelength)) -lt 2 ]]; then
					   emptyline=$((emptyline+1))
					   if [[ $((emptyline)) == 2 ]]; then
					      complete_sipmsg
                       fi
					elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
						base64found=1
						emptyline=0
						echo "# Base64 dump found" >> "$newfile"
						if [[ -f "$newfile.b64" ]]; then
							rm "$newfile.b64"
						fi
					elif [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]]; then
						echo "$line" >> "$newfile.b64"
						emptyline=0
					else
						echo "$line" >> "$newfile"
						siplines=$((siplines+1))
						get_useragent
						emptyline=0
					fi
				fi
#		    done <<< "$conv"
            done < $file
#	    fi

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