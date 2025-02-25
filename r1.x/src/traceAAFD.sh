#!/bin/bash
version="1.0.2"
NL=$'\n'
TAB=$'\t'
echo ''
today=$(date +%m/%d/%Y)
localip="1.1.1.1:1111"
protocol="TLS"
sipstat=1
alllogs=0
noINFO=0
siplength=666
base64decode=1
voutput=1
vsyslog=0

function usage ()  {
    echo 'traceAAFD.sh v1.0 @ 2022 : converting SIP messages into a format required by traceSM tool'
	echo -e "\t\t\t\t\t\t\t   created by <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceAAFD.sh <options> [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis either \"AvayaAgentLogs.zip\" or SIPMESSAGES.txt from an AAfD LogReport"
	echo '  Options:'
	echo -e "\t-h:\t\tget Usage screen"
	echo -e "\t-b:\t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-s:\t\tdo not provide statistics/progress on execution of this conversion"
	echo -e "\t-A:\t\tconvert all aditional logs in logreport where SIP message found (SIPMESSAGESx.txt)"
	echo -e "\t-I:\t\tignore all SIP INFO messages (used in sharedcontrol session)"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0
	sipstart=0
	siplines=0
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
			echo -en "$file => $n/$rec Msgs converted            \r"
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
	if [[ $line == *"RECEIVED"* ]]; then
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

	elif [[ $line == *"SENT"* ]]; then
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
	    reset_sipmsg
	fi
	if [[ $((dirdefined)) != 0 ]]; then
#		ip=$(echo $line | awk '{print $(NF-1)}')			
		ip=$(echo "$line" | awk '{print $9}')		# cut -d' ' -f10)
		ip1=$(echo $ip    | cut -d':' -f1)
		ip2=$(echo $ip    | cut -d':' -f2 | cut -d'.' -f1)
		ip=$ip1:$ip2
		siplength=$(echo "$line" | awk '{printf "%i",$NF}')
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
# 2022-05-20 09:33:24.326 DBH [13536] SIGNAL | SENT to 10.134.117.194:5061. Length= 604.			

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

function convert_siplog () {
if [[ $file != "" ]]; then
	basefile=""; output=""; rec=0
	if [[ $input != "" ]] && [[ $file != "" ]]; then
		if [[ $file == *"."* ]]; then
			basefile=$(echo "${file%.*}")
		else
			basefile=$file
		fi
		file="$input.tmp/$file"
	fi

	fsize=0; rec=0
	if [ -f "$file" ]; then
		fsize=$(wc -c < "$file" 2>/dev/null)
	fi
	if [[ $((fsize)) -gt 0 ]]; then
		rec=$(egrep -c "DBH \[" "$file")
#		rec=$(grep -E "::SIP|\] PPM\:" $file| wc -l)		
	fi

	if [[ $rec == 0 ]]; then
		if [[ $var != $file ]]; then
			echo "error: $var -> $file does not include any SIP messages in the expected format."		
		else
			echo "error: $var file does not include any SIP messages in the expected format."
		fi
		error=1
		rec=$(egrep -m 1 -c -e "^CSeq:*" "$file")
		if [[ $rec != 0 ]]; then
			if [[ $var != $file ]]; then
				echo "Though found a line starting with \"CSeq:\" - so there might be some SIP messages included in $var -> $file"
			else
				echo "Though found a line starting with \"CSeq:\" - so there might be some SIP messages included in $var"			
			fi
		else
			rec=$(egrep -c "^User-Agent: Avaya Agent for Desktop*" "$file")
			if [[ $rec == 0 ]]; then
				echo 'And, could not find any lines including "CSeq:" or "User-Agent: Avaya Agent for Desktop" either.'
			fi
		fi
		echo "Verify source and content of this $file."
		echo ''; error=2; return
	else
		if [[ $input != "" ]] && [[ $input != $file ]] && [[ $basefile != "" ]]; then
			output="$input-$basefile"
		else
			output=$input			
		fi

		if [[ $output != "" ]]; then
			newfile="$output.asm.tmp"
		else
			newfile="$file.asm.tmp"
		fi
		if [ -f "$newfile" ]; then
			rm "$newfile"
		fi

 # echo file=$file basefile=$basefile filelist=$filelist
 # echo input=$input output=$output newfile=$newfile

		echo "# This file had been created by $0 v$version on $today at $currtime." > "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"

		if [[ $var != $file ]]; then
			echo -e "# Input/output file: $var -> $file -> $var.asm\n" >> "$newfile"
		else 
			echo -e "# Input/output file: $var -> $var.asm\n" >> "$newfile"
		fi

#	    conv=$(awk -e '/DBH \[*/{flag=1} flag; /}/{flag=0}' "$file")
	    conv=$(awk -W source='/DBH \[*/{flag=1} flag; /}/{flag=0}' "$file")			

		vsyslog=77
		base64found=0
		base64msg=0
		useragent=""
		foundipaddr=""
		nlines=0
		sipyear=""
		sipmonth=""
		sipday=""
		siphour=""
		sipmin=""
		sipsec=""
		sipmsec=""
		sipmsg=0
		siptotalmsg=0
		sipmaxlines=0
		sipmaxsplit=0
		sipwordlist=""		
		longestmsg=0		
		sipin=0
		sipout=0
		n=0		

	    reset_sipmsg

		while IFS= read -r line
		do
			nlines=$((nlines+1))

			if [[ $line == *"DBH ["* ]]; then
				if [[ $((sipstart)) != 0 ]]; then
					complete_sipmsg
				fi
				insidesip=1
				base64found=0
				siptotalmsg=$((siptotalmsg+1))	
				sip_direction
				get_sip_datetime								
			elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]] && [[ $line == "{"* ]];	then
#				sipmsg_header	
				sipstart=1
			elif [[ $((sipstart)) ==  1 ]];	then
				if [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
					reset_sipmsg
					continue
				else
					sipmsg_header	
					start_sipmsg
					sipstart=2
				fi
			elif [[ $((sipstart)) == 2 ]] && [[ $line == *"}"* ]]; then
				complete_sipmsg
			elif [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64"
				fi
			elif [[ $((base64found)) != 0 ]]; then
				echo "$line" >> "$newfile.b64"
			else
				echo "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
			fi				
		done <<< "$conv"

		if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg
		fi
		echo '' >> "$newfile"

		if [[ $output == "" ]]; then
			output="$var"
		fi

        if [[ $((sipstat)) != 0 ]]; then
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
		echo -e "\tTask started: $currtime - completed: $(date +%R:%S)"
		echo ''

		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		pwd;ls -l "$output.asm"
		echo ''
	fi
fi
} # convert_siplog()

################################# Execution starts here #####################################
if [[ $# -eq 0 ]]; then
	usage
    exit 0
else
  while getopts ":hbf:sAI" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	A)
		alllogs=1;;
    I)
		noINFO=1;;		
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

		voutput=$var
		if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
			voutput=1
		fi
		skipper=0
		continue
	fi

	n=0
	error=0
	file=$var
	currtime=$(date +%R:%S)
	input=""
	vsyslog=0

	if [ -f $var ];then
		echo -en "Exploring content in $var... stand by\r"

		filetype=$(file -b "$file")
		filecontent="AAfD"		

		if [[ $filetype == "Zip archive"* ]] && [[ $filecontent == "AAfD" ]]; then
			if [[ $file == *"."* ]]; then
#				outfile=$(echo "$file" | cut -d'.' -f1)
				input=$(echo "${file%.*}")
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
			mkdir "$input.tmp"
			cd "$input.tmp"			
			unzip -qq -v >/dev/null
			if [[ $? == 0 ]]; then
				unzip -qq "../$file"
				if [[ $? -gt 1 ]]; then
					tar --version >/dev/null
					if [[ $? == 0 ]]; then
						tar xf "../$file"
						if [[ $? != 0 ]]; then
							error=8
							echo "error: unable to uncompress $file, using \"tar\" utility."
							echo ''								
						fi
					else
						error=8
						echo "error: could not uncompress $file, using unzip.  Suggest to deploy \"unzip\" package"
						echo ''	
					fi
				fi
			else
				echo "warning: \"unzip\" package was not found - if using Ubuntu, execute \"sudo apt-get unzip install\" and re-try."
				echo ''
				tar --version >/dev/null
				if [[ $? == 0 ]]; then
					tar xf "../$file"
					if [[ $? != 0 ]]; then
						error=8
						echo "error: could not uncompress $var, using \"tar\" utility either."
						echo "Suggest to validate uncompressing $var in your environment."
						echo ''; continue
					fi
				fi
			fi

			file=""; filelist=""
			if [ -f "LogsFromDefaultDir.zip" ]; then
				unzip -qq "LogsFromDefaultDir.zip"			
				if [[ $((alllogs)) != 0 ]]; then
					filelist=`ls -r -t1 SIPMessages*.txt | egrep -v bak`
				else
					file=$(ls -r -t1 SIPMessages*.txt 2>/dev/null | egrep -v bak | head -1)					# ususally this would be SIPMessages0.txt file				
					filelist=$file
				fi
			else
				if [[ $((alllogs)) != 0 ]]; then
					filelist=`ls -r -t1 SIPMessages*.txt | egrep -v bak`
				else
					file=$(ls -r -t1 SIPMessages*.txt 2>/dev/null | egrep -v bak | head -1)					# ususally this would be SIPMessages0.txt file				
					filelist=$file
				fi
			fi

			if [[ $file == "" ]] && [[ $filelist == "" ]]; then
				echo "error: extracted $var does not include any SIPMessages*.txt files"
				echo ''					
				error=9
			fi
			cd ..			
		fi

# echo "filetetype=$filetype input=$input filename=$file" pwd=$PWD

	if [[ $((alllogs)) != 0 ]]; then
		nfiles=0
		if [[ $filelist != "" ]]; then
			nfiles=$(echo $filelist | wc -w)
		fi

		if [[ $((nfiles)) -gt 1 ]]; then
			echo "Warning: about to convert multiple files ($nfiles x SIPMessages.txt), this may take a while... "
			echo "You may want to execute this script on a more powerful PC or server."
			echo ''
		fi
	fi
	
	for file in $filelist;
	do
		convert_siplog
	done

else
	echo "error: file $var was not found."
	error=3
	echo ''	
fi
done