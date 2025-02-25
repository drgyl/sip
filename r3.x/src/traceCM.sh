#!/bin/bash
version="2.0.0.3"
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
adjusthour=0
alllogs=0
bCAT=0
noINFO=0
findANI=""
base64decode=1
bDelTemp=1
protocol="TLS"
CMversion=""
CMpatch=""
localip="1.1.1.1:1111"
endptaddr="" # 135.105.129.244"
voutput=0  ## 1 = SIPMESSAGES.txt, 2 = eqios SipMessages.txt, 3 = traceSM asset.log
vsyslog=0

## 1) input file: decoded CM MST trace file (.m)
## 10)input file: raw CM MST trace file (.M)

function usage ()  {
    echo "traceCM.sh v$version @ $year : converting SIP messages into a format required by traceSM tool"
	echo -e "\t\t\t\t       created by <gbaross@avaya.com> & <lgyalog@avaya.com>"	
#	echo ''
	echo 'Usage: traceCM.sh [OPTIONS] [<LOG_FILE>,...]'
	echo '  Where:'
	echo -e "\t<LOG_FILE>\tis a log file collected from Communication Manager (either raw or decoded MST)"
	echo -e "\t\t\tor a .zip, .tgz or .gz file including one or more ECS logfiles, or a raw/decoded MST"				
	echo '  OPTIONS:'
	echo -e "\t-h \t\tget Usage screen"
	echo -e "\t-e ipaddr:\tconvert messages only with IP addr: a.b.c.d (for decoded MST only)"		
	echo -e "\t-b \t\tdo not decode Base64 encoded content of SIP header lines"
	echo -e "\t-I \t\tignore all SIP INFO messages (used in sharedcontrol session or DTMF)"
	echo -e "\t-A \t\tconvert all aditional logs in logreport or in folder where SIP message found"
	echo -e "\t-C \t\tconcatenate output (.asm) files (if converting multiple logfiles)"	
	echo -e "\t-N ANI\t\tfind a call with caller/called number matching to ANI (digit string)"	
	echo -e "\t-s \t\tdo not provide statistics/progress on execution of this conversion"	
	echo -e "\t-f [1,2,3]:\toutput format, 1=1XC SIPMESSAGES.txt, 2=1XSIPIOS SIPMESSAGES.txt, 3=native traceSM"
	echo ''
} # usage()

function reset_sipmsg () {
	insidesip=0;	sipstart=0; 	dirdefined=0
	siplines=0;	    emptyline=0;	base64found=0	
	sipdate=""; siptime=""
	localip=""; ip=""
#	sipyear=""	
} # reset_sipmsg()

function start_sipmsg () {
if [[ $((dirdefined)) != 0 ]]; then	
	emptyline=0	
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

#	if [[ $((siplines)) -gt $((sipmaxlines)) ]]; then	
#		sipmaxlines=$siplines
#		longestmsg=$sipmsg
#		if [[ $((dirdefined)) == 1 ]]; then 
#			longestsipword="RX $sipword"
#		elif [[ $((dirdefined)) == 2 ]]; then
#			longestsipword="TX $sipword"
#		fi
#	fi
#	
#	if [[ $((dirdefined)) == 1 ]]; then	
#		sipin=$((sipin+1))
#	else
#		sipout=$((sipout+1))
#	fi

	if [[ $((base64decode)) != 0 ]] && [[ $((base64found)) != 0 ]] && [[ -f "$newfile.b64" ]]; then
		base64 -d "$newfile.b64" >> "$newfile"
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
		sipstart=0; n=$((n+1))
		if [[ $((sipstat)) != 0 ]]; then		
			echo -en "$var => $n/$rec Msgs converted                                 \r"
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
	if [[ $((dirdefined)) == 1 ]]; then
#	if [[ $line == *"==> SIP In" ]]; then
#		dirdefined=1
		sipstream=5f70
		case $voutput in
		1|2)	dirstring1="RECEIVED";  dirstring2="from";;
		3)		dirstring1="-->"; 		dirstring2="ingress";;
		esac
	elif [[ $((dirdefined)) == 2 ]]; then
#	elif [[ $line == *"<-- SIP Out" ]]; then
#		dirdefined=2
		sipstream=1474
		case $voutput in
		1)	dirstring1="SENT";		dirstring2="to";;
		2)	dirstring1="SENDING";	dirstring2="to";;
		3)	dirstring1="<--"; 		dirstring2="egress";;
		esac
#	else
#		insidesip=0
#		dirdefined=0
	fi
} # sip_direction()

function get_useragent () {
	if [[ $useragent == "" ]] && [[ $((dirdefined)) == 2 ]]; then
		if [[ $line == *"User-Agent:"* ]]; then
			useragent=$(awk -F'User-Agent: ' '{print $2}' <<< "$line")
			if [[ $useragent != "Avaya CM"* ]]; then
				useragent=""
			fi
		fi
	fi
} # get_useragent()

function get_sip_datetime () {
#     1  15:01:00.215  8B          <-- SIP Out
#   sipmonth=$(echo $today | cut -d'/' -f1)
# 	sipday=$(echo "$today" | cut -d'/' -f2)
# 	sipyear=$(echo $today | cut -d'/' -f3)
									
	sipmsec=$(awk '{print $2}' <<< "$line")
	siphour=$(cut -d':' -f1 <<< "$sipmsec")
	sipmin=$(cut -d':' -f2 <<< "$sipmsec")
	sipsec=$(cut -d':' -f3 <<< "$sipmsec")
	sipmsec=$(cut -d'.' -f2 <<< "$sipsec")
	sipsec=$(cut -d'.' -f1 <<< "$sipsec")

	case $voutput in
	1)	sipdate=$(echo $sipmonth/$sipday/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec);;
	2)	sipdate=$(echo $sipyear/$sipmonth/$sipday)
		siptime=$(echo $siphour:$sipmin:$sipsec:$sipmsec);;
	3)	sipdate=$(echo $sipday/$sipmonth/$sipyear)
		siptime=$(echo $siphour:$sipmin:$sipsec.$sipmsec);;
	esac
} # get_sip_datetime()

function explore_logfolder() {
	targetfiles=""
	targetX=""; targetX=$(ls -t1 -r 2*.log 2>/dev/null)
	if [[ $? != 0 ]]; then
		targetX=""
	elif [[ $targetX != "" ]]; then
		targetfiles="$targetX"
	fi

	if [[ $((alllogs)) == 0 ]]; then
		if [[ "$targetfiles" != "" ]]; then
#			targetfiles=$(tail -1 <<< $targetfiles)
			targetfiles=${targetfiles##* }							# last word			
		else
			targetfiles="$targetX"
		fi
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
#		destdir="$destdir/$folder"
		cd "$folder"
	fi

	if [ -d "var" ]; then
		destdir="$destdir/var"
		cd "var"
		if [ -d "log" ]; then
			destdir="$destdir/log"
			cd "log"
			if [ -d "ecs" ]; then
				destdir="$destdir/ecs"
				target="$target-ecslog"
				cd "ecs"
			else
				target="$target-varlog"
			fi
		else
			target="$target-var"
		fi
	elif [ -d "log" ]; then
		destdir="$destdir/log"
		cd "log"
		if [ -d "ecs" ]; then
			destdir="$destdir/ecs"
			target="$target-ecs"
			cd "ecs"
		else
			target="$target-log"
		fi
	elif [ -d "ecs" ]; then
		destdir="$destdir/ecs"
		target="$target-ecs"
		cd "ecs"
	fi

	explore_logfolder

	if [[ $file == "" ]] && [[ $origtarget != "" ]]; then
		if [ -s "$origtarget.m" ]; then
			file="$destdir/$origtarget.m"
			bSinglefile=1
		elif [ -s "$origtarget.mm" ]; then
			file="$destdir/$origtarget.mm"
			bSinglefile=1
		elif [ -s "$origtarget.M" ]; then
			file="$destdir/$origtarget.M"
			bSinglefile=1
		elif [[ $file == "" ]]; then
			if [ -s "$folder.m" ]; then
				file="$destdir/$folder.m"
				bSinglefile=1
			elif [ -s "$folder.mm" ]; then
				file="$destdir/$folder.mm"
				bSinglefile=1							
			elif [ -s "$folder.M" ]; then
				file="$destdir/$folder.M"
				bSinglefile=1							
			fi
		fi
	fi	
fi
} # explore_folders()

function convert_logmst () {
	EPAT='MST '	
	echo -e "\nConverting CM logfile into raw MST format..."	
	egrep "$EPAT" "$file" |sed -e 's.[]|:=,()@[]. .g' | awk '
BEGIN {
	BYTESperLINE=16
	HASHREC = 20
	STDERR = "cat >&2"
}

# {print}

(HASH) {
	# if ((NR % (80*HASHREC)) == 0) { printf "\n" }
	# else if ((NR % HASHREC) == 99) { printf "*" }
	#if ((NR % HASHREC) == 0) { printf "|\r" }
	#else if ((NR % HASHREC) == int(.25*HASHREC)) { printf "\\\r" }
	#else if ((NR % HASHREC) == int(.50*HASHREC)) { printf "-\r" }
	#else if ((NR % HASHREC) == int(.75*HASHREC)) { printf "/\r" }
	if ((NR % HASHREC) == 0) { printf "\r%d",NR | STDERR }
}

($7 == "MST") {
	# ignore informational lines

	if (CurMstByte != 0 && $8 == "++++")
	{
		# continuation line
		CurMstByte = dumpBytes(9, CurMstByte, Bytes_in_msg)
		next
	}
	else if (int($8) == 0)
	{
		# ignore:
		# continuation (++++) when none was expected
		# abnormal MST line
		next
	}

	# New message
	Bytes_in_msg = int($8) - 1

	if (!Hdr) {
		Hdr = 1
		printf("H1	v1	@(#)logmst	0.0.0.1	9/22/03\n");
		printf("H2	MST_ALL\n");
		printf("H3	%s	%s	%s\n",HOST,USER,DAYTIME)
		printf("H4	%s	%s\n",RELEASE,DAYTIME)
		printf("H6	%s\n",PATCH)
		printf("H7	%s\n",FULLCMREL)
	}

	if ($9 == "8a" || $9 == "8b") {
		# SIP MST message
		printf("M\t%d\t%s\t1\t",++Msgno,$9)
		printf("\t%02d:%02d:%02d.%03d",
			substr($2,1,2),
			substr($2,3,2),
			substr($2,5,2),
			substr($2,7,3))
		printf("\t%02d/%02d/%02d",
			substr($1,5,2),
			substr($1,7,2),
			substr($1,3,2))

		CurMstByte=0

		CurMstByte = dumpBytes(10, CurMstByte, Bytes_in_msg)
		next
	}
}

function dumpBytes(beginIndex, mstByte, msgSize,	i)
{
	for (i=beginIndex; i <= NF; i++) {
		if ((mstByte++ % BYTESperLINE) == 0)
			printf("\nD\t\t%s",$i)
		else
			printf(" %s",$i)
	}

	if (msgSize == mstByte) {
		# end of message
		printf("\nN\n")
		return(0)
	}
	else
		return(mstByte)
}

END {
}
' HASH=0 PATCH="unknown CM patch" RELEASE="unknown CM release" FULLCMREL="unknown CM full release" HOST="$(hostname)" USER="$USER" DAYTIME="$(date +%H:%M:%S\	%m/%d/%y)" > "$file.logmst"
} # convert_logmst()

function convert_rawMST1 () {
	echo "Converting raw MST file..."
	conv=$(awk -W source='/M\s[0-9]*\s8[ab]/{flag=1} flag; /N/{flag=0}' "$file" | sed -e '/^D/ s/D[\t]*//' | sed ':a;$!{N;/\n[MN]/!{s/\n/ /;ba}};P;D')
	awk '{
		if ($1 =="M" ) {
			counter++
#			msgtag="1474"
			if ($3 =="8b") {
				printf "[" substr($6,1,6);
				printf "20";
				printf substr($6,7,2);
				printf " ";
				sub(/\./,":",$5);
				printf $5"] DBH:     SIGNAL: ["counter"] SENT to ";
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
				printf $5"] DBH:     SIGNAL: ["counter"] RECEIVED from ";
				printf "%d",strtonum("0x"$8); printf "."
				printf "%d",strtonum("0x"$9); printf "."
				printf "%d",strtonum("0x"$10); printf "."
				printf "%d",strtonum("0x"$11); printf ":"
				printf "%d",strtonum("0x"$12 $13);
			}
			printf "\n{\n["counter"] " 		

			for(i=23;i<=NF-1;i++) printf "%c",strtonum("0x"$i); print ""
			printf "\r\n["counter"] }\r\n\n"
		} 
	}' <<< "$conv" >> "$newfile"
} # convert_rawMST1()

function convert_rawMST2 () {
	echo "Converting raw MST file..."
	conv=$(awk -W source='/M\s[0-9]*\s8[ab]/{flag=1} flag; /N/{flag=0}' "$file" | sed -e '/^D/ s/D[\t]*//' | sed ':a;$!{N;/\n[MN]/!{s/\n/ /;ba}};P;D')
	awk '{

		if ($1 =="M" ) {
			counter++
#			msgtag="1474"
			if ($3 =="8b") {
				printf "[20" substr($6,7,2);
				printf "/" substr($6,1,5);
				printf " ";
				sub(/\./,":",$5);
				printf $5"] SENDING 666 bytes to ";
				printf "%d",strtonum("0x"$15); printf "."
				printf "%d",strtonum("0x"$16); printf "."
				printf "%d",strtonum("0x"$17); printf "."
				printf "%d",strtonum("0x"$18); printf ":"
				printf "%d",strtonum("0x"$19 $20);
			}
			else
			{
				printf "[20" substr($6,7,2);
				printf "/" substr($6,1,5);
				printf " ";
				sub(/\./,":",$5);
				printf $5"] RECEIVED 666 bytes from ";
				printf "%d",strtonum("0x"$8); printf "."
				printf "%d",strtonum("0x"$9); printf "."
				printf "%d",strtonum("0x"$10); printf "."
				printf "%d",strtonum("0x"$11); printf ":"
				printf "%d",strtonum("0x"$12 $13);
			}
#		  	printf "\n\n{\n["counter"] "
			printf " {\n\n"

			for(i=23;i<=NF-1;i++) printf "%c",strtonum("0x"$i); print ""
#			printf "\r\n["counter"] }\r\n\n"
			printf "\n}\n\n";
		} 
	}' <<< "$conv" >> "$newfile"
} # convert_rawMST2()


# H1      v1      @(#)logmst      0.0.0.1 9/22/03
# H2      MST_ALL
# H3      avcm1a  init    14:07:17        07/10/23
# H4      R018x.01.0.890.0        14:07:17        07/10/23
# H6      01.0.890.0-26766 KERNEL-3.10.0-1160.24.1.el7 PLAT-rhel7.6-0100
# H7      8.1.3.1.0.890.26766
# M       1       8a      1               13:57:12.584    07/10/23

function convert_rawMST3 () {
	echo "Converting raw MST file..."
	conv=$(awk -W source='/M\s[0-9]*\s8[ab]/{flag=1} flag; /N/{flag=0}' "$file" 2>/dev/null)
	if [[ $? != 0 ]]; then
		conv=$(awk -e '/M\s[0-9]*\s8[ab]/{flag=1} flag; /N/{flag=0}' "$file" | sed -e '/^D/ s/D[\t]*//' | sed ':a;$!{N;/\n[MN]/!{s/\n/ /;ba}};P;D')
	else
		conv=$(awk -W source='/M\s[0-9]*\s8[ab]/{flag=1} flag; /N/{flag=0}' "$file" | sed -e '/^D/ s/D[\t]*//' | sed ':a;$!{N;/\n[MN]/!{s/\n/ /;ba}};P;D')
	fi
	
	awk '{

		if ($1 =="M" ) {
			counter++
#			msgtag="1474"
			if ($3 =="8b") {
				printf "com.avaya.asm  SIPMSGT \n--------------------\n";
				printf substr($6,4,3);
				printf substr($6,1,3);
				printf "20";
				printf substr($6,7,2);
				printf " ";
				sub(/\./,".",$5);
				printf $5" <-- \negress: { L";
				printf "%d",strtonum("0x"$15); printf "."
				printf "%d",strtonum("0x"$16); printf "."
				printf "%d",strtonum("0x"$17); printf "."
				printf "%d",strtonum("0x"$18); printf ":"
				printf "%d",strtonum("0x"$19 $20)
				printf "/R"
				printf "%d",strtonum("0x"$8); printf "."
				printf "%d",strtonum("0x"$9); printf "."
				printf "%d",strtonum("0x"$10); printf "."
				printf "%d",strtonum("0x"$11); printf ":"
				printf "%d",strtonum("0x"$12 $13);
				printf "/TLS/ }\n--------------------\n";
			}
			else
			{
				printf "com.avaya.asm  SIPMSGT \n--------------------\n";			
				printf substr($6,4,3);
				printf substr($6,1,3);
				printf "20";
				printf substr($6,7,2); 
				printf " ";
				sub(/\./,".",$5);
				printf $5" --> \ningress: { L";
				printf "%d",strtonum("0x"$8); printf "."
				printf "%d",strtonum("0x"$9); printf "."
				printf "%d",strtonum("0x"$10); printf "."
				printf "%d",strtonum("0x"$11); printf ":"
				printf "%d",strtonum("0x"$12 $13)
				printf "/R"
				printf "%d",strtonum("0x"$15); printf "."
				printf "%d",strtonum("0x"$16); printf "."
				printf "%d",strtonum("0x"$17); printf "."
				printf "%d",strtonum("0x"$18); printf ":"
				printf "%d",strtonum("0x"$19 $20)
				printf "/TLS/ }\n--------------------\n";
			}
#	  		printf "\n\n{\n["counter"] "
#			printf "{\n"
#			printf "\n"

			for(i=23;i<=NF-1;i++) printf "%c",strtonum("0x"$i); print ""
#			printf "\r\n["counter"] }\r\n\n"
#			printf "\n}\n\n"
			printf "--------------------\n\n"
		} 
	}' <<< "$conv" >> "$newfile"
} # convert_rawMST3()

function convert_MST () {
while IFS= read -r line
	do
#	linelength=${#line}
	nlines=$((nlines+1))

# if [[ $((siptotalmsg)) -gt 366 ]]; then
#	break
# fi

#   if [[ $((insidesip)) == 0 ]]; then
#	if [[ $line == *"==> SIP In" ]] || [[ $line == *"<-- SIP Out" ]]; then
    if [[ $line =~ "<-- SIP Out" ]]; then
	    if [[ $((sipstart)) != 0 ]]; then 
			complete_sipmsg;
		fi
		dirdefined=2
	elif [[ $line =~ "==> SIP In" ]]; then
    	if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg;
		fi
		dirdefined=1
	elif [[ $line =~ "msg bytes" ]] || [[ $line == "  ..."* ]] || [[ $line =~ "MST_DISABLED" ]]; then
    	if [[ $((sipstart)) != 0 ]]; then
			complete_sipmsg;
		fi
		continue
	fi

	if [[ $((insidesip)) == 0 ]] && [[ $((dirdefined)) != 0 ]]; then
#   if [[ $line == *"==> SIP In" ]] || [[ $line == *"<-- SIP Out" ]]; then

#        if [[ $((sipstart)) != 0 ]]; then
#    	    complete_sipmsg
#        fi

	    insidesip=1
		siptotalmsg=$((siptotalmsg+1))		
		get_sip_datetime
		sip_direction
#   fi
	elif [[ $((insidesip)) == 0 ]]; then
		continue

	elif [[ $((sipstart)) != 0 ]] && [[ $line =~ ^\#.* ]]; then
	    complete_sipmsg
	elif [[ $((insidesip)) == 1 ]] && [[ $((sipstart)) == 0 ]]; then
	    insidesip=2
	elif [[ $((insidesip)) == 2 ]] && [[ $line == *"From IPAddr:"* ]]; then
        insidesip=3
		localip1=$(awk '{print $3}' <<< "$line")
		localip2=$(awk '{print $6}' <<< "$line")
		proto=$(awk '{print $8}' <<< "$line")
		protocol=${proto:0:3}

    elif [[ $((insidesip)) == 3 ]] && [[ $line == *"To IPAddr:"* ]]; then
	    insidesip=4
		ip1=$(awk '{print $3}' <<< "$line")
#		ip2=$(echo $line | cut -d' ' -f6 | sed 's/CTRLVM//g')             # it appends ^M to the end of string
		ip2=$(awk '{printf "%i",$6}' <<< "$line")
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
		elif [[ $noINFO == 1 ]] && [[ $line =~ ^INFO ]]; then
			reset_sipmsg;
			continue
	  	else
			sipmsg_header
			start_sipmsg
		fi
	elif [[ $((sipstart)) == 1 ]]; then
        if [[ ${#line} -lt 2 ]]; then
		   emptyline=$((emptyline+1))
		   if [[ $((emptyline)) == 2 ]]; then
		      complete_sipmsg
           fi
		else
			if [[ $findANI != "" ]] && [[ $sipword =~ "INVITE" ]]; then
				if [[ $calltime == "" ]] && [[ $line =~ ^From:|^To: ]] && [[ $line =~ $findANI ]]; then
					calltime=$siptime
				elif [[ $calltime != "" ]] && [[ $callDIR == 0 ]] && [[ $line =~ ^Call-ID: ]]; then
					callID=$line; callDIR=$dirdefined
				fi
			fi

			if [[ $((base64decode)) != 0 ]] && [[ $line == "Base64 dump"* ]]; then
				base64found=1;	emptyline=0
				echo "# Base64 dump found" >> "$newfile"
				if [[ -f "$newfile.b64" ]]; then
					rm "$newfile.b64" 2>/dev/null
				fi
			elif [[ $((base64found)) != 0 ]]; then
				echo "$line" >> "$newfile.b64"
				emptyline=0
			else
				echo "$line" >> "$newfile"
				siplines=$((siplines+1))
				get_useragent
				emptyline=0
			fi
		fi
	fi
#   done <<< "$conv"
    done < "$file"
#	    fi

	if [[ $((sipstart)) != 0 ]]; then
		complete_sipmsg
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
		if [[ ${#endptaddr} == 0 ]]; then
			echo "==> $sipmsg out of $n/$rec SIP messages have been converted into $output.asm file"
		else
			if [[ $((sipmsg)) == 0 ]]; then 
				echo "==> no SIP messages were found for addr=$endptaddr in $bvar file"
			else
				echo "==> $sipmsg out of $n/$rec SIP messages (read $nlines lines)"
				echo "    have been converted for addr=$endptaddr into $output.asm file"
			fi
		fi

		if [[ $useragent != "" ]]; then
			server=""; server=$(egrep -m 1 "^Server:" "$newfile" 2>/dev/null)
			fullversion=$(egrep -m 1 "Full Release String:" < "$file" 2>/dev/null | awk -F"String:" '{print $2}' | awk '{print $1}')	# or | awk '{print $5}'
			if [[ $fullversion != "" ]] && [[ ! $fullversion =~ unknown ]]; then
				useragent="$useragent\t\t version: $fullversion"
			fi
			if [[ $foundipaddr != "" ]] && [[ $foundipaddr != "0.0.0.0" ]]; then
				if [[ ${#useragent} -lt 19 ]]; then
					echo -e "\n\tUser-Agent: $useragent\t\t ipaddr = $foundipaddr"
				elif [[ ${#useragent} -lt 27 ]]; then
					echo -e "\n\tUser-Agent: $useragent\t ipaddr = $foundipaddr"
				else
					echo -e "\n\tUser-Agent: $useragent   ipaddr = $foundipaddr"
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
			if [[ $((nINFO)) != 0 ]]; then
				echo -e "\tINFO messages ignored:\t\t\t\t $nINFO"
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

		if [[ $((error)) == 0 ]] && [[ $((n)) != 0 ]]; then
			echo '' >> "$newfile"
			if [[ $sipwordlist != "" ]]; then
				echo -e "# SIP requests found:\t$sipwordlist" >> "$newfile"
			fi
			converted=$((converted+1))
		else
			echo "Conversion of $file has ended with error code: $error n=$n sipwords=$sipwordlist"
		fi

		tmpsec=$((SECONDS-logsec))
		if [[ $((tmpsec)) != 0 ]]; then
			avgmsg=$(printf %.3f "$(($((n)) * 1000 / $tmpsec))e-3")
			echo -e "\n\tTask started:  $currtime  completed:  $(date +%R:%S)\t Total spent: $SECONDS sec  Avg. SIP msg/sec: $avgmsg\n"
		else
			echo -e "\n\tTask started:  $currtime  completed:  $(date +%R:%S)\t Avg. SIP msg/sec: N/A\t  Time spent: $SECONDS sec\n"
		fi
		currtime=$(date +%R:%S)

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
} # convert_MST()

function convert_siplog () {
if [[ $file != "" ]] && [ -s "$file" ]; then
	error=0; fsize=0; rec=0; rec2=0; basefile=""

	if [[ $file == *"/"* ]]; then 
		basefile=$(basename "$file")			
	else
		basefile=$file
	fi

	rec=$(egrep -c -e "^CSeq:*" "$file" 2>/dev/null)
	rec2=$(egrep -m 1 -c "==> SIP In|<-- SIP Out" "$file" 2>/dev/null)

	if [[ $rec == 0 ]] || [[ $rec2 == 0 ]];	then
		if [[ $((rec)) != 0 ]]; then
			asmfile=0; asmfile=$(egrep -m 1 -c "SIPMSGT" "$file" 2>/dev/null)		
			if [[ $((asmfile)) != 0 ]]; then
				asmfile=$(egrep -m 1 -c -e "(egress|ingress):\ \{" "$file" 2>/dev/null)
				if [[ $((asmfile)) != 0 ]]; then
					echo "It appears $basefile is a traceSM file (or a converted file using 3rd output format)."
					echo "This kind of input is not (yet) supported by this tool."
				fi
			fi
		fi
		rec=$(egrep -c -E "M[[:blank:]][[:digit:]]*[[:blank:]]8[ab]" "$file" 2>/dev/null)
		if [[ $(($rec)) == 0 ]]; then
			rec=$(egrep -c -e "\[MST\ " "$file" 2>/dev/null)
			if [[ $((rec)) == 0 ]]; then
				echo -e "\nerror: No SIP messages have been found in $bvar in the expected format."
#				echo "\tLooks like this file is neither a raw nor a decoded CM MST."
				echo -e "\nVerify source and content of $bvar.\n"
				error=1
			else
				if [ -f "$file.logmst" ]; then
					rm "$file.logmst" 2>/dev/null
				fi
				convert_logmst
				if [ -f "$file.logmst" ]; then
					file="$file.logmst"; tmpfile=1
					vsyslog=10
				else
					echo -e "\nerror: could not convert $file into raw MST format."
					echo -e "Verify source and content of $bvar.\n"
					error=1
				fi
			fi
		else
			vsyslog=10
#			if [[ $((voutput)) == 0 ]]; then
#				voutput=3
#			fi
		fi
	else
		vsyslog=1
	fi

	if [[ $((error)) != 0 ]]; then
		return
	elif [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
		voutput=3
	fi

	if [[ $((vsyslog)) != 0 ]]; then
		logsec=$SECONDS
		base64msg=0
		foundipaddr=""
		useragent=""
		nlines=0
		sipyear=$(cut -d'/' -f3 <<< "$today")
		sipmonth=$(cut -d'/' -f1 <<< "$today")
		sipday=$(cut -d'/' -f2 <<< "$today")
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
		nINFO=0
		CMversion=""
		CMpatch=""

		reset_sipmsg

		if [[ $((rec)) -gt 500 ]]; then 
			echo "Warning: about to convert a large file ($rec SIP messages), this may take a while... "
			echo -e "You may want to execute this script on a more powerful PC or server.\n"
		fi

		bakfile=""; output=""; 	bfile=""

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
				output="$var"
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

		echo "# This file had been created by SIPlog2traceSM v$version tool." > "$newfile"
		echo "# Script $0 was executed by $USER on $today at $currtime." >> "$newfile"
		echo "# Command line: $args" >> "$newfile"
		echo "# using BASH:$BASH_VERSION running $OSTYPE on $MACHTYPE." >> "$newfile"
		echo "# Host: $HOSTNAME   PWD=$PWD   vsyslog=$vsyslog" >> "$newfile"
		if [[ $tmpfile != 0 ]]; then
			echo -e "# Input/output file history: $var -> $file -> $var.asm" >> "$newfile"			
		else
			echo -e "# Input/output file history: $var -> $var.asm" >> "$newfile"
		fi

		if [[ $((vsyslog)) == 10 ]]; then
			mstcount=0			
			CMversion=$(egrep -m 1 "^H7" "$file" | awk '{print $2}')
			CMpatch=$(egrep -m 1 "^H6" "$file" | awk '{print $3,$4}')
			if [[ $CMversion != "" ]] && [[ $CMpatch != "" ]] && [[ ! $CMversion =~ unknwown ]]; then
				echo -e "# CM version: $CMversion\t\t$CMpatch\n" >> "$newfile"
			else
				echo '' >> "$newfile"
			fi
			mstcount=$(egrep -c "^H7" "$file")
			if [[ $((mstcount)) -gt 1 ]]; then
				echo "ALERT: $var appears to have multiple ($mstcount) MST sessions!"
			fi

			case $voutput in
			1) 	convert_rawMST1;;
			2)  convert_rawMST2;;
			3)  convert_rawMST3;;
			esac
			if [[ $CMversion != "" ]] && [[ $CMpatch != "" ]] && [[ ! $CMversion =~ unknown ]]; then
				echo -e "\nCM version: $CMversion\t\t$CMpatch"
			fi

		elif [[ $((vsyslog)) == 1 ]]; then			
			convert_MST
		else 
			error=9
			echo -e "\nerror: could not recognize format in input file: $file"
			echo "Verify source and content of $var."
		fi

		if [ -f "$output.asm" ]; then
			mv "$output.asm" "$output.asm.bak"
		fi
		mv "$newfile" "$output.asm"
		if [[ $bDelTemp != 0 ]] && [[ $tmpfile == 1 ]] && [[ $var != $file ]] && [ -f "$file" ]; then
		    rm "$file" 2>/dev/null							# this is already a tmp file, can be removed
		fi
		pwd; ls -l "$output.asm"			
		echo ''		
	fi
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
  while getopts ":e:hbdf:sN:AC" options; do
	case "${options}" in
	h)
		usage
		exit 0;;
	s)
		sipstat=0;;
	A)
		alllogs=1;;
	C)
		bCAT=1;;
	N)	
		findANI=${OPTARG}
		if [[ $findANI =~ [A-Za-z]+ ]]; then
			findANI=""
		fi;;
	b)
		base64decode=0;;
	d)
		bDelTemp=0;;
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

skipper=0; var=""

if [[ $((base64decode)) != 0 ]]; then
	base64 --help >/dev/null 2>&1
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
		elif [[ $var == "-N"* ]]; then
			skipper=3
		else
			skipper=0
		fi
		var="": continue

	elif [[ $skipper != 0 ]]; then
		if [[ $((skipper)) == 1 ]]; then	
			voutput="$var"
			if [[ $((voutput)) == 0 ]] || [[ $((voutput)) -gt 3 ]]; then
				voutput=3
			fi
		elif [[ $((skipper)) == 2 ]]; then
			endptaddr="$var"
		elif [[ $((skipper)) == 3 ]]; then
			findANI=$findANI		# findANI=$var
		fi	
		skipper=0; var=""
		continue
	fi
	
	n=0; 		error=0;	vsyslog=0
	bdir="";	bvar="";	folder=""
	target=""; 	destdir="";	input=""; input2=""
	file=""; 	filelist="";basefile=""
	currtime=$(date +%R:%S);currdir=$PWD	
	bSinglefile=0; tmpfile=0
	filetype2=""; filecontent="MST"
	
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
		target="MST"
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
	origtarget="$target"

	if [ -d "$var" ]; then
		echo -en "\nExploring content in \"$bvar\" folder ... stand by\r"
		cd "$var"; folder="$bvar"
		destdir="$PWD"
		explore_folders
		cd "$currdir"		

	elif [ -s "$var" ]; then
		echo -en "\nExploring content in $bvar... stand by\r"

		filetype1=$(file -b "$file")
		filetype2=$(file -bZ "$file")

		if [[ $filetype == "7-zip archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract 7-Zip archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "RAR archive"* ]]; then
			error=99
			echo -e "\nerror: unfortunately, this script is unable to extract RaR archives."
			echo -e "Suggesting to manually unzip $bvar file."

		elif [[ $filetype == "Zip archive"* ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
			else
				bfile=$(basename "$var")			
			fi
	
			if [[ $bUnzip != 0 ]]; then			
				if [[ $bvar == *"."* ]]; then
					input=${bvar%.*}
				else
					input="$bvar"
				fi
				if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
					rm -rf "$input.tmp" 2>/dev/null
					if [[ $? != 0 ]]; then						
						echo -e "error: could not delete temp folder: $input.tmp in $PWD."
						echo -e "Check if any subfolders or files are open (in other shell sessions).\n"
						error=7; cd "$currdir"; input=""; continue
					fi
				fi

				mkdir "$input.tmp" 2>/dev/null
				if [[ $? != 0 ]]; then					
					echo -e "\nerror: could not create $input.tmp folder in $PWD.\n"
					error=7; cd "$currdir"; input=""; continue
				fi

				cd "$input.tmp"			
				echo -e "\nUncompressing $var into $input.tmp ...                                                                          "			

				unzip -qq "../$var" 2>/dev/null
				if [[ $? != 0 ]]; then
					cd ..
					if [[ $input != "" ]] && [ -d "$input.tmp" ]; then
						rm -rf "$input.tmp"	2>/dev/null
					fi
					echo -e "\nerror: could not uncompress $var, using unzip."
					echo -e "Suggesting to validate \"unzip\" manually on \"$bfile\".\n"
					error=8; cd "$currdir"; input=""; continue
				else
					destdir="$PWD"; tmpfile=1
					folder="$input"
					explore_folders
				fi
				cd "$currdir"
			else
				echo -e "\nerror: could not uncompress $var, \"unzip\" utility not found."
				echo -e "Suggesting to deploy \"unzip\" package. in Ubuntu, you can install it by typing: \"sudo apt install unzip\".\n"
				error=8; continue
			fi

		elif [[ $filetype == *"compressed data"* ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				zfile="$file"
				bfile=$(basename "$file")
				filetype2=$(file -bZ "$file")
			else
				zfile="$var"
				bfile=$(basename "$var")
				filetype2=$(file -bZ "$var")
			fi

			if [[ $filetype =~ compressed ]] && [[ $filetype2 =~ ASCII|text|data ]]; then
				gunzip --version >/dev/null 2>&1
				if [[ $? == 0 ]]; then
					gunzip -q -c "$zfile" 2>/dev/null >"$zfile.txt"
					file="$zfile.txt"; tmpfile=1; bSinglefile=1	
					filelist=""; filecontent="ASCII"
#					filetype=$(file -b "$file")					
					filetype2=""; filetype=""
				else				
					echo -e "error: unable to uncompress $bvar, using \"gunzip\" utility.\n"
					error=8; exit $error
				fi

			elif [[ $filetype =~ compressed ]] && [[ $filetype2 =~ tar ]]; then
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
					echo "Uncompressing $zfile into $input2 ...                                                               "
					gunzip -q -c "$zfile" > "$input2" 2>/dev/null

					if [[ $? -le 1 ]]; then
						file="$input2"; tmpfile=2
						filetype=$(file -b "$file")
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

		if [[ $filetype =~ tar ]] || [[ $filetype2 =~ tar ]]; then
			if [[ $file != "" ]] && [[ $file != $var ]]; then
				bfile=$(basename "$file")
				zfile="$file"
			else
				bfile=$(basename "$var")
				zfile="$var"
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
						echo -e "\nerror: could not delete existing temp folder: $input.tmp"
						echo "Check if any subfolders or files are open (in other shell sessions).\n"
						error=7; cd "$currdir"; input=""; continue
					fi
				fi

				mkdir "$input.tmp"
				if [[ $? != 0 ]]; then
					echo -e "\nerror: could not create $input.tmp folder at $PWD.\n"
					error=7; cd "$currdir"; input=""; continue
				fi

				cd "$input.tmp"
				echo "Extracting $bfile ...                                                                          "

				if [[ $filetype =~ compressed ]] && [[ $filetype2 =~ tar ]]; then
					tar zxf "../$zfile" 2>/dev/null
				elif [[ $filetype =~ tar ]]; then
					tar xf "../$zfile" 2>/dev/null				
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
							else
								destdir="$PWD"; tmpfile=1
								folder="$input"
								explore_folders
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
			filelist=""; filecontent="ASCII"
			file="$var"; bSinglefile=1
		fi
		
	elif [[ $filetype =~ cannot|open ]]; then
		echo -e "\nerror: $bvar was not found or unable to open. Verify path and filename."
		error=3
	elif [[ $file == "" ]] && [[ $error == 0 ]]; then
		echo -e "\nerror: filetype of $bvar is not supported ($filetype)."
		error=4
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
			echo "Warning: about to convert multiple files ($nfiles x dsa.log*.txt)."
			echo "This may take a while... You may want to execute the script on a more powerful PC or server."

			let z=0; file=""
			for file in $filelist;
			do
				if [[ $file != "" ]] && [ -s "$file" ]; then
					IFS=$origIFS
					z=$(egrep -m 1 -c -e "CSeq:|\[MST\ " "$file")
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
#		file=$(awk '{print $1}' <<< "$filelist")		# head -1)
		file=${filelist%% *}
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