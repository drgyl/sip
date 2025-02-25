SIPlog2traceSM is a tool to collect and convert SIP messages from logfiles created by Avaya products, into format required by 'traceSM'.  This tool was developed by Laszlo Gyalog.

SIPlog2traceSM is a set of simple BASH shell scripts which collect and convert SIP messages found in the logfiles of most Avaya products into a format that is accepted by 'traceSM' tool of Avaya Session Manager server. 

List of Avaya products where script is currently implemented: 
Endpoints + softclients: 11xxSIP/12xxSIP, 96x1SIP, J1xxSIP, H175, K1xx, Konftel IPDECT10 (new), B169, B179, B199, Konftel 800 and 300IP (new), VDI-C/Workplace for VDI, AAfD, 1xAgent (new), CU360/XT, Workplace clients, Workplace Attendant, or any ClientSDK based applications
Servers: AS5300 (new), ASBCE, ASM, IP Office, Experience Portal, Breeze, ADA, AAWG, AAM, AAC, 1XCES, CIE, IX Meetings (iVIEW + MCU), MX, AAMS, CM, MEGA, SES
Non-Avaya products: ACME SBC (new), Ringcentral/ACO, Phoner/PhonerLite, BRIA, SIPP

Latest version of SIPlog2traceSM is available at
http://info.dr.avaya.com/~lgyalog/SIPlog2traceSM.tgz or at http://toolsa.sd.avaya.com/~lgyalog/SIPlog2traceSM.tgz
Individual script files can be downloaded using http://info.dr.avaya.com/~lgyalog/SIPlog2traceSM/traceXXXX.sh files.

These scripts can be run on any Linux servers, or Linux-like environment running on Windows (eg. Cygwin, WSL2, etc). If a problem is found related to executing in a specific Linux environment, contact developer with description of the issue.  The scripts utilize several basic Linux commands, such as 'cut', 'awk', 'sed', 'tr', 'egrep', 'tail', 'tar' and 'wl'.
Fir certain scripts, non-standard utilities are required to be present and available such as 'tshark', 'unzip' or 'openssl'.

The scripts accept either an individual logfile or folder (new) as input, or in most cases even a logreport (eg. phone report, debugreport, CS/log package
etc) can be provided in which case decryption, decompression is automatically performed and conversion takes either the most recent logfile or all of the
lgofiles (new) found in the package or in the folder (new).

Certain products can send SIP messages to remote SYSLOG servers. The script can recognize if the input file is a native logfile, or if the content would be rather SYSLOG.

There are many 3rd party SYSLOG servers available, which all store the syslog lines in different format. Current SIPlog2traceSM implemented either only a single or just a few more SYSLOG formats, eg KIWI/Solarwinds, MEGA, Interactive, tftpd64). (Supporting additional SYSLOG servers can be implemented per demand.)

If syslog sent by the product is captured by a network monitoring tool (eg. 'tcpdump' or 'Wireshark'), than syslog can be extracted either manually (using "Follow UDP stream" feature of Wireshark), or if 'tshark' utility is available, the "pcap" file can be provided as input and the script will extract the syslog content from the packet capture and then explore and convert the included SIP messages.

Note: due to product defect, network or remote syslog server issues, some SIP messages may not be logged completely, or can be delivered/get saved out of order.

Some syslog collector tools may export/save the collected data in reverse chronologial order (eg. Interactive Syslog application).

The output file has the ".asm" extension, located in the same folder where the script was launched from.

This ".asm" file is a text file that can be read and processed by traceSM tool - recommend to use min. v3.29 or above version of traceSM.

A new optional parameter '-C' will concatenate each '.asm" files into a single ".casm" file in the sequence order of execution during the conversion of the explored
logfiles.  This helps analyze the final SIP message flow in the correct order ('traceSM' does not sort the provided input files into chronological order).

Refer to usage screen for detailed information on how to use the script (-h will display usage information). 

Note: SIPMESSAGES.txt of One-X Communicator, 1XC for Mac, Communicator for Microsoft Lync, one-X SIPIOS and Workplace for iOS, require no conversion: traceSM v3.29 or later can natively process those files. 

Note: since 'traceSM' script runs Avaya Session Manager servers, it would be natural to upload these scripts to an ASM lab server and execute the conversion over there.  In
such case, due to the Linux security tightening of ASM server does not allow execution via "./traceXXX.sh".  Workaround is the execute via "bash traceXXX.sh".

Usually the logfiles of endpoints/softclients do not append the client's IP addresses to the SIP messages, therefore in such case the endpoints are being referred as "1.1.1.1:1111" by 'traceSM'.

Session Manager r8.x allows to collect SIPtrace or send SIP messages via syslog. In order to view such data (or SIP logs from ASM r6.2 or earlier release) by traceSM, the "traceASM.sh" script can be utilized to convert this log into traceSM format. 

H175's EndpointLog_B+sig+CPS.txt can be decoded either by using 'traceVDIC.sh' or 'trace96x1.sh' scripts.

AS5300 server log is accepted by 'traceAAC.sh' script.

one-X Agent SIP client's logfile can be converted either by 'trace96x1.sh' or 'traceVDIC.sh' scripts.

Konftel IPDECT10 is supported by 'traceB169.sh", Konftel 800 is supported by 'traceB199.sh' and Konftel 300IP is supported by 'traceB179.sh' script.

Extensive testing on each script has been performed, but flawless operation is not guaranteed for all kind of log inputs and/or combination of SIP product versions and Linux environments.

If you find a product which is not covered by the existing set of scripts, or using a remote SYSLOG server which is not recognized by the script, or if the conversion fails, or 'traceSM' unable to open the converted file, or 'traceSM' presents ERROR for any messages, contact developer by sharing few important details such as
(1) reference to the product, including its software version
(2) copy of the script in trouble
(3) copy of the input logfile and output files, and 
(4) details on the OS environment where the script run


Some examples for script execution:

$./traceWP.sh WP/UccLog.*
This creates UccLog.*.asm files which contains all the SIP messages from all UccLog.* found in 'WP' directory

In R2, it would be a better way to execute this using "$./traceWP.sh -A WP" instead.
This will explore all Workplace related logfiles in 'WP' folder and start executing conversion in chronological order of meessages.

$./traceWP.sh -k 123456 "Logs 2022-09-20 16-47-20-527.zip"
This decodes the encrypted log report from Workplace for Windows client, and converts the most recent logfile (UccLog.log) - output will be "Logs
2022-09-20 16-47-20-527.asm". If there is a need to convert all available UccLog* files, execute traceWP.sh again via either '-A' or '-AC' options.

$./traceWP.sh FA-RELEASE73-BUILD.15_20220809_FlareAndroid_logs.zip
This decompresses the .zip file using 'unzip' command, and converts "logs_app.log" into "FA-RELEASE73-BUILD.15_20220809_FlareAndroid_logs.asm".

$./traceVDIC.sh Transfer-scenario1.pcap
This will check using 'tshark' if the input file contains any syslog packets and then it will convert all SIP messages into 'Transfer-scenario1.pcap.asm'

$./traceAAFD.sh -ACI -N 3612388318 AvayaAgentLogs.zip
This will decompress "LogsFromDefaultDir.zip" (if found any) from "AvayaAgentLogs.zip", and converts all of SIPMessages*.txt into "AvayaAgentLogs-SIPMessagesX.asm". Furthermore, 'C' will concatenate all converted '.asm' files (in chronological order) into 'AvayaAgentsLog.casm', as well as report screen of each '.asm' conversion will present timestamp and Call-ID of the first call where 'From' or 'To:" header was matching to the number specified via the '-N' parameter. The '-I' parameter will drop all SIP INFO messages (which could be quite many in a shared control scenario).

$./traceCM.sh hold-fail.mm
This will create hold-fail.mm.asm file which includes all SIP messages from the decoded MST trace.
Note: "traceCM" tool already exist on toolsa servers which can accept raw MST files. Requires Perl and X-Windows setup.

$./traceK1xx.sh -k Avaya123 debugreport-K175-20WZ3450032E-2022-06-22T17-09.tar.gz
This will decrypt and decompress the debugreport (either for Vantage R3.x or R2.0 andr earlier), providing the 'openssl' command is available, and then converts the latest "vantage.log' file into 'debugreport-K175-20WZ3450032E-2022-06-22T17-09.asm'.

$./traceASM.sh TraceViewerExport_Details.txt
This will convert the SIPtrace captured and extracted from SMGR->Session Manager->System Tools->SIP Traces Viewer.

$./traceASM.sh -s 10.172.67.59 -a 10.200.17.83 SyslogCatchAll.txt
This will collect all SIP messages sent by ASM server at 10.172.67.59 addressed to/from client or server at 10.200.17.83, gathered by KIWI/Solarwinds remote SYSLOG server

$./trace96x1.sh 8811149_64c3549e5334_report.tgz
This will convert either the EndpointLog.txt or avaya-phone.log from the phonereport file. With '-A' option, it will explore all "avaya_phone.log.[1-7].gz" files as well.

$./trace96x1.sh -A path/Avaya (or path/Avaya Endpoint)
This will convert all of the EndpointLog*.txt files from SparkEmulator's or J100 emulator's log folder.

Sample of the the execution and its result presented:

$ ../traceWP.sh -N 6103 EqA/logs_app.log

Exploring content in logs_app.log ... stand by
==> 49 out of 49/49 SIP messages have been converted into EqA/logs_app.log.asm file

        User-Agent: Avaya Aura Communicator Android/2.0.0 (FA-GRIZZLYINT-JOB1.218; Nexus 7)
        Server: AVAYA-SM-6.3.1.0.631004
        Total # of lines digested:                       979
        Total # of SIP messages processed (RX/TX):       49 (24/25)
        Longest SIP message had:                         45 lines at msg# 39 (RX INVITE)
        First msg: REGISTER   10/02/2013 18:36:00:358    Last msg: ACK   10/02/2013 18:39:10:881
        Incoming call from 6103 at 18:39:05:492  	 Call-ID: 0e2dd69c940e31d84c5245866d00

        Task started: 18:55:32 - completed: 18:56:07     Avg. SIP msg/sec: 1.44  Time spent: 36 sec

/home/work/Workplace
-rw-r--r-- 1 user None 49790 Oct 11 18:56 logs_app.log.asm


