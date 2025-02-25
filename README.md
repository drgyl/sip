# Introduction

SIPlog2traceSM is a tool to collect and convert SIP messages from logfiles created by Avaya products, into format required by traceSM

SIPlog2traceSM is a set of simple BASH scripts which collect and convert SIP messages from logfiles of most Avaya products into a format that is accepted by traceSM tool. Tool was developed by Laszlo Gyalog in 2022-2024. 

List of Avaya products where script is currently implemented: 
Endpoints + softclients: 11xxSIP/12xxSIP, 96x1SIP, J1xxSIP, H175, K1xx, B169, B179, B199, VDI-C/Workplace for VDI, AAfD, CU360/XT, Workplace clients, Workplace Attendant, or any ClientSDK based applications
Servers: ASBCE, ASM, IP Office, Experience Portal, Breeze, ADA, AAWG, AAM, AAC, 1XCES, CIE, IX Meetings (iVIEW + MCU), MX, AAMS, CM, MEGA, SES
Non-Avaya products: Ringcentral/ACO, Phoner/PhonerLite, BRIA, SIPP

# Download

Latest version of SIPlog2traceSM is available at https://github.com/drgyl/sip/

These scripts can be run on any Linux servers, or Linux-like environment running on Windows (eg. Cygwin, WSL2, etc).

The scripts utilize several basic Linux commands, such as 'cut', 'awk', 'sed', 'tr', 'egrep', 'tail', 'tar' and 'wl'.

In specific cases, non-standard utilities are required to be present and available such as 'tshark', 'unzip' or 'openssl'.

The scripts accept either an individual logfile as input, or in most cases even a logreport (eg. phone report, debugreport, CS/log package etc) can be provided in which case decryption, decompression is automatically performed and conversion takes the most recent logfile found in the package.

Certain products can send SIP messages to remote SYSLOG servers. The script can recognize if the input file is a native logfile, or if the content would be rather SYSLOG.

There are many 3rd party SYSLOG servers available, which all store the syslog lines in different format. Current SIPlog2traceSM implemented either only a single or just a few more SYSLOG formats, eg KIWI/Solarwinds, MEGA, Interactive, tftpd64). (Supporting additional SYSLOG servers can be implemented per demand.)

If syslog sent by the product is captured by a network monitoring tool (eg. 'tcpdump' or 'Wireshark'), than syslog can be extracted either manually (using "Follow UDP stream" feature of Wireshark), or if 'tshark' utility is available, the "pcap" file can be provided as input and the script will extract the syslog content from the packet capture and then explore and convert the included SIP messages.

Note: due to product defect, network or remote syslog server issues, some SIP messages may not be logged completely, or can be delivered/get saved out of order.

Some syslog collector tool may export/save the collected data in reverse chronologial order (eg. Interactive Syslog application)

The output file has the ".asm" extension, located in the same folder where the script was launched from.

This ".asm" file is a text file that can be read and processed by traceSM tool - recommend to use min. v3.29 or above version of traceSM.

Refer to usage screen for detailed information on how to use the script (-h will display usage information). 

Note: SIPMESSAGES.txt of One-X Communicator, Communicator for Microsoft Lync, one-X SIPIOS and Workplace for iOS, require no conversion: traceSM v3.29 or later can natively process those files. 

For endpoints/clients, the logfiles usually do not append the client's IP addresses to the SIP messages, therefore in traceSM, in such case the endpoints are being referred as "1.1.1.1:1111"

Session Manager r8.x allows to collect SIPtrace or send SIP messages via syslog. In order to view such data (or SIP logs from ASM r6.2 or earlier release) by traceSM, use the "traceASM.sh" script to convert into traceSM format. 

H175's EndpointLog_B+sig+CPS.txt can be decoded either by using traceVDIC.sh or trace96x1.sh scripts. Testing on each script has been performed, but flawless operation is not guaranteed for all log inputs.

# Report a problem

Extensive testing on each script has been performed, but flawless operation is not guaranteed for all kind of log inputs and/or combination of SIP product versions and Linux environments.

If you find a product which is not covered by the existing set of scripts, or using a remote SYSLOG server which is not covered by the script, or the conversion fails, or traceSM unable to open the converted file, or traceSM presents ERROR for any messages, contact the author, by sharing few details such as 
(1) reference to the product including its software version
(2) copy of the script in trouble
(3) copy of the input and output files, and 
(4) details on the OS environment where the script run

# Example scenario

Some examples for script execution:

$./traceWP.sh UccLog.*
This creates UccLog.*.asm files which contains all the SIP messages from all UccLog.* found in current directory

$./traceWP.sh -k 123456 "Logs 2022-09-20 16-47-20-527.zip"
This decodes the encrypted log report from Workplace for Windows client, and converts UccLog.log file - output will be "Logs 2022-09-20 16-47-20-527.asm". If there is need to convert additional UccLog files, go into "Logs 2022-09-20 16-47-20-527.tmp" folder and execute traceWP.sh again (eg. traceWP.sh UccLog.log.2022-08-30*)

$./traceWP.sh FA-RELEASE73-BUILD.15_20220809_FlareAndroid_logs.zip
This decompresses the .zip file using 'unzip' command, and converts "logs_app.log" into "FA-RELEASE73-BUILD.15_20220809_FlareAndroid_logs.asm"

$./traceVDIC.sh Transfer-scenario1.pcap
This will check using 'tshark' if the input file contains any syslog and will convert all SIP messages into 'Transfer-scenario1.pcap.asm'

$./traceAAFD.sh -A AvayaAgentLogs.zip
This will decompress "LogsFromDefaultDir.zip" from "AvayaAgentLogs.zip", and converts all of SIPMessages*.txt into "AvayaAgentLogs-SIPMessagesX.asm"

$./traceCM.sh hold-fail.mm
This will create hold-fail.mm.asm file which includes all SIP messages from the decoded MST trace.
Note: "traceCM" tool already exist on toolsa servers which can accept raw MST files. Requires Perl and X-Windows setup.

$./traceK1xx.sh -k Avaya123 debugreport-K175-20WZ3450032E-2022-06-22T17-09.tar.gz
This will decrypt and decompress the debugreport (either for Vantage R3.x or R2.0 andr earlier), providing 'openssl' command is available, and then converts the latest "vantage.log' file into 'debugreport.tar.asm'

$./traceASM TraceViewerExport_Details.txt
This will convert the SIPtrace captured and extracted from SMGR->Session Manager->System Tools->SIP Traces Viewer.

$./traceASM -s 10.172.67.59 -a 10.200.17.83 SyslogCatchAll.txt
This will collect all SIP messages sent by ASM server at 10.172.67.59 addressed to/from client or server at 10.200.17.83, gathered by KIWI/Solarwinds remote SYSLOG server

$./trace96x1.sh 8811149_64c3549e5334_report.tgz
This will convert either the EndpointLog.txt or avaya-phone.log from the phonereport file.

$./trace96x1.sh -A AvayaEndpoint.zip
This will convert all of the EndpointLog.txt files from SparkEmulator's log folder.
