#!/bin/sh
#//::+------------------------------------------------------------------------------------------+
#//::| The RdPCIConfigLocal() command provides sideband read access to the PCI                  |
#//::| configuration space that resides within the processor. This includes all processor IIO   |
#//::| and uncore registers within the PCI configuration space as described in the              |
#//::| Intel?Xeon? Processor E5/E7 v3 Product Family External Design Specification (EDS),       |
#//::| Volume Two: Registers document.                                                          |
#//::|                                                                                          |
#//::| Usage:                                                                                   |
#//::|   RdPCIConfigLocal cpu bus dev fun reg name                                              |
#//::|                                                                                          |
#//::|   cpu - CPU index(0 ~ 8)                                                                 |
#//::|   bus - Bus number(0 or 1)                                                               |
#//::|   dev - Device number(0 ~ 31)                                                            |
#//::|   fun - Function number(0 ~ 7)                                                           |
#//::|   reg - Register offset(0 ~ 0xFFF)                                                       |
#//::|   name - Register name                                                                   |
#//::+------------------------------------------------------------------------------------------+
RdPCIConfigLocal()
{
    local cpu=$1
    local bus=$2
    local dev=$3
    local fun=$4
    local reg=$5
    local regName=$6
    local ouputFile=$7

    local client_address
    let "client_address = cpu+0x30" 
    local write_len="0x05";
    local read_len="0x05";
    local cmd_code="0xe1";
    local host_id="0x0";
    local PCA 
    let "PCA = (bus<<20)|(dev<<15)|(fun<<12)|(reg)"

    local pca0 
    let "pca0=(PCA)&0xff"
    local pca1 
    let "pca1=(PCA>>8)&0xff"
    local pca2 
    let "pca2=(PCA>>16)&0xff"
    local ipmicmd="$PECI_RAW_CMD_PRE $client_address $write_len $read_len $cmd_code $host_id $pca0 $pca1 $pca2"
    local outStrPre=`printf "(Bus:%-2s Dev:%-2s Fun:%-2s Reg:%-6s) CPU%s %-20s" "$bus" "$dev" "$fun" "$reg" "$cpu" "$regName"`
    #LOG_INFO "$outStrPre[$ipmicmd]"
    #echo "$outStrPre"
    sendMEIPMIWithRetry "$ipmicmd" "$ouputFile" "$outStrPre" 3
#    cmdline<<QString("%1").arg(client_address)
#            <<QString("%1").arg(write_len)
#            <<QString("%1").arg(read_len)
#            <<QString("%1").arg(cmd_code)
#            <<QString("%1").arg(host_id)
#            <<QString("%1").arg(pca0)
#            <<QString("%1").arg(pca1)
#            <<QString("%1").arg(pca2);

    #sendMEIPMIWithRetry
    return 0;
}

#//::+------------------------------------------------------------------------------------------+
#//::| The RdIAMSR() PECI command provides read access to the Machine Check Bank                |
#//::| Model Specific Registers (MSRs) defined in the processor’s Intel® Architecture (IA).     |
#//::| MSR definitions may be found in the Intel®Xeon® Processor E5/E7 v3 Product Family        |
#//::| External Design Specification (EDS), Volume Two: Registers.                              |
#//::|                                                                                          |
#//::| Usage:                                                                                   |
#//::|   RdIAMSR cpu processor reg name                                                         |
#//::|                                                                                          |
#//::|   cpu - CPU index(0 ~ 8)                                                                 |
#//::|   processor - processor ID                                                               |
#//::|   reg - Register offset(0 ~ 0xFFFF)                                                      |
#//::|   name - Register name                                                                   |
#//::+------------------------------------------------------------------------------------------+
RdIAMSR()
{
    local cpu=$1
    local processor=$2
    local reg=$3
    local regName=$4
    local ouputFile=$5
    local client_address
     let "client_address = cpu+0x30" 
    local write_len="0x05";
    local read_len="0x09";
    local cmd_code="0xb1";
    local host_id="0x0";
    local lsb
    let "lsb=(reg)&0xff"
    local msb
    let "msb=(reg>>8)&0xff"

 #   //::echo %PECI_RAW_CMD% %client_address% %write_len% %read_len% %cmd_code% %host_id% %processor% %lsb% %msb%
 #   //set /p=cpu%cpu% %name% <nul
 #   //%PECI_RAW_CMD% %client_address% %write_len% %read_len% %cmd_code% %host_id% %processor% %lsb% %msb%
    local ipmicmd="$PECI_RAW_CMD_PRE $client_address $write_len $read_len $cmd_code $host_id $processor $lsb $msb"
    local outStrPre=`printf "CPU%s_Proc%-2s %-20s" "$cpu" "$processor" "$regName"`
    #LOG_INFO "$outStrPre[$ipmicmd]"
    sendMEIPMIWithRetry "$ipmicmd" "$ouputFile" "$outStrPre" 3
    return 0;
}


PECI_INFO_MODE_CSR="0"
PECI_INFO_MODE_MSR="1"
CPU_PLATFORM_SKYLAKE="0"
#CPU_PLATFORM_IVB="1"
cpuPlatform=$CPU_PLATFORM_SKYLAKE
maxThreadID=12
blackboxpeci_log="/var/blackbox/blackboxpeci.log"
getMEPECIInfo()
{
    LOG_INFO "getMEPECIInfo cpuplatform:$cpuPlatform"
    if [ "$cpuPlatform" == "$CPU_PLATFORM_SKYLAKE" ] ; then
        echo "Parsed CPU Platform is SKYLAKE"
        getPECIInfoByMode "config/skl_csr.txt" "$bmcLogPath/skl_csr.txt" "$PECI_INFO_MODE_CSR"
        getPECIInfoByMode "config/skl_msr.txt" "$bmcLogPath/skl_msr.txt" "$PECI_INFO_MODE_MSR"
    #elif [ "$cpuPlatform" == "$CPU_PLATFORM_IVB" ] ; then 
    #    echo "Parsed CPU Platform is IVB"  
    #    getPECIInfoByMode "config/ivt_csr.txt" "$bmcLogPath/ivt_csr.txt" "$PECI_INFO_MODE_CSR"
    #    getPECIInfoByMode "config/ivt_msr.txt" "$bmcLogPath/ivt_msr.txt" "$PECI_INFO_MODE_MSR"    
    else
        echo "Invalid CPU Platform: $cpuPlatform"
        return -1;
    fi

    echo "$(cat $bmcLogPath/skl_csr.txt)" > $blackboxpeci_log
    echo "$(cat $bmcLogPath/skl_msr.txt)" >> $blackboxpeci_log

    return 0;
}


getPECIInfoByMode()
{
    local configFile=$1
    local outputFileName=$2
    local peciInfoMode=$3

    #echo "getPECIInfoByMode:$configFile $outputFileName $peciInfoMode maxThreadID:$maxThreadID"

    local socketIndex=0
    while [ $socketIndex -le 7 ]
    do
        cat "output/mespec_pingcpu${socketIndex}.txt" | grep "57 01 00" > /dev/null
        if [ $? -ne 0 ] ; then
            LOG_INFO "CPU$socketIndex cannot ping!"
            socketIndex=$(($socketIndex+1))
            continue
        fi

        cat "output/mespec_pingcpu${socketIndex}.txt" | grep "Unable" > /dev/null
        if [ $? -eq 0 ] ; then
            LOG_INFO "CPU$socketIndex cannot ping!"
            socketIndex=$(($socketIndex+1))
            continue
        fi

        cat "output/mespec_pingcpu${socketIndex}.txt" | grep "Unknown" > /dev/null
        if [ $? -eq 0 ] ; then
            LOG_INFO "CPU$socketIndex cannot ping!"
            socketIndex=$(($socketIndex+1))
            continue
        fi

        local line
        local lines=`cat $configFile | grep -v "#"`
        echo "$lines" | while read line
        do
            if [ "$line" == "" ]
            then
                continue
            fi

            echo $configFile | grep "csr" > /dev/null
            if [ $? -eq 0 ] ; then
                local bus=`echo "$line" | awk -F" " '{print $1}' |  sed 's/ //g'`
                local dev=`echo "$line" | awk -F" " '{print $2}' |  sed 's/ //g'`
                local fun=`echo "$line" | awk -F" " '{print $3}' |  sed 's/ //g'`
                local reg=`echo "$line" | awk -F" " '{print $4}' |  sed 's/ //g'`
                local name=`echo "$line" | awk -F" " '{print $5}' |  sed 's/ //g' | sed 's/[\r\n]//g' | sed 's/\n//g'`
              
                RdPCIConfigLocal $socketIndex $bus $dev $fun $reg $name $outputFileName 
            fi

            echo $configFile | grep "msr" > /dev/null
            if [ $? -eq 0 ] ; then
                local tmpMaxThreadId=1
                local reg=`echo "$line" | awk -F" " '{print $1}' |  sed 's/ //g' `
                local name=`echo "$line" | awk -F" " '{print $2}' |  sed 's/ //g' | sed 's/[\r\n]//g' | sed 's/\n//g'`
                #echo "test--$name--"
                #local corebased=`echo "$line" | awk -F" " '{print $3}' |  sed 's/ //g' | sed 's/[ \t]*$//g' `
                echo "$line" | grep "YES" > /dev/null 2>&1
                if [ $? -eq 0 ]; then
                    tmpMaxThreadId=$(($maxThreadID+1))
                else
                    tmpMaxThreadId=1
                fi

                local i=0
                tmpMaxThreadId=$(($tmpMaxThreadId-1))
		while [ $i -le $tmpMaxThreadId ]
                do
                    #echo "RdIAMSR $socketIndex $i $reg $outputFileName"
                    RdIAMSR $socketIndex $i $reg $name $outputFileName
		i=$(($i+1))
                done
            fi

        done
        socketIndex=$(($socketIndex+1))
    done

    return 0;
}


CheckMEIpmiActive()
{
    local retry=0;
    while [ $retry -le 4 ]
    do
        #${ipmitool} "-b 6 -t 0x2c raw 0x06 0x04" > /dev/null 2>&1
        #echo "${ipmitool} -b 6 -t 0x2c raw 0x06 0x04"
        ${ipmitool} -b 6 -t 0x2c raw 0x06 0x04 > /dev/null 2>&1
        if [ $? -eq 0 ] ; then
            MEChannel=6
            ME_RAW_CMD_PRE="${ipmitool} -b $MEChannel -t 0x2c "
            PECI_RAW_CMD_PRE="${ipmitool} -b $MEChannel -t 0x2c raw 0x2e 0x40 0x57 0x01 0x00 "
            return 0
        fi
        retry=$(($retry+1))
    done

    retry=0;
    while [ $retry -le 4 ]
    do
        #${ipmitool} "-b 0 -t 0x2c raw 0x06 0x04" > /dev/null 2>&1
        ${ipmitool} -b 0 -t 0x2c raw 0x06 0x04 > /dev/null 2>&1
        if [ $? -eq 0 ] ; then
            MEChannel=0
            ME_RAW_CMD_PRE="${ipmitool} -b $MEChannel -t 0x2c "
            PECI_RAW_CMD_PRE="${ipmitool} -b $MEChannel -t 0x2c raw 0x2e 0x40 0x57 0x01 0x00"
            return 0
        fi
        retry=$(($retry+1))
    done

    return 255;
}


getPECICommonInfo()
{
    local configFile=$1
    local lines=`cat $configFile 2>/dev/null | grep -v "#" `
    echo "$lines" | while read line
    do
        if [ "$line" == "" ]
        then
            continue
        fi

        local cmdStr=`echo "$line" | awk -F">" '{print $1}' |  sed 's/[ \t]*$//g' `
        local outputFile=`echo "$line" | awk -F">" '{print $2}' | awk -F"/" '{print $2}' | sed 's/[ \t]*$//g' `
        outputFile="output/$outputFile"
        sendIPMIWithRetry "${ME_RAW_CMD_PRE} $cmdStr" "$outputFile" 3
    done
    return 0;
}

sendIPMIWithRetry()
{
    local ipmicmd=$1
    local outputFile=$2
    local retry=$3
    local res=""
    local i=0
    local retCod=255
    if [ "$retry" == "" ] ; then
        let retry=3
    fi

    retry=$(($retry-1))
    while [ $i -le $retry ]
    do
        LOG_INFO "$ipmicmd > $outputFile 2>&1"
        $ipmicmd > $outputFile 2>&1
        if [ $? -eq 0 ] ; then 
            let retCod=0
            break;
        fi
	i=$(($i+1))
    done

    return $retCod
}

sendMEIPMIWithRetry()
{
    local ipmicmd=$1
    local outputFile=$2
    local outStrPre="$3"
    local retry=$4
    local res=""
    local i=0
    local cmd="${ipmitool} sel time get"
    local time=`$cmd`
    
    if [ "$retry" == "" ] ; then
        let retry=3
    fi

    #sleep 0.001

    retry=$(($retry-1))
    while [ $i -le $retry ]
    do
        res=`$ipmicmd`
        echo "$res" | grep "57 01 00 40" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break;
        fi
        echo "$res" | grep "57 01 00 90" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break;
        fi
        echo "$res" | grep "57 01 00 91" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break;
        fi
        echo "$res" | grep "57 01 00 92" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break;
        fi
        echo "$res" | grep "57 01 00 93" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break;
        fi
        echo "$res" | grep "57 01 00 94" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            break;
        fi
        LOG_INFO "$outStrPre[$ipmicmd] [$res]###Retry $i###"
        sleep 0.05
        #sleep 0.1
	i=$(($i+1))
    done

	res=`echo $res | sed 's/Data length = b//g'`
    LOG_INFO "$outStrPre[$ipmicmd]"
    #printf "%-40s %s\n" "$outStrPre" "$res"| tee -a "$outputFile"
    echo "$time $outStrPre  $res" >> "$outputFile"
    
}

PECI_GETCPUID_RES_FILE="mespec_cpuid.txt"
PECI_MAXTHREADID_RES_FILE="mespec_maxthreadid0.txt"
#PECI_CPUID_HASSWELL=0x000306f0
#PECI_CPUID_BROADWELL=0x000406f0
#PECI_CPUID_IVB=0x000306e0
PECI_CPUID_MASK=0x07ff1ff0


CheckCPUPlatForm()
{
    local filename="output/$PECI_GETCPUID_RES_FILE"

    local peciRes=`cat $filename | grep "57 01 00 40"`
    if [ "$peciRes" == "" ] ;then
        LOG_INFO "CPU Platform parse failed, set to default SKYLAKE!"
        cpuPlatform="$CPU_PLATFORM_SKYLAKE"
        return 0
    fi

    #local data0=`echo $peciRes | awk -F" " '{print $5}'`
    #local data1=`echo $peciRes | awk -F" " '{print $6}'`
    #local data2=`echo $peciRes | awk -F" " '{print $7}'`
    #local data3=`echo $peciRes | awk -F" " '{print $8}'`

    #local data="0x${data3}${data2}${data1}${data0}"
    #local cpuid
    #let "PECI_CPUID_HASSWELL=0x000306f0&$PECI_CPUID_MASK"
    #let "PECI_CPUID_BROADWELL=0x000406f0&PECI_CPUID_MASK"
    #let "PECI_CPUID_IVB=0x00030630&$PECI_CPUID_MASK"
    #let "cpuid=$data&$PECI_CPUID_MASK"
    
   # if [ $cpuid -eq $PECI_CPUID_HASSWELL ] ; then
   #     cpuPlatform="$CPU_PLATFORM_SKYLAKE"
    #elif [ $cpuid -eq $PECI_CPUID_BROADWELL ] ; then
    #    cpuPlatform="$CPU_PLATFORM_SKYLAKE"
    #elif [ $cpuid -eq $PECI_CPUID_IVB ] ; then
    #    cpuPlatform="$CPU_PLATFORM_IVB"
    #else
    #    cpuPlatform="$CPU_PLATFORM_SKYLAKE"
    #fi

	
    # Purley default SKYLAKE
    cpuPlatform="$CPU_PLATFORM_SKYLAKE"

    #echo "CheckCPUPlatForm:$cpuid==$PECI_CPUID_HASSWELL/$PECI_CPUID_BROADWELL/$PECI_CPUID_IVB? cpuPlatform:$cpuPlatform"
    LOG_INFO "CheckCPUPlatForm:$cpuPlatform"

}

CheckMaxThreadID()
{
    filename="output/$PECI_MAXTHREADID_RES_FILE"
    local peciRes=`cat $filename | grep "57 01 00 40"`
    if [ "$peciRes" == "" ] ;then
        LOG_INFO "Max ThreadID parse failed, set to default 12!"
        cpuPlatform="$CPU_PLATFORM_SKYLAKE"
        return 0
    fi

    local data0=`echo $peciRes | awk -F" " '{print $5}'`
    local data1=`echo $peciRes | awk -F" " '{print $6}'`
    local data2=`echo $peciRes | awk -F" " '{print $7}'`
    local data3=`echo $peciRes | awk -F" " '{print $8}'`

    local data="0x${data3}${data2}${data1}${data0}"
    maxThreadID=$data

    if [ $maxThreadID -gt 255 ] ; then
        LOG_INFO "Max ThreadID parse invalid $maxThreadID, set to default 12!"
        maxThreadID=12
    fi

    LOG_INFO "CheckMaxThreadID raw:$data; maxThreadID:$maxThreadID"
}


getpecilog()
{
    CheckMEIpmiActive
    if [ $? -ne 0 ] ; then
        echo "Try to access ME failed!!!!"
        return 255
    fi

    getPECICommonInfo "config/cmd.list"
    CheckCPUPlatForm
    CheckMaxThreadID
    getMEPECIInfo
}


bmcLogPath="output/logs"


run_cmd "mkdir -p $bmcLogPath"


isBMCActive()
{
    local i=0
    while [ $i -le 2 ]
    do
        #echo "=====++${ipmitool} mc info++"
        ${ipmitool} mc info 2>/dev/null |grep "Provides Device SDRs " >/dev/null 2>&1
        if [ $? = 0 ] ;then 
            LOG_INFO  "BMC is Active, with ip:$bmcip, user:$bmcuser, pass:$bmcpassword." 
            #sleep 1
            return 0
        else
            LOG_INFO  "BMC is not Active , with ip:$bmcip, user:$bmcuser, pass:$bmcpassword... " 
            sleep 1
        fi
	i=$(($i+1))
    done
    
    LOG_INFO "BMC not response, please check ip $bmcip, user:$bmcuser, pass:$bmcpassword!!!!"
    return 1
}

##################
# input 1: ip
##################
isPingActive()
{
    local ip=$1
    ping "$ip" -c 3 > /dev/null 2>&1 
    if [ $? = 1 ] ; then
        #echo "ping "$ip" not access!!"
        return 1
    fi
    #echo "ping "$ip" access OK!!"
    return 0
}
