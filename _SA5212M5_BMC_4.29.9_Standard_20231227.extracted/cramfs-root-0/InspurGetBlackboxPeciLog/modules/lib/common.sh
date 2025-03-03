#!/bin/sh
if [  ! -z "$common" ];then
    return
fi
common="common.sh"

blackboxpeci_log_all="/var/blackbox/blackboxpeci.tar.gz"
blackboxpeci_log="/var/blackbox/blackboxpeci.log"

################################################################
#Function:		<Compression_dir>
#Description:	Compression directory
#Parameter:	$1 : dir to compress
#Return:	N/a
#Since:		
#Other:		N/a				
###################################################################
compression_dir()
{   
    local file_num=""
    local inputdir="$1"
    local Fbasename=$(basename "$inputdir")
    local compress_file="${Fbasename}.tar.gz"
    local Log_size=""
    printf "\r%-65.65s\n" "==[ DONE ]============================================================================================="
	
    run_cmd "chmod 400 -R ${inputdir}"
    run_cmd "tar -czf ${compress_file} ${inputdir}"
    if [ 0 -eq $? ]
    then
        #run_cmd "rm -rf ${inputdir}"
        run_cmd "chmod 400 ${compress_file}"
        #md5sum "${compress_file}" > "${Fbasename}.md5"
        if [ $? -ne 0 ]; then
            #echo -e "\033[31mcompressed file fail, please manual compression" | tee -a "${OUTPUTLOG}/system/${OUTPUTRUNLOG}\033[0m"
            echo -e "\033[31mcompressed file fail, please manual compression\033[0m"
        else
            #run_cmd "chmod 400 ${Fbasename}.md5"
            file_size=$(du -sh "${compress_file}"  | awk '{print $1}')
            file_path=$(readlink -f "$compress_file")

            run_cmd "mv ${compress_file} $blackboxpeci_log_all"

            echo -e "\033[32mAll File Path: ${blackboxpeci_log_all} \033[0m"
            echo -e "\033[32mAll File size: ${file_size} \033[0m"
            echo -e "\033[32mBlackboxpeci Log File Path: ${blackboxpeci_log} \033[0m"
            #echo -e "\033[32mFile md5sum: $(cat ${Fbasename}.md5 | cut -d ' ' -f 1) \033[0m"
        fi
        #file_num=$(ls -A1 /var/crash/ 2>/dev/null | wc -l)
        #if [ "${file_num}" -gt 0 ]; then
         #   echo -e "\033[31mPlease collect crash files[/var/crash] manually.\033[0m"
        #fi

    else
        echo -e "\033[31mCompress $inputdir failed. Please compress manually.\033[0m"
        LOG_ERROR "Compress $inputdir failed. Please compress manually."
    fi
    printf "%-65.65s\n" "================================================================================================="
}

################################################################
#Function:		<check_auth>
#Description:	check auth id is 0
#Parameter:	N/a	
#Return:	exit 1 if not  id0 user
#Since:		
#Other:		N/a				
###################################################################
check_auth()
{
    local login_id=$(id -u $(whoami))
    if [ "${login_id}" -ne 0 ]; then
        echo  "Current user id is ${login_id}.Recommendation to use ID:0 user to collect logs."
        LOG_ERROR "Current user id is ${login_id}.Recommendation to use ID:0 user to collect logs."
    else 
        LOG_INFO "User ID is:$(id $(whoami))"
    fi 
}

################################################################
#Function:		<run_cmd>
#Description:	exec cmd 
#Parameter:	$1��cmd to be run  $2: Variable parameter��out put the result to file�� 
#Return:	errocode  0:ok
#Since:		
#Other:		N/a				
###################################################################
run_cmd()
{
   local ret=1
   local cmd="$1"
   local output="$2"
   local result=""
   local retCode=""

    if [ "" == "$cmd" ] || [ 2 -lt $# ] 
    then
        LOG_ERROR "Invalid parameters."
        ret=1
        return $ret 
    fi
	
	LOG_INFO "[$cmd] is called."
        local cmdshow=$(echo $cmd | awk -F">" '{print $1}' | sed 's/^\s*\|\s*$//g')
        
                if [ "" != "$output" ]      
	then
	   echo "${cmdshow}" >> "$output"  
	   echo "{" >> "$output"            
	fi

	result=$(eval "${cmd}" 2>&1)          
	retCode=$?
	if [ 0 -ne $retCode  ]
	then
	   ret=$retCode
	   LOG_ERROR "[$cmd] failed.Ret:$retCode. Desc:$result"
	else 
	   ret=0
	   LOG_INFO "[$cmd] successfull."
	fi 

	if [ "" != "$output" ]      
	then
                    echo "$result" >> "$output"
	    echo "}" >> "$output"
	fi

    return $ret

}

cmdisfunc()
{
    local cmd="$1"
	local flist=$(grep '^function' funclib.sh | awk '{print $2}' | sed -e 's/[( )]//g')
	
	for i in $flist
	do
	    if [ "$cmd" == "$i" ]
		then
		    return 0
        fi
	done
	return 1
}

#INFO_COLLECT_USED_TO_DISPLAY="yes"
module_log_collect()
{ 
    #local file=""
    local cmd=""
    local cmdshow=""
    #local cmdType=""
    #local lineNum=""
    local result="SUCCEED"
    #local line=""
    local modname="$1"
    LOG_INFO "${moduleName} collect start." 
    mkdir -p output
    printf "\r\033[K Collect %.60s" "[${moduleName}] information..." 
    #lineNumber=`cat config.ini 2>/dev/null | grep -v '#' | grep '|' | wc -l`
    groupid=`cat ../../config.ini | grep -v -E "^#" |grep "|" | grep "yes"| grep "module=$modname" | awk -F"|" '{print $2}' | awk -F"=" '{print $2}' `
    groupid="base ""$groupid"

    local  usedToDisplayFlag=""
    local INFO_COLLECT_USED_TO_DISPLAY_FILE="../../../infoUsedDisplayFlag.txt"
    if [ -f "$INFO_COLLECT_USED_TO_DISPLAY_FILE" ] ; then
        #echo "test==77777INFO_COLLECT_USED_TO_DISPLAY_FILE===="
        usedToDisplayFlag="yes"
    fi
    #echo "Test1=========="
    #echo "$groupid"
    #echo "Test2=========="
    for id in $groupid
    do
        con=`cat cmd.list | grep -v -E "^#" | grep "|" |grep -E "^\s*$id"`
        #echo "$con"
        ##start collect
        LOG_INFO  "group [${id}] collect start." 
        #printf "\r%.75s" "                                                   "
        printf "\r\033[K Collect [${id}] ...... please wait"
        echo "$con" | while read line
        do
            cmd=$(echo $line | awk -F"|" '{print $2}'| awk -F"#" '{print $1}'| sed 's/^\s*\|\s*$//g')
            cmdshow=$(echo $cmd | awk -F">" '{print $1}' | sed 's/^\s*\|\s*$//g')
            if [ "$usedToDisplayFlag" = "yes" ] ; then
                cmdInfoDisplayMode=$(echo $line | awk -F"|" '{print $3}' | sed 's/ //g')
                #echo "test=cmdInfoDisplayMode:$cmdInfoDisplayMode===="
                if [ "$cmdInfoDisplayMode" != "yes" ] ;then
                    continue
                fi
            fi
            #avoid cmd too long
            if [ ${#cmdshow} -gt 40 ]
            then
                cmdshow=${cmdshow:0:40}" ..."
            fi
            outfile=$(echo $line | awk -F"|" '{print $2}'| awk -F"#" '{print $2}'| sed 's/^\s*\|\s*$//g')
            needw=$(echo "$outfile"| grep -c -E '^writehead:')
            if [ $needw -eq 0 ]
            then
                outfile=""
            else
                outfile=$(echo "$outfile" | awk -F':' '{print $2}'|sed 's/^\s*\|\s*$//g')
            fi
            
            if [ "$cmd" == "" ]
            then
                continue
            fi 
            LOG_INFO  "[${cmd}] excute start." 
            #printf "\r%.75s" "                                                   "
            printf "\r\033[K Excute [${cmdshow}] ...... please wait"
            #echo $cmd
                        #echo "test===$ipmitool==$cmd======"
            #$ipmitool -b 0x06 -t 0x2c raw 0x06 0x01
            cmdisfunc "$cmd"

            if [ "0" == "$?" ]
            then
                 $cmd
            else
                    #             echo "$cmd"
                 run_cmd "$cmd" "$outfile"
                 
                 if [ "0" == "$?" ]
                 then
                     LOG_INFO "$cmd excute ok."
                     result="SUCCEED"
            else
                     LOG_INFO "$cmd excute failed."
                     result="FAILED"
                 fi
            fi
        done

        printf "\r\033[K Collect group [${id}] ...... Done        "
        done

    printf "\r\033[K %.60s" "[${modname}]...                                                                            "
    printf "%s\n" "Done"
    LOG_INFO "${modname} collect finished." 
    return
}

