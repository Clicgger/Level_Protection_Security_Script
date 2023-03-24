#! /bin/bash
## By: Clicgger

# 需要填写的变量
# 指定有挂载ISO镜像的FTP服务器
# 请确保ftp服务器的防火墙selinux已经关闭,否则会导致连接不上ftp服务器
FTPIP=""
## 日志采集服务器IP端口,@是udp,@@是tcp
RSSERVER="@IP:PORT"
# 主机IP
HOST_IP=`hostname -I|cut -f1 -d" "`
# 系统内核版本
OSVERSION=`uname -r`
# 当前用户
NUSER=`who|head -n 1|cut -f1 -d ' '`
# 规则
PASSPOLICY="password    requisite     pam_cracklib.so retry=5 difok=3 minlen=10 lcredit=-1 dcredit=-1 ucredit=-1 ocredit=-1"
ACOTPOLICY="auth        required   	  pam_tally2.so even_deny_root deny=5 unlock_time=300"
ACOTPOLICY8="auth    requisite       pam_faillock.so preauth even_deny_root deny=5 unlock_time=300"
ACOTPOLICY81="auth    [default=die]   pam_faillock.so authfail even_deny_root deny=5 unlock_time=300"
ACOTPOLICY82="auth    sufficient      pam_faillock.so authsucc even_deny_root deny=5 unlock_time=300"
## 获取HISTSIZE行号,准备在其下一行添加TMOUT
HLN=`grep -n "HISTSIZE=" /etc/profile |cut -f1 -d:`
HLN=$(($HLN+1))
## 用户列表
USERLIST="/BCF/UserList.txt"
## 备份文件列表,有添加就另起一行,不要逗号
DIRECTORYLIST=(
    "/etc/pam.d/system-auth"
    "/etc/pam.d/password-auth"
    "/etc/profile"
    "/etc/ssh/sshd_config"
    "/etc/logrotate.conf"
    "/etc/sysctl.conf"
    "/etc/rsyslog.conf"
    "/etc/pam.d/su"
    "/etc/firewalld/firewalld.conf"
    "/etc/aliases"
    "/etc/login.defs"
)


## 备份文件
function BACKUP_PROFILE(){
    ## 创建备份配置文件夹
    ## 临时如此输出,应该要做一个输出模块,返回查询结果
    echo -e "\033[32m----------------------------------------\033[0m"
    echo -e "\033[32m       >>>[[[START BACKUP]]]<<<\033[0m"
    echo -e "\033[32m----------------------------------------\033[0m"
    if [ ! -d "/BCF" ]; then
        echo -e "\033[32mBACKUP DRECTORY NOT EXIST,CREATED TO /BCF  \033[0m"
        mkdir /BCF
    else
        echo -e "\033[33m /BCF IS EXIST! \033[0m"
    fi

    ## 备份配置文件
    for DS in ${DIRECTORYLIST[@]}
    do
        FILENAME=`basename $DS`
        if [ -e $DS ]; then
            if [ -e /BCF/$FILENAME ]; then
                echo -e "\033[33m$FILENAME ALREADY BACKUP! \033[0m"
            else
                cp $DS /BCF/
                echo -e "\033[32m$FILENAME BACKUP SUCCESS! \033[0m"
            fi
        else
            echo -e "\033[31m$DS NOT EXIST! PLEASE CHECK! \033[0m"
        fi
    done
    echo -e "\033[32mBACKUP OVER,SAVE IN\033[33m/BCF \033[0m"
}

function EXPORT_USER_LIST(){
    echo -e "\033[32m----------------------------------------\033[0m"
    echo -e "\033[32m  >>>[[[COLLECT SUSPICIOUS USERS]]]<<<\033[0m"
    echo -e "\033[32m----------------------------------------\033[0m"
    echo "本机IP: $HOST_IP" > $USERLIST
    echo "所有用户UID为0的用户: " >> $USERLIST
    awk -F: '$3==0{print $1}' /etc/passwd >> $USERLIST
    echo -e "\n" >> $USERLIST
    echo "可以使用sudo的所有用户: " >> $USERLIST
    more /etc/sudoers |grep -v "^$\|^#" | grep "=(ALL)" >> $USERLIST
    echo -e "\n" >> $USERLIST
    echo "passwd文件下的所有用户: " >> $USERLIST
    echo "注册名    用户标识号  组标识号" >> $USERLIST
    awk -F: '{print $1,$3,$4}' /etc/passwd >> $USERLIST
    echo "-----------------[UserList]-----------------"
    cat $USERLIST
    echo "-----------------[END]-----------------"
}

# 限制只有wheel组的用户可以使用su提权
function MODIFY_WHEEL_GROUP_PROFILE(){
    read -p "PRESS ENTER MODIFY WHEEL GROUP CONFIGURATION"
    sed -i "1 i\auth sufficient pam_rootok.so" /etc/pam.d/su
    sed -i "2 i\auth required pam_wheel.so group=wheel" /etc/pam.d/su
    echo "-----------------[su]-----------------"
    grep "auth" /etc/pam.d/su
    echo "MODIFY WHEEL GROUP CONFIGURATION FILE! MODIFIED IN /etc/pam.d/su"
    echo "-----------------[END]-----------------"
}

# 设置密码长度与警告天数
function MODIFY_LOGIN_PROFILE(){
    read -p "PRESS ENTER MODIFY /etc/login.defs CONFIGURATION FILE"
    sed -i "s/^PASS_MIN_LEN.*/PASS_MIN_LEN 10/g" /etc/login.defs
    sed -i "s/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/g" /etc/login.defs
    echo "-----------------[login.defs]-----------------"
    grep -i "^PASS_" /etc/login.defs
    echo "MODIFY /etc/login.defs"
    echo "-----------------[END]-----------------"
}

function MODIFY_AUTHENTICATION_PROFILE(){
    echo "CURRENT SYSTEM VERSION $OSVERSION JUDGE FOR YOURSELF"
    read -p "CENTOS7 PLEASE ENTER 7 || CENTOS8 PLEASE ENTER 8: " OSN
    sed -i "4 i$PASSPOLICY" /etc/pam.d/system-auth
    AUTHLNSYSTEM=`grep -n "auth.*pam_unix.so.*nullok.*" /etc/pam.d/system-auth|cut -f1 -d:`
    AUTHLNPASSWORD=`grep -n "auth.*pam_unix.so.*nullok.*" /etc/pam.d/password-auth|cut -f1 -d:`
    AHSYSTEM=$(($AUTHLNSYSTEM))
    AHSYSTEM2=$(($AUTHLNSYSTEM+2))
    AHSYSTEM3=$(($AUTHLNSYSTEM+3))
    AHPASSWD=$(($AUTHLNPASSWORD))
    AHPASSWD2=$(($AUTHLNPASSWORD+2))
    AHPASSWD3=$(($AUTHLNPASSWORD+3))
    if [ ! -n "$OSN" ]; then
        echo "ERROR INPUT!"
        exit 0
    else
        if [ $OSN = "7" ]; then
            sed -i "5 i$ACOTPOLICY" /etc/pam.d/system-auth
            sed -i "5 i$ACOTPOLICY" /etc/pam.d/password-auth
            echo "-----------------[system-auth]-----------------"
            sed -n '3,10p' /etc/pam.d/system-auth
            echo "-----------------[END]-----------------"
            echo "-----------------[password-auth]-----------------"
            sed -n '3,10p' /etc/pam.d/password-auth
            echo "-----------------[END]-----------------"
            echo "\033[32m ADD POLICY IN /etc/pam.d/system-auth AND /etc/pam.d INSIDE CENTOS7 \033[0m"
        elif [ $OSN = "8" ]; then
            ## [CentOS 8测试可用]
            ## 更替system-auth策略
            sed -i "$AHSYSTEM i$ACOTPOLICY8" /etc/pam.d/system-auth
            wait
            sed -i "$AHSYSTEM2 i$ACOTPOLICY81" /etc/pam.d/system-auth
            wait
            sed -i "$AHSYSTEM3 i$ACOTPOLICY82" /etc/pam.d/system-auth
            ## 更替password-auth策略
            sed -i "$AHPASSWD i$ACOTPOLICY8" /etc/pam.d/password-auth
            wait
            sed -i "$AHPASSWD2 i$ACOTPOLICY81" /etc/pam.d/password-auth
            wait
            sed -i "$AHPASSWD3 i$ACOTPOLICY82" /etc/pam.d/password-auth
            wait
            echo "-----------------[system-auth]-----------------"
            sed -n '3,15p' /etc/pam.d/system-auth
            echo "-----------------[END]-----------------"
            echo "-----------------[password-auth]-----------------"
            sed -n '3,15p' /etc/pam.d/password-auth
            echo "-----------------[END]-----------------"
            echo -e "\033[32m ADD POLICY IN /etc/pam.d/system-auth AND /etc/pam.d/password-auth INSIDE CENTOS8 \033[0m"
        else
            echo -e "\033[31m ERROR OS VERSION!\033[0m"
        fi
    fi
}

# 修改profile文件配置超时,修改sysctl.conf防止SYN泛洪攻击
function MODIFY_PROFILE(){
    read -p "PRESS ENTER MODIFY /etc/profile AND /etc/sysctl.conf"
    sed -i "$HLN i\TMOUT=900" /etc/profile
    source /etc/profile
    echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
    sysctl -p
    echo "-----------------[profile]-----------------"
    grep "TMOUT" /etc/profile
    echo "-----------------[END]-----------------"
    echo "-----------------[sysctl.conf]-----------------"
    grep "tcp_max_syn" /etc/sysctl.conf
    echo "-----------------[END]-----------------"
}

# 修改ssh配置文件限制客户端无操作退出时间为600秒
# 限制同时在线账户最大为2个,最大密码输错次数为4次
function MODIFY_SSH_PROFILE(){
    read -p "PRESS ENTER MODIFY /etc/ssh/sshd_config"
    sed -i "s/^#ClientAliveInterval.*/ClientAliveInterval 600/g" /etc/ssh/sshd_config
    sed -i "s/^#ClientAliveCountMax.*/ClientAliveCountMax 2/g" /etc/ssh/sshd_config
    sed -i "s/^#MaxAuthTries.*/MaxAuthTries 4/g" /etc/ssh/sshd_config
    systemctl restart sshd
    systemctl enable sshd
    echo "-----------------[sshd_config]-----------------"
    grep "ClientAlive" /etc/ssh/sshd_config
    grep "MaxAuthTries" /etc/ssh/sshd_config
    echo "-----------------[END]-----------------"
}

function MODIFY_ALIASES_PROFILE(){
    read -p "PRESS ENTER MODIFY /etc/aliases"
    if [ -e /etc/aliases ]; then
        sed -i "s/games/#games/g" /etc/aliases
        sed -i "s/ingres/#ingres/g" /etc/aliases
        sed -i "s/system/#system/g" /etc/aliases
        sed -i "s/toor/#toor/g" /etc/aliases
        sed -i "s/uucp/#uucp/g" /etc/aliases
        sed -i "s/manager/#manager/g" /etc/aliases
        sed -i "s/dumper/#dumper/g" /etc/aliases
        sed -i "s/operator/#operator/g" /etc/aliases
        sed -i "s/decode/#decode/g" /etc/aliases
        sed -i "s/^root/#root/g" /etc/aliases
    fi
    echo "-----------------[aliases]-----------------"
    grep -E '^#[^[:blank:]]' /etc/aliases
    echo "-----------------[END]-----------------"
}

function REFUSE_MODIFY_PROFILE(){
    read -p "PRESS ENTER MODIFY SYSTEM USER GROUP FILE"
    chattr +i /etc/passwd
    chattr +i /etc/shadow
    chattr +i /etc/group
    chattr +i /etc/gshadow
    lsattr /etc/passwd
    lsattr /etc/shadow
    lsattr /etc/group
    lsattr /etc/gshadow
}

function MODIFY_FIREWALLD_PROFILE(){
    # 防止有些主机没有开启firewalld获取不到版本号
    systemctl restart firewalld
    local FIREWALLD_VERSION=`firewall-cmd --version`
    echo "WHETHER TO UPGRADE THE FIREWALL"
    echo "PLZ MAKE SURE YOUR FIREWALLD VERSION HIGHER THAN 0.3.9"
    echo "CURRENT FIREWALLD VERSION $FIREWALLD_VERSION"
    read -p "JUDGE FOR YOUSELF [y/n]" WAIT_SIGN
    echo $WAIT_SIGN
    # 准备做个FTP服务器存活检查,如果存活再执行
    if [ ! -n "$WAIT_SIGN" ]; then
        echo "WRONG CHOICE,FIREWALLD NOT UPDATED"
    else
        if [ $WAIT_SIGN = "y" ] || [ $WAIT_SIGN = "Y" ]; then
            if [ -n "$FTPIP" ] && [[ $FTPIP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                mkdir -p /BCF/yumbackup
                mv /etc/yum.repos.d/* /BCF/yumbackup
                echo "[centos]" > /etc/yum.repos.d/local.repo
                wait
                echo "name=centos" >> /etc/yum.repos.d/local.repo
                wait
                echo "baseurl=ftp://$FTPIP/centos" >> /etc/yum.repos.d/local.repo
                wait
                echo "gpgcheck=0" >> /etc/yum.repos.d/local.repo
                wait
                echo "enabled=1" >> /etc/yum.repos.d/local.repo
                wait
                yum clean all > /dev/null
                wait
                yum makecache > /dev/null
                wait
                yum -y install firewalld
                wait
                mv /etc/yum.repos.d/local.repo /tmp
                mv /BCF/yumbackup/*.repo /etc/yum.repos.d/
                yum clean all > /dev/null
                wait
                yum makecache > /dev/null
                wait
                echo "CONTINUE DOWN THE SCRIPT!"
            else
                echo "ERROR FTP IP ADDRESS,PLEASE CHECK"
                exit 0
            fi
        elif [ $WAIT_SIGN = "n" ] || [ $WAIT_SIGN = "N" ]; then
            # 装饰
            echo "CONTINUE DOWN THE SCRIPT"
        else
            echo "WRONG CHOICE,FIREWALLD NOT UPDATED"
        fi
    fi

    # 添加日志到推送服务器
    local FIREWALLD_VERSION=`firewall-cmd --version`
    echo "BEFORE PROCEEDING TO THE NEXT STEP"
    echo "PLZ MAKE SURE YOUR FIREWALLD VERSION HIGHER THAN 0.3.9"
    echo "CURRENT FIREWALLD VERSION IS $FIREWALLD_VERSION"
    read -p "IF YOU THINK THERE IS NO PROBLEM, PLEASE PRESS ENTER TO CONTINUE"
    sed -i "s/LogDenied=off/LogDenied=all/g" /etc/firewalld/firewalld.conf
    systemctl restart firewalld
    wait
    firewall-cmd --get-log-denied
    firewall-cmd --permanent --add-port=1-25565/tcp
    firewall-cmd --permanent --add-port=1-25565/udp
    firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -p all -s 0.0.0.0/0 -j LOG --log-prefix "INPUT " --log-level 4
    firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -p all -s 127.0.0.1 -j LOG --log-prefix "OUTPUT " --log-level 4
    firewall-cmd --reload
}


function MODIFY_LOG_PROFILE(){
    read -p "PRESS ENTER ENABLE FIREWALLD LOGGING!"
    echo "kern.* /var/log/firewalld" > /etc/rsyslog.d/firewalld.conf
    sed -i "1 i\/var/log/firewalld" /etc/logrotate.d/syslog
    echo "*.*$RSSERVER" >> /etc/rsyslog.conf
    systemctl restart rsyslog
    service auditd restart
    systemctl status rsyslog
    systemctl status auditd
}

# 后续再做修改
function ROLLBACK_OPERATION(){
    read -p "ARE YOU SURE YOU WANT ROLLBACK THE OPERATION? PRESS ENTER"
    echo "FIREWALLD AND RSYSLOG NOT ROLLBACK,IF WANT ROLLBACK PLEASE MANUALLY"
    echo -e "\033[32m >>>[[[START ROLLBACK]]]<<<\033[0m"
    if [ ! -d "/BCF" ]; then
        echo -e "\033[32m BACKUP DRECTORY NOT EXIST,CANNENT NO ROLLBACK  \033[0m"
        exit
    else
        # 倒斜线有取消aliases和特殊符号的作用.
        # 因为cp指令默认别名是cp -i所以每次执行都会询问是否覆盖
        \cp /BCF/su /etc/pam.d/su
        \cp /BCF/login.defs /etc/login.defs
        \cp /BCF/system-auth /etc/pam.d/system-auth
        \cp /BCF/password-auth /etc/pam.d/password-auth
        \cp /BCF/sysctl.conf /etc/sysctl.conf
        \cp /BCF/profile /etc/profile
        \cp /BCF/sshd_config /etc/ssh/sshd_config
        systemctl restart sshd
        \cp /BCF/aliases /etc/aliases
        chattr -i /etc/passwd
        chattr -i /etc/shadow
        chattr -i /etc/group
        chattr -i /etc/gshadow
        # 这边防火墙和日志就不做回退了,保持端口放行,做透明桥日志记录
    fi
}

function MAIN(){
    ## 系统信息
    echo "HOST IP: $HOST_IP"
    echo "SYSTEM: $OSVERSION"
    echo "CURRENT USER: $NUSER"
    echo "PLEASE CHECK FTP REMOTE IP ADDRESS!"
    echo "PLEASE CHECK RSYSLOG SERVER IP ADDRESS AND PORT"
    read -p "PLEASE PRESS ENTER START BACKUP CONFIGURATION FILE"

    # 备份配置文件(不需要询问用户,必做的操作)
    BACKUP_PROFILE
    # 导出用户列表(不需要询问用户,必做的操作)
    EXPORT_USER_LIST

    # 功能模块列表,执行的模块如果有先后顺序,请自行排序
    MODULESLIST=(
        "MODIFY_WHEEL_GROUP_PROFILE"
        "MODIFY_LOGIN_PROFILE"
        "MODIFY_AUTHENTICATION_PROFILE"
        "MODIFY_PROFILE"
        "MODIFY_SSH_PROFILE"
        "MODIFY_ALIASES_PROFILE"
        "REFUSE_MODIFY_PROFILE"
        "MODIFY_FIREWALLD_PROFILE"
        "MODIFY_LOG_PROFILE"
    )
    
    # 自行决定是否执行模块
    for MDLS in ${MODULESLIST[@]}
    do
        echo -e "\033[032mTHE CURRENT MODULE IS $MDLS \033[0m"
        read -p "PRESS q/Q SKIPING THIS MODULE" TVARIABLES
        if [ ! -n "$TVARIABLES" ]; then
            $MDLS
        else
            if [ $TVARIABLES = "q" ] || [ $TVARIABLES = "Q" ]; then
                echo "\033[32m SKIPING THIS MODULE \033[0m"
            else
                $MDLS
            fi
        fi
    done

    echo "SCRIPT FINISHED!"
    echo "PLZ CHECK CONFIGURATION AND SERVICE OR SOMETHING"
    echo "MAKE SURE THERE IS NOTHING WRONG"
    echo "SUSPICIOUS USER SAVE IN /BCF/UserList.txt"
    echo "BACKUP FILES SAVE IN /BCF"
}