#!/bin/bash


echo "U-01: permission root login"

if [ "`cat /etc/pam.d/login | grep -i "pam_securetty.so"`" == "" ] 
then
#    if [ -f /lib/security/pam_securetty.so ]
#    then
    echo "/etc/pam.d/login ...vulnerable"
else
    echo "/etc/pam.d/login ...safe"
fi

SSH_PERM=`cat /etc/ssh/sshd_config | grep -i "permitrootlogin" | cut -d " " -f2`
for VAL in $SSH_PERM
do
    MSG="/etc/ssh/sshd_config ...vulnerable"
    if [ $VAL == "No" ] || [ $VAL == "no" ]
    then
        MSG="/etc/ssh/sshd_config ...safe"
    fi
done
echo $MSG

unset SSH_PERM
unset MSG
unset VAL


echo ""
echo "U-02: password complexity"

passwd_config() {
    if [ `cat /etc/security/pwquality.conf | grep $1 | cut -d "=" -f2` == $2 ]
    then
        echo "$1 ...safe"
    else
        echo "$1 ...vulnerable"
    fi
}

passwd_config lcredit -1
passwd_config ucredit -1
passwd_config dcredit -1
passwd_config ocredit -1
passwd_config minlen 8
passwd_config difok N


echo ""
echo "U-04: /etc/shadow"

ENC_PASSWD=`cat /etc/passwd | cut -d ":" -f2` # passwd encrypt
MSG="...safe"
for VAL in $ENC_PASSWD
do
    if [ $VAL != "x" ]
    then
        MSG="...vulnerable"
    fi
done
echo $MSG

unset ENC_PASSWD
unset MSG
unset VAL


echo ""
echo "U-44: check UID"

CNT_UID=`cat /etc/passwd | cut -d ":" -f3` # passwd UID
CNT=0
for UID_NUM in $CNT_UID
do
    if [ "$UID_NUM" == "0" ]
    then
        let "CNT = $CNT + 1"
    fi
done
if [ $CNT -eq 1 ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi

unset CNT_UID
unset CNT
unset UID_NUM


echo ""
echo "U-47: password max days"

if [ `cat /etc/login.defs | grep -P "PASS_MAX_DAYS\t[0-9]+" | cut -d$'\t' -f2` -le 90 ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi


echo ""
echo "U-48: password min days"

if [ `cat /etc/login.defs | grep -P "PASS_MIN_DAYS\t[0-9]+" | cut -d$'\t' -f2` -ge 1 ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi


echo ""
echo "U-49: check unnecessary user"

if [ -z `cat /etc/passwd | egrep "^lp|^uucp|^nuucp"` ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi


echo ""
echo "U-52: check same UID"

UID_NUM=`cat /etc/passwd | cut -d ":" -f3 | wc -l`
UID_INSPECT=`cat /etc/passwd | cut -d ":" -f3 | uniq -u | wc -l`

if [ $UID_NUM -eq $UID_INSPECT ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi

unset UID_NUM
unset UID_INSPECT

echo ""
echo "U-53: check user shell" 

USER_SHELL=`cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" | grep -v "admin" | cut -d ":" -f7`
MSG="...safe"
for USER in $USER_SHELL
do
    if [[ "$USER" != */bin/false* ]] && [[ "$USER" != */sbin/nologin* ]]
    then
        MSG="...vulnerable"
    fi
done
echo $MSG

unset USER_SHELL
unset MSG
unset USER


echo ""
echo "U-54: session timeout"

if [ -z `cat /etc/profile | grep "TMOUT="` ]
then
    echo "...vulnerable"
else
    if [ `cat /etc/profile | grep "TMOUT=" | cut -d "=" -f2` -gt 600 ]
    then
        echo "...vulnerable"
    else
        if [ -n `cat /etc/profile | grep -e "export\tTMOUT" -e "export +TMOUT"` ]
        then
            echo "...safe"
        else
            echo "...vulnerable"
        fi
    fi
fi


# file management
echo ""
echo "U-06: nouser/nogroup"

if [ -z `find / -nouser -o -nogroup 2>/dev/null` ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi


echo ""
echo "U-07: /etc/passwd OWN/PERM"

OWN_PERM=`find /etc/passwd -user root ! -perm -133 2>/dev/null` # passwd perm 644 -le
MSG="...vulnerable"
if [ $OWN_PERM == "/etc/passwd" ]
then
    MSG="...safe"
fi

echo $MSG

unset OWN_PERM
unset MSG


echo ""
echo "U-08: /etc/shadow OWN PERM"

OWN_PERM=`find /etc/shadow -user root ! -perm -377 2>/dev/null` # shadow perm 400 -le
MSG="...vulnerable"
if [ $OWN_PERM == "/etc/shadow" ]
then
    MSG="...safe"
fi

echo $MSG
 
unset OWN_PERM
unset MSG


echo ""
echo "U-09: /etc/hosts OWN PERM"

OWN_PERM=`find /etc/hosts -user root ! -perm -177 2>/dev/null` # hosts perm 600 -le
MSG="...vulnerable"
if [ $OWN_PERM == "/etc/hosts" ]
then
    MSG="...safe"
fi

echo $MSG

unset OWN_PERM
unset MSG


echo ""
echo "U-12: /etc/services OWN PERM"

OWN_PERM=`find /etc/services \( -user root -o -user bin \) ! -perm -133 2>/dev/null`
MSG="...vulnerable"
if [ $OWN_PERM == "/etc/services" ]
then
    MSG="...safe"
fi

echo $MSG

unset OWN_PERM
unset MSG


echo ""
echo "U-13: SUID/SGID file"

for FILE in `find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev 2>/dev/null`
do
    echo $FILE
done


echo ""
echo "U-14: Permission Startup Env"

FILE=`find ~ -type f -name ".*" -perm /002 -user root 2>/dev/null`
if [ -z $FILE ]
then
    echo "...safe"
else
    echo "...vulnerable"
fi

unset FILE


echo ""
echo "U-15: World Writable File"

FILES=`find / ! \( -path '/proc' -prune \) -type f -perm -2 2>/dev/null`
MSG="...safe"
for FILE in $FILES
do
    if [ $FILE == "" ]
    then
        MSG="...vulnerable"
    fi
done

echo $MSG

unset FILES
unset MSG
unset FILE


echo ""
echo "U-16: /dev Device File"

FILES=`find /dev -type f 2>/dev/null`
if [ "$FILES" == "" ] 
then
    echo "...safe"
else
    echo "...vulnerable"
    for FILE in $FILES
    do
        echo $FILE
    done
fi

unset FILES
unset FILE 
