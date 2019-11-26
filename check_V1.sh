#!/bin/bash

ipadd=$(ifconfig -a | grep inet | awk -F "[ :]+" '{print $3}' | head -n 1)
hostname=$(hostname)

echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "==========1. 계정 및 패스워드 관리==========" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt

#1-01 root와 중복된 UID/GID가 없도록 설정 하였는가?

UIDS=$(awk -F[:] 'NR!=1{print $3}' /etc/passwd)
flag=0
for i in $UIDS
do
  if [ $i = 0 ];then
    echo -e "\033[31;1m"1-01 비 root 계정 중에서 UID 0 존재 - 취약"\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  else
    flag=1
  fi
done
if [ $flag = 1 ];then
  echo "1-01 비 root 계정 중에서 UID 0 존재하지 않음 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
fi


#1-02 불필요한 계정의 로그인 Shell 제한 설정을 하였는가?

file1=$(grep -E "adm|bin\|daemon|listen|lp|nobody|noaccess|nuucp|smtp|sys\|uucp" /etc/passwd | wc -l)
  if [ $file1 -eq 0 ];then
    echo "1-02불필요한 계정 존재 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"1-02 불필요한 계정 존재 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi


#1-03 취약한 패스워드를 사용하지 않는가?

file2=$(cat /etc/pam.d/system-auth | grep pam_cracklib.so | wc -l)
	if [ $file2 -eq 1 ];then
		echo "1-03 취약한 패스워드 사용 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"1-03 취약한 패스워드 사용 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

 
#1-04 패스워드 파일 권한을 설정 하였는가?

file3=$(ls -l /etc/shadow | awk '{print $1}')
if [ $file3 = "-r--------." ];then
  echo "1-04 /etc/shadow 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
else
  echo -e "\033[31;1m"1-04 /etc/shadow 파일권한 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

#1-05 패스워드 최소 길이를 설정 하였는가?

file4=$(cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}')
if [ $file4 -ge 8 ];
then
  echo "1-05 ${file4} 자리 - 최소 암호 길이 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
else
  echo -e "\033[31;1m"1-05 ${file4} 자리 - 최소 암호 길이 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

#1-06 패스워드 복잡도를 설정 하였는가?

file5=$(cat /etc/pam.d/system-auth | grep ocredit | wc -l)

	if [ $file5 -eq 1 ];then
		echo "1-06 패스워드 복잡도 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"1-06 패스워드 복잡도 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

cat /etc/pam.d/system-auth | grep tally

#1-07 계정 잠금 임계값을 설정 하였는가?

file6=$(cat /etc/pam.d/system-auth | grep tally | wc -l)

	if [ $file6 -eq 1 ];then
		echo "1-07 계정 잠금 임계값 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"1-07 계정 잠금 임계값 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

#1-08 패스워드의 최대 사용기간을 설정 하였는가?

file7=$(cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}')

if [ $file7 -le 91 -a $file7 -gt 0 ];
then
  echo "1-08 ${file7} 일 - 패스워드의 최대 사용기간 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
else
  echo -e "\033[31;1m"1-08 ${file7} 일 - 패스워드의 최대 사용기간 - 취약"\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

#1-09 최근 패스워드 기억을 설정 하였는가?

file8=$(cat /etc/pam.d/system-auth | grep remember | wc -l)

	if [ $file8 -eq 1 ];then
		echo "1-09 최근 패스워드 기억을 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"1-09 최근 패스워드 기억을 설정 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "=================2. 접근제어================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt

# 2-01 Inetd.conf 파일 권한을 644로 설정 하였는가?

echo "2-01 Inetd.conf 파일 권한을 644로 설정 하였는가? - 해당사항 없음" >> /sh/${ipadd}_${hostname}_out.txt

# 2-02 SU 명령을 특정 계정만 사용할 수 있도록 제한 하였는가?

file9=$( grep -E "pam_rootok.so|pam_staff.so" /etc/pam.d/su | wc -l)
  if [ $file9 -eq 2 ];then
    echo "2-02 SU 명령을 특정 계정만 사용할 수 있도록 제한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "2-02 SU 명령을 특정 계정만 사용할 수 있도록 제한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
fi


# 2-03 원격 root 접속 설정을 제한 하였는가?

file10=$(cat /etc/pam.d/system-auth | grep pam_securetty.so | wc -l)

	if [ $file10 -eq 1 ];then
		echo "2-03 원격 root 접속 설정을 제한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "2-03 원격 root 접속 설정을 제한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
fi

# 2-04 원격 root 접속 설정을 제한 하였는가?

file11=$(cat /etc/profile | grep TMOUT | wc -l)

	if [ $file11 -eq 1 ];then
		echo "2-04 원격 root 접속 설정을 제한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"2-04 원격 root 접속 설정을 제한 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "===============3. 시스템 보안===============" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt

# 3-01 환경 파일 권한을 640으로 설정 하였는가?

echo -e "3-01 환경 파일 권한을 640으로 설정 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt

file12=$(ls -l /root/.bash_profile | awk '{print $1}')

if [ -f /root/.bash_profile ];then
  if [ $file12 = "-rw-r-----." ];then
    echo "	/root/.bash_profile 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.bash_profile 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.bash_profile 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file13=$(ls -l /root/.profile | awk '{print $1}')

if [ -f /root/.profile ];then
  if [ $file13 = "-rw-r-----." ];then
    echo "	/root/.profile 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.profile 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.profile파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /root/.login | awk '{print $1}')

if [ -f /root/.login ];then
  if [ $file14 = "-rw-r-----." ];then
    echo "	/root/.login 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.login 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.login 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file15=$(ls -l /root/.cshrc | awk '{print $1}')

if [ -f /root/.cshrc ];then
  if [ $file15 = "-rw-r-----." ];then
    echo "	/root/.cshrc 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.cshrc 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.cshrc 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file16=$(ls -l /root/.kshrc | awk '{print $1}')

if [ -f /root/.kshrc ];then
  if [ $file16 = "-rw-r-----." ];then
    echo "	/root/.kshrc 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.kshrc 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.kshrc 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file17=$(ls -l /root/.bash_profile | awk '{print $1}')

if [ -f /root/.kshrc ];then
  if [ $file17 = "-rw-r-----." ];then
    echo "/root/.bash_profile 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.bash_profile 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.bash_profile 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file18=$(ls -l /root/.bashrc | awk '{print $1}')

if [ -f /root/.bashrc ];then
  if [ $file18 = "-rw-r-----." ];then
    echo "	/root/.bashrc 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.bashrc 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.bashrc 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file19=$(ls -l /root/.login | awk '{print $1}')

if [ -f /root/.login ];then
  if [ $file19 = "-rw-r-----." ];then
    echo "	/root/.login 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.login 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.login 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file20=$(ls -l /root/.exrc | awk '{print $1}')

if [ -f /root/.exrc ];then
  if [ $file20 = "-rw-r-----." ];then
    echo "	/root/.exrc 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.exrc 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.exrc 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file21=$(ls -l /root/.exrc | awk '{print $1}')

if [ -f /root/.exrc ];then
  if [ $file21 = "-rw-r-----." ];then
    echo "	/root/.exrc 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.exrc 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.exrc 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file22=$(ls -l /root/.netrc | awk '{print $1}')

if [ -f /root/.netrc ];then
  if [ $file22 = "-rw-r-----." ];then
    echo "	/root/.netrc 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.netrc 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.netrc 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file23=$(ls -l /root/.dtprofile | awk '{print $1}')

if [ -f /root/.dtprofile ];then
  if [ $file23 = "-rw-r-----." ];then
    echo "	/root/.dtprofile 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.dtprofile 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.dtprofile 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file24=$(ls -l /root/.Xdefaults | awk '{print $1}')

if [ -f /root/.Xdefaults ];then
  if [ $file24 = "-rw-r-----." ];then
    echo "	/root/.Xdefaults 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.Xdefaults 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.Xdefaults 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file25=$(ls -l /root/.rhosts | awk '{print $1}')

if [ -f /root/.rhosts ];then
  if [ $file25 = "-rw-r-----." ];then
    echo "	/root/.rhosts 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/root/.rhosts 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/root/.rhosts 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi




# 3-02 환경 파일 권한을 640으로 설정 하였는가?
# 812까지 배열로 변경

echo -e "3-02 주요 디렉터리 및 중요파일의 권한을 설정 하였는가??" >> /sh/${ipadd}_${hostname}_out.txt

file12=$(ls -l /etc/hosts.allow | awk '{print $1}')

if [ -f /etc/hosts.allow ];then
  if [ $file12 = "-rw-------." ];then
    echo "	/etc/hosts.allow 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/hosts.allow 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/hosts.allow 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file13=$(ls -l /etc/inetd.conf | awk '{print $1}')

if [ -f /etc/inetd.conf ];then
  if [ $file13 = "-rw-------." ];then
    echo "	/etc/inetd.conf 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/inetd.conf 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/inetd.conf 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /var/log/authlog | awk '{print $1}')

if [ -f /var/log/authlog ];then
  if [ $file14 = "-rw-------" ];then
    echo "	/var/log/authlog 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/log/authlog 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/log/authlog 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file15=$(ls -l /var/log/syslog | awk '{print $1}')

if [ -f /var/log/syslog ];then
  if [ $file15 = "-rw-------" ];then
    echo "	/var/log/syslog 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/log/syslog 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/log/syslog 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file16=$(ls -l /var/adm/loginlog | awk '{print $1}')

if [ -f //var/adm/loginlog ];then
  if [ $file16 = "-rw-------" ];then
    echo "	/var/adm/loginlog 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/loginlog 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/loginlog 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file17=$(ls -l /var/adm/lastlog | awk '{print $1}')

if [ -f /var/adm/lastlog ];then
  if [ $file17 = "-rw-------" ];then
    echo "/var/adm/lastlog 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/lastlog 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/lastlog 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file18=$(ls -l /var/adm/messages | awk '{print $1}')

if [ -f /var/adm/messages ];then
  if [ $file18 = "-rw-------" ];then
    echo "	/var/adm/messages 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/messages 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/messages파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file19=$(ls -l /var/adm/sulog | awk '{print $1}')

if [ -f /var/adm/sulog ];then
  if [ $file19 = "-rw-------" ];then
    echo "	/var/adm/sulog 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/sulog 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/sulog 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file20=$(ls -l /var/adm/pacct | awk '{print $1}')

if [ -f /var/adm/pacct ];then
  if [ $file20 = "-rw-------" ];then
    echo "	/var/adm/pacct 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/pacct 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/pacct 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file21=$(ls -l /var/adm/wtmp | awk '{print $1}')

if [ -f /var/adm/wtmp ];then
  if [ $file21 = "-rw-------" ];then
    echo "	/var/adm/wtmp 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/wtmp 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/wtmp 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file22=$(ls -l /var/adm/utmp | awk '{print $1}')

if [ -f /var/adm/utmp ];then
  if [ $file22 = "-rw-------" ];then
    echo "	/var/adm/utmp 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/adm/utmp 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/adm/utmp 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file23=$(ls -l /usr/bin/lastcomm | awk '{print $1}')

if [ -f /usr/bin/lastcomm ];then
  if [ $file23 = "-rw-------" ];then
    echo "	/usr/bin/lastcomm 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/usr/bin/lastcomm 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/usr/bin/lastcomm 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file24=$(ls -l /var/log/daemon.log | awk '{print $1}')

if [ -f /var/log/daemon.log ];then
  if [ $file24 = "-rw-------" ];then
    echo "	/var/log/daemon.log 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/log/daemon.log 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/log/daemon.log 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file25=$(ls -l /var/log/kern.log | awk '{print $1}')

if [ -f /var/log/kern.log ];then
  if [ $file25 = "-rw-------" ];then
    echo "	/var/log/kern.log 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/log/kern.log 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/log/kern.log 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file12=$(ls -l /etc/services | awk '{print $1}')

if [ -f /etc/services ];then
  if [ $file12 = "-rw-r-----." ];then
    echo "	/etc/services 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/services 파일권한 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/services 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file13=$(ls -l /etc/passwd | awk '{print $1}')

if [ -f /etc/passwd ];then
  if [ $file13 = "-rw-r--r--." ];then
    echo "	/etc/passwd 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/passwd 파일권한 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/passwd 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file14=$(ls -l /etc/group | awk '{print $1}')

if [ -f /etc/group ];then
  if [ $file14 = "-rw-r--r--." ];then
    echo "	/etc/group 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/group 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/passwd 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file12=$(ls -l /etc/motd | awk '{print $1}')

if [ -f /etc/motd ];then
  if [ $file12 = "-rw-r-----." ];then
    echo "	/etc/motd 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/motd 파일권한 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/motd 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file13=$(ls -l /etc/hosts | awk '{print $1}')

if [ -f /etc/hosts ];then
  if [ $file13 = "-rw-r--r--." ];then
    echo "	/etc/hosts 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/hosts 파일권한 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/hosts 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file14=$(ls -l /etc/group | awk '{print $1}')

if [ -f /etc/group ];then
  if [ $file14 = "-rw-r--r--." ];then
    echo "	/etc/group 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/group 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/passwd 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file15=$(ls -l /etc/syslogd.pid | awk '{print $1}')

if [ -f /etc/syslogd.pid ];then
  if [ $file15 = "-rw-r--r--." ];then
    echo "	/etc/syslogd.pid 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/syslogd.pid 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/syslogd.pid 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file16=$(ls -l /etc/syslogd.pid | awk '{print $1}')

if [ -f /etc/hosts.equiv ];then
  if [ $file16 = "-rwx------" ];then
    echo "	/etc/hosts.equiv 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/hosts.equiv 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/hosts.equiv 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file17=$(ls -l /etc/syslogd.pid | awk '{print $1}')

if [ -f /etc/hosts.equiv ];then
  if [ $file17 = "-rwxrwx--x" ];then
    echo "	/etc/hosts.equiv 파일권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/hosts.equiv 파일권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/hosts.equiv 파일 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi




file14=$(ls -l /etc | awk '{print $1}')

if [ -f /etc ];then
  if [ $file14 = "-rwxrwx--x" ];then
    echo "	/etc 폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc 폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc 폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /bin | awk '{print $1}')

if [ -f /bin ];then
  if [ $file14 = "-rwxrwx--x" ];then
    echo "	/bin 폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/bin 폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/bin 폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file14=$(ls -l /usr/bin | awk '{print $1}')

if [ -f /usr/bin ];then
  if [ $file14 = "-rwxrwx--x" ];then
    echo "	/usr/bin 폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/usr/bin 폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/usr/bin 폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /sbin | awk '{print $1}')

if [ -f /sbin ];then
  if [ $file14 = "-rwxrwx--x" ];then
    echo "	/sbin 폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/sbin 폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/sbin 폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /etc/init.d | awk '{print $1}')

if [ -f /etc/init.d ];then
  if [ $file14 = "-rwxr-xr-x" ];then
    echo "	/etc/init.d 폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/init.d 폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/init.d 폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file14=$(ls -l /etc/rc*.* | awk '{print $1}')

if [ -f /etc/rc* ];then
  if [ $file14 = "-rwxr-xr-x" ];then
    echo "	/etc/rc*.* 폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/rc*.* 폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/rc*.* 폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /etc/cron.dcron.allow  | awk '{print $1}')

if [ -f /etc/cron.dcron.allow ];then
  if [ $file14 = "-rwxr-xr-x" ];then
    echo "	/etc/cron.dcron.allow  폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/cron.dcron.allow  폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/cron.dcron.allow  폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /etc/cron.d/cron.deny  | awk '{print $1}')

if [ -f /etc/cron.d/cron.deny ];then
  if [ $file14 = "-rwxr-xr-x" ];then
    echo "	/etc/cron.d/cron.deny  폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/cron.d/cron.deny  폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/cron.d/cron.deny  폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file14=$(ls -l /etc/cron.d/at.allow   | awk '{print $1}')

if [ -f /etc/cron.d/at.allow  ];then
  if [ $file14 = "-rwxr-xr-x" ];then
    echo "	/etc/cron.d/at.allow   폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/cron.d/at.allow   폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/cron.d/at.allow   폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /etc/cron.d/at.eny  | awk '{print $1}')

if [ -f /etc/cron.d/at.eny ];then
  if [ $file14 = "-rwxr-xr-x" ];then
    echo "	/etc/cron.d/at.eny  폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/etc/cron.d/at.eny  폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/etc/cron.d/at.eny  폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi

file14=$(ls -l /tmp | awk '{print $1}')

if [ -f /tmp ];then
  if [ $file14 = "-rwxrwxrwt" ];then
    echo "	/tmp  폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/tmp  폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/tmp  폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


file14=$(ls -l /var/tmp | awk '{print $1}')

if [ -f /var/tmp ];then
  if [ $file14 = "-rwxrwxrwt" ];then
    echo "	/var/tmp  폴더권한 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"	/var/tmp  폴더권한 취약  "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
  fi

else
  echo "	/var/tmp  폴더 존재하지 않음." >> /sh/${ipadd}_${hostname}_out.txt
fi


# 3-03 Host 파일의 권한을 644로 설정 하였는가?

echo -e "3-03 Host 파일의 권한을 644로 설정 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "3-02 항목과 중복" >> /sh/${ipadd}_${hostname}_out.txt


# 3-04 부팅 스크립트의 권한을 754로 설정 하였는가?

echo -e "3-04 부팅 스크립트의 권한을 754로 설정 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "3-02 항목과 중복" >> /sh/${ipadd}_${hostname}_out.txt


# 3-05 PATH 설정 내 "."를 제거 하였는가?

echo -e "3-05 PATH 설정 내 "."를 제거 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 3-06 UMASK 값을 022로 설정 하였는가?

file10=$(cat /etc/profile | grep umask | grep 022 | wc -l)

	if [ $file10 -eq 1 ];then
		echo "3-06 UMASK 값을 022로 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"3-06 UMASK 값을 022로 설정 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

# 3-07 일반사용자에 대하여 SUID/SGID의 설정을 해제 하였는가?

echo -e "3-07 일반사용자에 대하여 SUID/SGID의 설정을 해제 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 3-08 홈 디렉터리 권한을 설정 하였는가?

echo -e "3-08 홈 디렉터리 권한을 설정 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 3-09 history file 권한을 600으로 설정 하였는가?

echo -e "3-09 history file 권한을 600으로 설정 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 3-10 /dev에 존재하지 않는 device 파일을 제거 하였는가?

echo -e "3-10 /dev에 존재하지 않는 device 파일을 제거 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "===============4. 서비스 보안===============" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt


# 4-01 불필요한 서비스를 중지 하였는가?
echo -e "4-01 /불필요한 서비스를 중지 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 4-02 NFS 공유 설정을 제거 하였는가?
echo -e "4-02 NFS 공유 설정을 제거 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 4-03 FTP 서비스 설정을 하였는가?
echo -e "4-03 FTP 서비스 설정을 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 4-05 SNMP community string 값을 설정 하였는가?

file10=$(ps -ef | grep snmp | grep -v grep | wc -l)

	if [ $file10 -eq 0 ];then
		echo "4-05 SNMP community string 값을 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"4-05 SNMP community string 값을 설정 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

# 4-06 SMTP 보안 설정을 적용 하였는가?

file1=$(ps -ef | grep smtp | grep -v grep | wc -l)

	if [ $file1 -eq 0 ];then
		echo "4-06 SMTP 보안 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"4-06 SMTP 보안 설정 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

# 4-08 SWAT 강제 공격 방지 설정을 하였는가?
echo -e "4-08 SWAT 강제 공격 방지 설정을 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 4-09 Samba 제한 설정을 하였는가?
echo -e "4-09 Samba 제한 설정을 하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 5 모니터링
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "===============5. 모니터링==================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt

# 5-01 시스템 로그를 설정하여 기록하고 있는가?
echo -e "5-01 시스템 로그를 설정하여 기록하고 있는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 5-02 SU 로그를 기록 하고 있는가?
echo -e "SU 로그를 기록 하고 있는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "	해당사항없음" >> /sh/${ipadd}_${hostname}_out.txt

# 5-03 lastlog를 기록하도록 설정하였는가?
file10=$( ls -l /var/log/lastlog | wc -l)

	if [ $file10 -eq 1 ];then
		echo "5-03 lastlog를 기록하도록 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"5-03 lastlog를 기록하도록 설정 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

# 6 기타 보안관리
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "===============6. 기타 보안관리=============" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt


# 6-01 서비스 배너에 시스템 OS 및 시스템 정보가 노출되지 않도록 경고 메시지를 설정 하였는가?
file10=$( cat /etc/issue | grep reported | wc -l)

	if [ $file10 -eq 1 ];then
		echo "6-01 경고 메시지 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"6-01 경고 메시지 설정 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi

# 6-02 .exrc 파일 설정 내 불법적인 명령어를 제거 하였는가?
file10=$(  cat /.exrc | grep ! | wc -l)

	if [ $file10 -eq 0 ];then
		echo "6-02 .exrc 파일 설정 내 불법적인 명령어 설정 - 정상" >> /sh/${ipadd}_${hostname}_out.txt
  else
    echo -e "\033[31;1m"6-02 .exrc 파일 설정 내 불법적인 명령어 - 취약 "\033[m" >> /sh/${ipadd}_${hostname}_out.txt
fi


# 6-04 최신 패치를 적용하였는가?
echo -e "6-04 최신 패치를 적용하였는가?" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "*********개별확인 필요" >> /sh/${ipadd}_${hostname}_out.txt

echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "===================완료=====================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt
echo -e "============================================" >> /sh/${ipadd}_${hostname}_out.txt



#moondal:moondal 을 user:passwd ftp주소 변경

#curl -T ${ipadd}_${hostname}_out.txt -u moondal:moondal ftp://172.27.0.206/"$(date +%Y%m)"/

echo -e "============================================"
echo -e "============================================"
echo -e "================결과전송===================="
echo -e "============================================"
echo -e "============================================"

