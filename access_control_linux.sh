#!/usr/bin/bash

myPassword=" " #pass your root password here
groupNames=("administration" "managers" "developers" "sudo")
# groupIdsArray=()
usersList="users_list.txt"
restrictedUsers=("Anthony" "Alice" "Elisa")
restrictedCommandUsers=("Boss")
restrictedGroups=("administration" "managers" "developers")


#here i am creating groups here.

for groupName in "${groupNames[@]}"
    do
        echo $myPassword | sudo -S groupadd "$groupName" #this command is creating group
        groupInfo=$(getent group "$groupName")
        echo " $groupName group has created".
    done

#craeting new users

if echo "$myPassword" | sudo -S newusers "$usersList"; then #i am taking users from $usersList file and creating users
    echo "User '$username' created successfully!"
else
    echo "Error: Failed to create user '$username'."
fi
#Adding umask in every created user

lineToAdd="umask 0000"
userDirectories=$(ls -1 /home)

for userDirectory in $userDirectories; do
    if [ -f "/home/$userDirectory/.bashrc" ]; then
        if ! grep -qF "$lineToAdd" "/home/$userDirectory/.bashrc" ; then
            echo $myPassword | sudo -S bash -c "echo -e '\n$lineToAdd' >> /home/$userDirectory/.bashrc"
            echo " $lineToAdd is added in the .bashrc file"
        else
            echo " $lineToAdd is present in the .bashrc file"
        fi
    else
        echo $myPassword | sudo -S bash -c "echo -e '$lineToAdd\n' > /home/$userDirectory/.bashrc"
        echo "bashrc file created and add this line"
    fi
done

#This script block will extract the username and user ID from each line of users_list.txt and process them accordingly. If a valid user ID is not found, it will print an error message.
while IFS=: read -r line; do
    username=$(echo "$line" | awk -F: '{print $1}') #Taking the user name from usersList file
    uid=$(echo "$line" | awk -F: '{print $3}') #Taking the user ID name from usersList file
    homeDir=$(echo "$line" | awk -F: '{print $6}') #Taking the user home directory from usersList file

    if [ -z "$uid" ]; then
        echo "User $username does not have a valid user ID."
    else
        if [ "$uid" -ge 1200 ] && [ "$uid" -lt 1300 ]; then
            #adding Boss and GodeMode users in a sudo group. They are the privileged users, that's why i am not controlling there permissions.
            echo "$myPassword" | sudo -S usermod -aG "${groupNames[3]}" "$username"
            #defining user's home directory ownership
            echo "$myPassword" | sudo -S chown -R "$username":"${groupNames[3]}" "$homeDir" \
            && echo "Added '$username' to the '${groupNames[3]}' group"
        elif [ "$uid" -ge 1300 ] && [ "$uid" -lt 1400 ]; then
            echo "$myPassword" | sudo -S usermod -aG "${groupNames[0]}" "$username" \
            && echo "Added $username to the ${groupNames[0]} group" \
            && sudo -S chown -R "$username":"${groupNames[0]}" "$homeDir" \
            && sudo -S chmod -R 750 "$homeDir"
            #here i am setting ACL's for the owner to rwx, and for group r-x, and for others ---, m:r-x will affect group and users permission only.
            #With this i am also setting up that the higher level group can read the objects of lower level group with g:"${groupNames[3]}":r-x line.
            echo "$myPassword" | sudo -S setfacl -R -m "u::rwx,g::r-x,g:"${groupNames[3]}":r-x,m::r-x,o::---" "$homeDir" \
            && sudo -S getfacl "$homeDir"
            # g+r represents here add read permissions for the group which group owns the file or dirctory.
            echo "$myPassword" | sudo -S chmod g+r "$homeDir" \
            # g+s represnts setgid, that does mean when any directory will be created inside this directory then it will inherit parents directorie's permissions.
            echo "$myPassword" | sudo -S chmod g+s "$homeDir" \
            && ls -l "$homeDir"
        elif [ "$uid" -ge 1400 ] && [ "$uid" -lt 1500 ]; then
            echo "$myPassword" | sudo -S usermod -aG "${groupNames[1]}" "$username" \
            && sudo -S chown -R "$username":"${groupNames[1]}" "$homeDir" \
            && sudo -S chmod -R 750 "$homeDir" \
            && sudo -S setfacl -R -m "u::rwx,g::r-x,g:"${groupNames[3]}":r-x,g:"${groupNames[0]}":r-x,m::r-x,o::---" "$homeDir" \
            && sudo -S chmod g+r "$homeDir" \
            && sudo -S chmod g+s "$homeDir" \
            && ls -l "$homeDir"
        elif [ "$uid" -ge 1500 ] && [ "$uid" -lt 1600 ]; then
            echo "$myPassword" | sudo -S usermod -aG "${groupNames[2]}" "$username" \
            && sudo -S chown -R "$username":"${groupNames[2]}" "$homeDir" \
            && sudo -S chmod -R 750 "$homeDir" \
            && sudo -S setfacl -R -m "u::rwx,g::r-x,g:"${groupNames[3]}":r-x,g:"${groupNames[0]}":r-x,g:"${groupNames[1]}":r-x,m::r-x,o::---" "$homeDir" \
            && sudo -S chmod g+r "$homeDir" \
            && sudo -S chmod g+s "$homeDir" \
            && ls -l "$homeDir"
        else
            echo "User $username does not satisfy any condition."
        fi
    fi
done < "$usersList"

# Restrict terminal access for specific user with AppArmor

for user in "${restrictedUsers[@]}"
do
    #here i am changing users shell for blocking there terminal access.
    echo $myPassword | sudo -S chsh -s /bin/false "$user"
    echo "Access terminal is block for user $user"
    # for revert this echo $myPassword | sudo -S chsh -s /bin/bash "$user"
done


#Access Control with AppArmor.

echo $myPassword | sudo -S apt install apparmor \
&& sudo -S systemctl enable apparmor \
&& sudo -S systemctl start apparmor

create_profile() {
    local userName=$1
    local profileFile="/etc/apparmor.d/usr.bin.restrict_cli_$userName"

    # Check if the profile file already exists
    #this is the apparmor profile i am creating here.
    if [ ! -f "$profileFile" ]; then
        echo $myPassword | sudo -S bash -c "cat > $profileFile <<EOF
# Deny access to essential system binaries
$profileFile {
    /usr/bin/* ix,
    /bin/* ix,
    /sbin/* ix,
    /usr/sbin/* ix,
    /lib/* ix,
    /lib64/* ix,
    /usr/lib/* ix,
    /usr/lib64/* ix,

    # Deny network access (optional, uncomment if needed)
    # network, 

    # Allow read-only access to some non-essential system files
    /var/log/** r,
    /tmp/** r,
    /var/tmp/** r,
}
EOF"
        #i am loading apparmor profile which i have created earlier
        echo $myPassword | sudo -S apparmor_parser -r $profileFile
        echo "AppArmor profile for $userName created and loaded."
    else
        echo "AppArmor profile for $userName already exists. No action need to be taken."
    fi
}

for user in "${restrictedCommandUsers[@]}"; do
    create_profile $user
done

# Assign the profiles to the users
for restrictedUser in "${restrictedCommandUsers[@]}"; do
    profilePath="/etc/apparmor.d/usr.bin.restrict_cli_$restrictedUser"
    if ! echo $myPassword | sudo -S aa-status --profile="$profilePath" | grep -q "enforced"; then
        # echo "DEBUG: Starting enforcement for $restrictedUser"
        # Enforcing the specified apparmor security profile for the /bin/bash executable
        echo $myPassword | sudo -S aa-enforce "$profilePath" "/bin/bash"
        echo "AppArmor profile for $restrictedUser enforced."
    else
        echo "AppArmor profile for $restrictedUser is already enforced. No action taken."
    fi
done

echo $myPassword | sudo -S aa-status

# Restrict some user groups from accessing some commands

restrictedCommands="!/sbin/shutdown"
networkAdapterCommands="!/usr/sbin/ifconfig, !/sbin/ip, !/sbin/ifup, !/sbin/ifdown"

for group in "${restrictedGroups[@]}"
do
    if ! echo $myPassword | sudo -S grep -q "^%$group ALL=(ALL) ${restrictedCommands}" /etc/sudoers; then
        #Adding rules in sudoers file that users can not use those commands.
        echo $myPassword | echo "%$group ALL=(ALL) ${restrictedCommands}" | sudo -S tee -a /etc/sudoers
    fi

    if ! echo $myPassword |sudo -S grep -q "^%$group ALL=(ALL) ${networkAdapterCommands}" /etc/sudoers; then
        #Adding rules in sudoers file that users can not run those commands for .
        echo "%$group ALL=(ALL) ${networkAdapterCommands}" | sudo -S tee -a /etc/sudoers
    fi
done



#this is the common directory i have created it inside the Boss user direcotry

if [ ! -d "/home/Boss/common_directory_for_all" ]; then
    echo $myPassword | sudo -S mkdir /home/Boss/common_directory_for_all
else
    echo "Directory already exists. No action taken."
fi
#adding sticky bit here, that does mean they can create and delete the file, but only their own file.
echo $myPassword | sudo -S chmod -R 1777 /home/Boss/common_directory_for_all
#-R flag is for recursive permissions, d is default ACl, that does mean the ACL will be applied for the new directory and file as well.
echo $myPassword | sudo -S setfacl -Rdm u::rwX,g::rwX,o::rwX /home/Boss/common_directory_for_all \
&& sudo -S chmod g+s /home/Boss/common_directory_for_all


#Preventing removing or updating any file inside /usr/bin directory
#With +i flag i am making the bin dir and it's content immutable. With -i flag permission can be removed.

immDir="/home/Boss/common_directory_for_all/immutable_dir"
if [ -d "$immDir" ]; then
    # Check if the directory is already immutable
    if lsattr "$immDir" | grep -q 'i'; then
        echo "Directory '$immDir' is already immutable. No action taken."
    else
        echo "Directory '$immDir' exists but is not immutable. Making it immutable..."
        echo "$myPassword" | sudo -S chattr +i "$immDir"
    fi
else
    echo "Directory '$immDir' does not exist. Creating it and making it immutable..."
    echo "$myPassword" | sudo -S mkdir "$immDir"
    echo "$myPassword" | sudo -S chattr +i "$immDir"
fi
# I am running this script On behalf of user sharfuzzaman, This is my Other user as well as sudo user
#and own this directory by GodMode


cd /home/Boss/common_directory_for_all/
touch sajib
echo $myPassword | sudo -S chown -R GodMode:GodMode /home/Boss/common_directory_for_all/sajib
echo "Sajib created by sharfuzzaman (other user)is now own by the GodMode user"
ls -l /home/Boss/common_directory_for_all/

#This is the directory of Boss (Under CEO  & Sudo Groups) where administartion group will access in a particular direcotry

echo $myPassword | sudo -S mkdir /home/Boss/directory_for_administration_group \
&& sudo -S chown -R Boss:"${groupNames[3]}" /home/Boss/directory_for_administration_group \
&& sudo -S setfacl -R -m "u::rwx,g::rwx,g:"${groupNames[0]}":rwx,m::rwx,o::---" /home/Boss/directory_for_administration_group \
&& sudo -S chmod g+s /home/Boss/directory_for_administration_group
ls -l /home/Boss/directory_for_administration_group

#here i am updating the password policy where when someone will create new user it will effect for them and when they will update the password
#i am deleting this default=ignore manually' from this section [success=1 default=ignore]' from /etc/pam.d/common-password this file.

passwordPolicy="minlen=8 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1"
echo "$myPassword" | sudo -S cp /etc/pam.d/common-password /etc/pam.d/common-password.backup

# Here i am checking is passowrd policy already exists
if grep -q "^password[[:space:]].*pam_unix\.so.*$passwordPolicy$" /etc/pam.d/common-password; then
    echo "Password policy is already set."
else
    echo "$myPassword" | sudo -S sed -i "/^password.*pam_unix.so/s/$/ $passwordPolicy/" /etc/pam.d/common-password
    #After running the sed command '$?' this contains the exit status, if the modification is successful and exit itt returns 0
    if [ $? -ne 0 ]; then
        echo "Error: Failed to update password policy in common-password file."
        exit 1
    else
        echo "Password Policy is set SUCCESSFULLY"
    fi
fi

#Password will be invalid after 90 days.
echo "$myPassword" | sudo -S chage -M 90 "$(whoami)"
if [ $? -ne 0 ]; then
    echo "Error: Failed to change password maximum age."
fi


#Activating the linux rsyslog
RSYSLOG_CONF="/etc/rsyslog.conf"

# UDP syslog uncommenting
if grep -q "^module(load=\"imudp\")" "$RSYSLOG_CONF" && grep -q "^input(type=\"imudp\" port=\"514\")" "$RSYSLOG_CONF"; then
    echo "UDP syslog reception already uncommented."
else
    echo $myPassword | sudo -S sed -i 's/^#module(load="imudp")/module(load="imudp")/' "$RSYSLOG_CONF" \
    && sudo -S sed -i 's/^#input(type="imudp" port="514")/input(type="imudp" port="514")/' "$RSYSLOG_CONF"
fi

# TCP syslog uncommenting
if grep -q "^module(load=\"imtcp\")" "$RSYSLOG_CONF" && grep -q "^input(type=\"imtcp\" port=\"514\")" "$RSYSLOG_CONF"; then
    echo "TCP syslog reception already uncommented."
else
    echo $myPassword | sudo -S sed -i 's/^#module(load="imtcp")/module(load="imtcp")/' "$RSYSLOG_CONF" \
    && sudo -S sed -i 's/^#input(type="imtcp" port="514")/input(type="imtcp" port="514")/' "$RSYSLOG_CONF"
fi

# Restart rsyslog service

echo $myPassword | sudo -S service rsyslog restart \
&& sudo -S netstat -tuln | grep 514


# for view the log from the last we use below command
# echo $myPassword | sudo -S tail -f /var/log/syslog


#Configuring privileged users logging and sessions

# By default linux maintain privileged user (sudo) logging in /var/log/auth.log file

logDir="/var/log/sudo_sessions/"
logFile="$logDir/sudo_$(date +%Y%m%d_%H%M%S)_$SUDO_USER.log"

# Check if the log file already exists
if [ -f "$logFile" ]; then
    echo "Log file already exists: $logfile"
else
    if groups $SUDO_USER | grep &>/dev/null '\bsudo\b'; then
        echo "$myPassword" | sudo -S mkdir -p "$logDir" \
        && sudo -S chmod 700 "$logDir" \
        && sudo -S script -f -a -q "$logFile"
    else
        echo "You are not authorized to use sudo."
    fi
fi