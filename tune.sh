#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
	echo "脚本需要root运行." 1>&2
	exit 1
fi

## Text colors and styles
info() {
	echo -e "\e[92m$1\e[0m"
}
info_2() {
	echo -e "\e[94m$1\e[0m"
}
fail() {
	echo -e "\e[91m$1\e[0m" 1>&2
}
seperator() {
	echo -e "\n"
	echo $(printf '%*s' "$(tput cols)" | tr ' ' '=')
}

## Loading animation
BLA_classic=( 0.25 '-' "\\" '|' '/' )
declare -a BLA_active_loading_animation

BLA::play_loading_animation_loop() {
  while true ; do
    for frame in "${BLA_active_loading_animation[@]}" ; do
      printf "\r%s" "${frame}"
      sleep "${BLA_loading_animation_frame_interval}"
    done
  done
}

BLA::start_loading_animation() {
  BLA_active_loading_animation=( "${@}" )
  # Extract the delay between each frame from array BLA_active_loading_animation
  BLA_loading_animation_frame_interval="${BLA_active_loading_animation[0]}"
  unset "BLA_active_loading_animation[0]"
  tput civis # Hide the terminal cursor
  BLA::play_loading_animation_loop &
  BLA_loading_animation_pid="${!}"
}

BLA::stop_loading_animation() {
  kill "${BLA_loading_animation_pid}" &> /dev/null
  printf "\n"
  tput cnorm # Restore the terminal cursor
}
# Run BLA::stop_loading_animation if the script is interrupted
trap BLA::stop_loading_animation SIGINT

## System Info
sysinfo_(){
	#Linux Distro Version
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		os=$NAME
		ver=$VERSION_ID
	elif type lsb_release >/dev/null 2>&1; then
		os=$(lsb_release -si)
		ver=$(lsb_release -sr)
	elif [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		os=$DISTRIB_ID
		ver=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ]; then
		os=Debian
		ver=$(cat /etc/debian_version)
	elif [ -f /etc/redhat-release ]; then
		os=Redhat
	else
		os=$(uname -s)
		ver=$(uname -r)
	fi

	#Virtualization Technology
	if [ $(systemd-detect-virt) != "none" ]; then	#Check virtualization using systemd-detect-virt
		virt_tech=$(systemd-detect-virt)
	fi

	#Memory Size
	mem_size=$(free -m | grep Mem | awk '{print $2}')

	#Network interface
	nic=$(ip addr | grep 'state UP' | awk '{print $2}' | sed 's/.$//' | cut -d'@' -f1)

	return 0
}

## Bandwidth Limit
bandwidth_limit_() {
	# Install vnstat if not already installed
	if ! [ -x "$(command -v vnstat)" ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install vnstat -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install vnstat -y
		fi
	fi
	if ! [ -x "$(command -v vnstat)" ]; then
		fail "vnstat 安装失败"
		return 1
	fi
	sed -i "s/Interface \"\"/Interface \"$nic\"/" /etc/vnstat.conf
	cat << EOF > .bandwidth_limit.sh
#!/bin/bash

# Set the bandwidth threshold
THRESHOLD=$threshold

# Get the current month's total bandwidth usage in MB
CURRENT_USAGE=\$(vnstat --month | grep "\$(date +%b)" | awk '{print \$3}')

# Check if the current usage exceeds the threshold
if [[ "\$CURRENT_USAGE" -gt "\$THRESHOLD" ]]; then
	# Shutdown command
	sudo shutdown -h now
fi
EOF
	chmod +x .bandwidth_limit.sh
	# Add the script to cron
	crontab -l | { cat; echo "* * * * * /root/.bandwidth_limit.sh"; } | crontab -
	return 0
}

## SSH Secure
ssh_secure_() {
	# Ask for the new SSH port
	read -p "新SSH端口: " new_ssh_port

	# Check if the input is a valid number
	while ! [[ $new_ssh_port =~ ^[0-9]+$ ]]; do
		echo "请输入一个有效的端口号"
		read -p "新SSH端口: " new_ssh_port
	done

	# Add the new SSH port without removing the existing one
	echo "Port $new_ssh_port" >> /etc/ssh/sshd_config

	# Restart SSH service to apply changes
	systemctl restart sshd

	# Make sure the new SSH port is open
	read -p "你能使用新SSH端口登录吗? (y/n): " can_login
	while ! [[ $can_login =~ ^[YyNn]$ ]]; do
		echo "请输入y或n"
		read -p "你能使用新SSH端口登录吗? (y/n): " can_login
	done
	if [[ $can_login =~ ^[Yy]$ ]]; then
		# Removing the original SSH port
		sed -i "0,/Port /s//Old&/" /etc/ssh/sshd_config
		sed -i '/OldPort/d' /etc/ssh/sshd_config

		# Restart SSH service to apply final changes
		systemctl restart sshd
		info_2 "旧SSH端口已关闭"
	else
		# Revert the changes
		sed -i ':a;N;$!ba;s/\(.*\)Port /\1OldPort /' /etc/ssh/sshd_config
		sed -i '/OldPort/d' /etc/ssh/sshd_config
		systemctl restart sshd
		fail "新SSH端口 $new_ssh_port 未打开"
		fail "旧SSH端口未关闭"
	fi

	#Disble Root Password Login
	keys="/root/.ssh/authorized_keys"

	if ! [ -s "$keys" ]; then
		fail "SSH 钥匙不存在"
	else
		sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
		sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
		unset can_login
		read -p "你能使用SSH密钥登录吗? (y/n): " can_login
		while ! [[ $can_login =~ ^[YyNn]$ ]]; do
			echo "请输入y或n"
			read -p "你能使用SSH密钥登录吗? (y/n): " can_login
		done
		if [[ $can_login =~ ^[Yy]$ ]]; then
			# Disable password login
			sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
			sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
			sed -i 's/^PermitRootLogin without-password/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
			systemctl restart sshd
			info_2 "Root密码登录已禁用"
		else
			fail "SSH密钥登录未启用"
		fi
	fi
}

## Update
update_() {
	if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
		apt-get update -y && apt-get upgrade -y
	elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
		yum update -y
	fi
}

## Install Tuned
tuned_() {
    if [ -z $(which tuned) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install tuned -y
			if [ $? -ne 0 ]; then
				fail "Tuned Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install tuned -y
			if [ $? -ne 0 ]; then
				fail "Tuned Installation Failed"
				return 1
			fi
		fi
	fi
	return 0
}

## File Open Limit
set_file_open_limit_() {
    cat << EOF >>/etc/security/limits.conf
## Hard limit for max opened files
root        hard nofile 1048576
## Soft limit for max opened files
root       soft nofile 1048576
EOF
	return 0
}

## Ring Buffer
set_ring_buffer_() {
	if [ -z $(which ethtool) ]; then
		apt-get -y install ethtool
		if [ $? -ne 0 ]; then
			fail "Ethtool Installation Failed"
			return 1
		fi
	fi
    ethtool -G $nic rx 1024
	if [ $? -ne 0 ]; then
		fail "Ring Buffer Setting Failed"
		return 1
	fi
    sleep 1
    ethtool -G $nic tx 2048
	if [ $? -ne 0 ]; then
		fail "Ring Buffer Setting Failed"
		return 1
	fi
    sleep 1
	return 0
}

## Disable TSO
disable_tso_() {
	if [ -z $(which ethtool) ]; then
		apt-get -y install ethtool
		if [ $? -ne 0 ]; then
			fail "Ethtool Installation Failed"
			return 1
		fi
	fi
	ethtool -K $nic tso off gso off gro off
	sleep 1
	return 0
}

## TCP Queue Length
set_txqueuelen_() {
	if [ -z $(which net-tools) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install net-tools -qqy
			if [ $? -ne 0 ]; then
				fail "Net-tools Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install net-tools -qqy
			if [ $? -ne 0 ]; then
				fail "Net-tools Installation Failed"
				return 1
			fi
		fi
	fi
    ifconfig $nic txqueuelen 10000
    sleep 1
	return 0
}

## Initial Congestion Window
set_initial_congestion_window_() {
    iproute=$(ip -o -4 route show to default)
    ip route change $iproute initcwnd 100 initrwnd 100
	return 0
}

## Kernel Settings
kernel_settings_() {
	# Set variables based on memory size
	if [ $mem_size -le 128 ]; then	# 128MB or less
		adv_win_scale=3
		rmem_default=262144
		rmem_max=16777216
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=16777216
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=5
		dirty_ratio=20
		writeback_centisecs=100
		expire_centisecs=100
		swappiness=60
	elif [ $mem_size -le 512 ]; then	# 512MB or less
		adv_win_scale=2
		rmem_default=262144
		rmem_max=33554432
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=33554432
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=5
		dirty_ratio=20
		writeback_centisecs=300
		expire_centisecs=500
		swappiness=60
	elif [ $mem_size -le 1024 ]; then	# 1GB or less
		adv_win_scale=1
		rmem_default=262144
		rmem_max=33554432
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=33554432
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=10
		dirty_ratio=30
		writeback_centisecs=1000
		expire_centisecs=6000
		swappiness=20
	else	# 1GB or more
		adv_win_scale=1
		rmem_default=262144
		rmem_max=67108864
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=67108864
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=10
		dirty_ratio=30
		writeback_centisecs=1000
		expire_centisecs=6000
		swappiness=10
	fi
	
	cat << EOF > /etc/sysctl.conf
#### Network Security Settings
# Turn on Source Address Verification in all interfaces to prevent some spoofing attacks
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1

# Protect a server against SYN flood attacks
#Enable TCP/IP SYN cookies to 
net.ipv4.tcp_syncookies=1
#Increase the maximum queue length of completely established sockets waiting to be accepted
# The net.core.somaxconn parameter is the maximum queue length of completely established sockets waiting to be accepted.
net.core.somaxconn=10000
#Increase the maximum queue length of incomplete sockets i.e. half-open connection
# The net.ipv4.tcp_max_syn_backlog parameter is the maximum queue length of incomplete sockets.
# NOTE: THis value should not be above "net.core.somaxconn", since that is also a hard open limit of maximum queue length of incomplete sockets/
# Kernel will take the lower one out of two as the maximum queue length of incomplete sockets
net.ipv4.tcp_max_syn_backlog=10000
#Increase the maximal number of TCP sockets not attached to any user file handle (i.e. orphaned connections), held by system.
# NOTE: each orphan eats up to ~64K of unswappable memory
# The net.ipv4.tcp_max_orphans parameter is the maximum number of TCP sockets not attached to any user file handle.
net.ipv4.tcp_max_orphans=10000
#Quickly Discard locally closed TCP connection
net.ipv4.tcp_orphan_retries = 2

# Protect a server against ack loop" DoS attacks
net.ipv4.tcp_invalid_ratelimit=500

# Disable packet forwarding
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0

# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0

# Do not accept IP source route packets (we are not a router)
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martian Packets
net.ipv4.conf.all.log_martians = 1

# Protect Against TCP TIME-WAIT Assassination
net.ipv4.tcp_rfc1337 = 0


### SoftIRQ Misses
# SoftIRQs are used for tasks that are not time-critical, such as network packet processing.
# Check the number of softIRQ misses
# cat /proc/net/softnet_stat
# Pay close attention to the following columns:
# Column-01: packet_process: Packet processed by each CPU.
# Column-02: packet_drop: Packets dropped.
# Column-03: time_squeeze: net_rx_action.

# Column-02: packet_drop: Packets dropped.
# Packet_drop indicates that the NIC is dropping packets due to a lack of backlog space.
# Solution 1. : Increase the size of the NIC’s backlog
# The backlog is the number of packets that the NIC can store in its backlog queue.
# Increase the backlog size to 10000
net.core.netdev_max_backlog=10000

# Column-03: time_squeeze: net_rx_action
# Time_squeeze: net_rx_action counter indicates the number of times the CPU has to return prematurely without draining the queue.
# This is most likely weak causing by weak CPU in a high-traffic environment.
# Solution 2. : Increasing net.core.netdev_budget and net.core.netdev_budget_usecs
# The netdev_budget parameter is the maximum number of packets that the kernel will process in a single softIRQ.
# The netdev_budget_usecs parameter is the maximum amount of time that the kernel will spend processing packets in a single softIRQ.
# To increase the netdev_budget and netdev_budget_usecs values, you can use the sysctl command.
net.core.netdev_budget=50000
net.core.netdev_budget_usecs=8000
# NOTE: Setting a high number might cause CPU to stall and end in poor overall performance
# NOTE: Increasing the number of Query Channels (RSS) can also help with the issue.

# Low latency busy poll timeout for socket reads
# NOTE: Not supported by most NIC
#net.core.busy_read=50
# Low latency busy poll timeout for poll and select
# NOTE: Not supported by most NIC
#net.core.busy_poll=50


### Socket buffer size
#Congestion window
# The congestion window is the amount of data that the sender can send before it must wait for an acknowledgment from the receiver.
# The congestion window is limited by 2 things. 
#   The receiver’s advertised window size, which is the amount of data that the receiver is willing to accept
#   And also the size of the sending socket buffer on the sender’s end.

#How to determine the optimal congestion window
# The optimal congestion window size is determined by the bandwidth-delay product (BDP) of the network.
# The BDP is the amount of data that can be in transit in the network at any given time.
# It is calculated by multiplying the bandwidth of the network by the round-trip time (RTT) of the network.
# The optimal congestion window size is the BDP of the network.
# You can use this site to calculate the BDP of your network: https://www.speedguide.net/bdp.php

#How to determine the Optimal Receive socket Buffer Size
# The optimal socket buffer size is determined by optimal congestion window and, in turn, also determined by the bandwidth-delay product (BDP) of the network.
# We have to make sure the advertised window size is not smaller than BDP to prevent underutilization of the network.
# The receive socket buffer space is shared between the application and kernel. /
#   TCP maintains part of the buffer as the TCP window, this is the size of the receive window advertised to the other end.  /
#   The rest of the space is used as the "application" buffer, used to isolate the network from scheduling and application latencies.
# The total receive socket buffer space is determined by net.ipv4.tcp_rmem and the portion of which is allocated as "application" buffer is determined by net.ipv4.tcp_adv_win_scale.
net.ipv4.tcp_adv_win_scale=$adv_win_scale
net.core.rmem_default=$rmem_default
net.core.rmem_max=$rmem_max
net.ipv4.tcp_rmem=$tcp_rmem

#How to determine the Optimal Send socket Buffer Size
# Send socket buffer size determine the maximum amount of data that the application can send before needing to wait for an acknowledgment (ACK) from the receiver
# As you may have recalled, it is bascially the definition of congestion window
# Therefore it is important to make sure the send buffer space is not smaller than BDP to prevent underutilization of the network.

# You can set send socket buffer size using the sysctl command.
net.core.wmem_default=$wmem_default
net.core.wmem_max=$wmem_max
net.ipv4.tcp_wmem=$tcp_wmem

#Relationship between net.core.r/wmem and net.ipv4.tcp_r/wmem
# net.core.r/wmem is the default buffer size for all protocols, including TCP
# And net.ipv4.tcp_r/wmem is the buffer size for TCP only

#net.ipv4.tcp_rmem = tcp_rmem_min tcp_rmem_default tcp_rmem_max
# Vector of 3 INTEGERs: min, default, max
#	min: Minimal size of receive buffer used by TCP sockets.
#	It is guaranteed to each TCP socket, even under moderate memory
#	pressure.
#
#	default: initial size of receive buffer used by TCP sockets.
#	This value overrides net.core.rmem_default used by other protocols.
#
#	max: maximal size of receive buffer allowed for automatically
#	selected receiver buffers for TCP socket. This value does not override
#	net.core.rmem_max.  Calling setsockopt() with SO_RCVBUF disables
#	automatic tuning of that socket's receive buffer size, in which
#	case this value is ignored.

#net.ipv4.tcp_wmem = tcp_wmem_min tcp_wmem_default tcp_wmem_max
# Vector of 3 INTEGERs: min, default, max
#	min: Amount of memory reserved for send buffers for TCP sockets.
#	Each TCP socket has rights to use it due to fact of its birth.
#
#	default: initial size of send buffer used by TCP sockets.  This
#	value overrides net.core.wmem_default used by other protocols.
#	It is usually lower than net.core.wmem_default.
#
#	max: Maximal amount of memory allowed for automatically tuned
#	send buffers for TCP sockets. This value does not override
#	net.core.wmem_max.  Calling setsockopt() with SO_SNDBUF disables
#	automatic tuning of that socket's send buffer size, in which case
#	this value is ignored.

# Because of the varying internet condition, not every connection is going to reach the optimal congestion window size, and that’s okay.
# To prevent slow link from using more than necessary amount of memory, we can use the following sysctl settings to enable receive buffer auto-tuning
net.ipv4.tcp_moderate_rcvbuf = 1


# Allows the use of a large window (> 64 kB) on a TCP connection, this is the default settings for most modern kernel
net.ipv4.tcp_window_scaling = 1

# Set maximum window size to MAX_TCP_WINDOW i.e. 32767 in times there is no received window scaling option
net.ipv4.tcp_workaround_signed_windows = 1


### MTU Discovery
# Allow Path MTU Discovery
net.ipv4.ip_no_pmtu_disc = 0

# Enable TCP Packetization-Layer Path, and use initial MSS of tcp_base_mss
net.ipv4.tcp_mtu_probing = 2

# Starting MSS used in Path MTU discovery
net.ipv4.tcp_base_mss = 1460

#  Minimum MSS used in connection, cap it to this value even if advertised ADVMSS option is even lower
net.ipv4.tcp_min_snd_mss = 536

# Maximum memory used to reassemble IP fragments
net.ipv4.ipfrag_high_threshold = 8388608


### Account for a high RTT lossy network
# Enable selective acknowledgments 
net.ipv4.tcp_sack = 1

# Allows TCP to send "duplicate" SACKs
net.ipv4.tcp_dsack = 1

# Enable Early Retransmit. ER lowers the threshold for triggering fast retransmit when the amount of outstanding data is small and when no previously unsent data can be transmitted
net.ipv4.tcp_early_retrans = 3

# Disable ECN to survive in a congested network
net.ipv4.tcp_ecn = 0

# Reordering level of packets in a TCP stream
# Initial reordering level of packets in a TCP stream. TCP stack can then dynamically adjust flow reordering level between this initial value and tcp_max_reordering
net.ipv4.tcp_reordering = 10
# Maximal reordering level of packets in a TCP stream
net.ipv4.tcp_max_reordering = 1000
# NOTE: An attempt to reduce the number of retransmissions due to packet reordering in a network. Which is common in a lossy network

# Enable F-RTO (Forward RTO-Recovery). Beneficial in networks where the RTT fluctuates 
net.ipv4.tcp_frto = 2

# Enable TCP Auto Corking
# When enabled, the TCP stack will automatically cork the socket when the application is not sending data fast enough
net.ipv4.tcp_autocorking = 1

# TCP Retry
# The number of times to retry before killing an alive TCP connection
net.ipv4.tcp_retries1 = 5
net.ipv4.tcp_retries2 = 20

# TCP Keepalive
# After $tcp_keepalive_time seconds of inactivity, TCP will send a keepalive probe every $tcp_keepalive_intvl to the other end. /
# After $tcp_keepalive_probes failed attempts, the connection will be closed
# In seconds, time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 7200
# In seconds, how frequently the probes are send out
net.ipv4.tcp_keepalive_intvl = 120
# How many keepalive probes TCP sends out, until it decides that the connection is broken
net.ipv4.tcp_keepalive_probes = 15

# SYN 
# Number of times SYNACKs for a passive TCP connection attempt will be retransmitted
net.ipv4.tcp_synack_retries = 10
# Number of times initial SYNs for an active TCP connection attempt	will be retransmitted
net.ipv4.tcp_syn_retries = 7


### To support more connections
#Solution 1. : Increase the maximum number of file descriptors
# The maximum number of connections that a server can handle is determined by the maximum number of file descriptors that the server can open.
fs.file-max=1000000
fs.nr_open=1000000

#Solution 2. : Increase the number of port that the kernel can allocate for outgoing connections
# The net.ipv4.ip_local_port_range parameter is the range of port numbers that the kernel can allocate for outgoing connections.
net.ipv4.ip_local_port_range="1024 65535"

#Solution 3. : Increase the maximum number of SYN_RECV sockets
# The net.ipv4.tcp_max_syn_recv parameter is the maximum number of SYN_RECV sockets.
net.ipv4.tcp_max_syn_recv=10000

#Solution 4. : Increase the maximum number of sockets in TIME_WAIT state
# The net.ipv4.tcp_max_tw_buckets parameter is the maximum number of sockets in TIME_WAIT state.
net.ipv4.tcp_max_tw_buckets=10000

#Solution 5. : Quickly discard sockets in the state FIN-WAIT-2
# The net.ipv4.tcp_fin_timeout parameter is the maximum time that a connection in the FIN-WAIT-2 state will stay open.
net.ipv4.tcp_fin_timeout=10


### Miscellaneous
# Enable TCP Fast Open
# TCP Fast Open (TFO) is an extension to speed up the opening of successive TCP connections between two endpoints
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 0

# The maximum amount of unsent bytes in TCP socket write queue, this is on top of the congestion window
net.ipv4.tcp_notsent_lowat = 131072

# Avoid falling back to slow start after a connection goes idle
net.ipv4.tcp_slow_start_after_idle = 0

# Disable timestamps
net.ipv4.tcp_timestamps = 0

# Save cache metrics on closing connections
net.ipv4.tcp_no_metrics_save = 0

## ARP table settings
# The maximum number of bytes which may be used by packets queued for each unresolved address by other network layers
net.ipv4.neigh.default.unres_qlen_bytes = 16777216

# Controls a per TCP socket cache of one socket buffer
# net.ipv4.tcp_rx_skb_cache=1


### Buffer and cache management
# Percentage of total system memory that can be filled with dirty pages /
# before the system starts writing them to disk in the background
vm.dirty_background_ratio = $background_ratio
# Percentage of total system memory that can be filled with dirty pages 
# before the system blocks any further writes /
# and forces the process that is generating dirty pages to write them to disk.
vm.dirty_ratio = $dirty_ratio

# The interval of when writes of dirty in-memory data are written out to disk. 
# It is expressed in centiseconds
vm.dirty_writeback_centisecs = $writeback_centisecs
# when dirty in-memory data is old enough to be eligible for writeout by the kernel flusher threads. 
# It is also expressed in centiseconds. 
vm.dirty_expire_centisecs = $expire_centisecs

# Avoid using swap as much as possible
vm.swappiness = $swappiness


### Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	sysctl -p
	return 0
}



## Tune
tune_() {
	tuned_
	set_file_open_limit_
	kernel_settings_

	if [ -z "$virt_tech" ]; then		#If not a virtual machine
		set_ring_buffer_
	else
		disable_tso_
	fi

	if [ -z "$virt_tech" ] || [ "$virt_tech" != "lxc" ]; then		#If not a LXC container
		set_txqueuelen_
		set_initial_congestion_window_
	fi
	return 0
}



## BBR
install_bbrx_() {
	#Check if $os is Set
	if [[ -z $os ]]; then
		# Linux Distro Version check
		if [ -f /etc/os-release ]; then
			. /etc/os-release
			os=$NAME
		elif type lsb_release >/dev/null 2>&1; then
			os=$(lsb_release -si)
		elif [ -f /etc/lsb-release ]; then
			. /etc/lsb-release
			os=$DISTRIB_ID
		elif [ -f /etc/debian_version ]; then
			os=Debian
		else
			os=$(uname -s)
		fi
	fi
	if [[ "$os" =~ "Debian" ]]; then
		if [ $(uname -m) == "x86_64" ]; then
			apt-get -y install linux-image-amd64 linux-headers-amd64
			if [ $? -ne 0 ]; then
				fail "BBR installation failed"
				return 1
			fi
		elif [ $(uname -m) == "aarch64" ]; then
			apt-get -y install linux-image-arm64 linux-headers-arm64
			if [ $? -ne 0 ]; then
				fail "BBR installation failed"
				return 1
			fi
		fi
	elif [[ "$os" =~ "Ubuntu" ]]; then
		apt-get -y install linux-image-generic linux-headers-generic
		if [ $? -ne 0 ]; then
			fail "BBR installation failed"
			return 1
		fi
	else
		fail "Unsupported OS"
		return 1
	fi
	wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRx/BBRx.sh && chmod +x BBRx.sh
	# Check if download fail
	if [ ! -f BBRx.sh ]; then
		fail "BBR download failed"
		return 1
	fi
    ## Install tweaked BBR automatically on reboot
    cat << EOF > /etc/systemd/system/bbrinstall.service
[Unit]
Description=BBRinstall
After=network.target

[Service]
Type=oneshot
ExecStart=/root/BBRx.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable bbrinstall.service
	return 0
}

install_bbrv3_() {
	if [ $(uname -m) == "x86_64" ]; then
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/x86_64/linux-headers-6.4.0+-amd64.deb
		if [ ! -f linux-headers-6.4.0+-amd64.deb ]; then
			fail "BBRv3 download failed"
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/x86_64/linux-image-6.4.0+-amd64.deb
		if [ ! -f linux-image-6.4.0+-amd64.deb ]; then
			fail "BBRv3 download failed"
			rm linux-headers-6.4.0+-amd64.deb
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/x86_64/linux-libc-dev_-6.4.0-amd64.deb
		if [ ! -f linux-libc-dev_-6.4.0-amd64.deb ]; then
			fail "BBRv3 download failed"
			rm linux-headers-6.4.0+-amd64.deb linux-image-6.4.0+-amd64.deb
			return 1
		fi
		apt install ./linux-headers-6.4.0+-amd64.deb ./linux-image-6.4.0+-amd64.deb ./linux-libc-dev_-6.4.0-amd64.deb
		# Clean up
		rm linux-headers-6.4.0+-amd64.deb linux-image-6.4.0+-amd64.deb linux-libc-dev_-6.4.0-amd64.deb
	elif [ $(uname -m) == "aarch64" ]; then
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/ARM64/linux-headers-6.4.0+-arm64.deb
		if [ ! -f linux-headers-6.4.0+-arm64.deb ]; then
			fail "BBRv3 download failed"
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/ARM64/linux-image-6.4.0+-arm64.deb
		if [ ! -f linux-image-6.4.0+-arm64.deb ]; then
			fail "BBRv3 download failed"
			rm linux-headers-6.4.0+-arm64.deb
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/ARM64/linux-libc-dev_-6.4.0-arm64.deb
		if [ ! -f linux-libc-dev_-6.4.0-arm64.deb ]; then
			fail "BBRv3 download failed"
			rm linux-headers-6.4.0+-arm64.deb linux-image-6.4.0+-arm64.deb
			return 1
		fi
		apt install ./linux-headers-6.4.0+-arm64.deb ./linux-image-6.4.0+-arm64.deb ./linux-libc-dev_-6.4.0-arm64.deb
		# Clean up
		rm linux-headers-6.4.0+-arm64.deb linux-image-6.4.0+-arm64.deb linux-libc-dev_-6.4.0-arm64.deb
	else
		fail "$(uname -m) is not supported"
	fi
	return 0
}

## Main
sysinfo_
update_
while getopts "bstx3h" opt; do
	case ${opt} in
		b )
			# Set the bandwidth threshold in GB
			info_2 "输入每月带库上限 （以GB为单位）："
			read threshold
			while true
			do
				if ! [[ "$threshold" =~ ^[0-9]+$ ]]; then
					fail "请输入数字"
					info_2 "输入每月带库上限 （以GB为单位）："
					read threshold
				else
					break
				fi
			done

			# Convert the threshold to MB
			threshold=$(("$threshold*1024"))
			seperator
			info "设置每月带库上限"
			bandwidth_limit_
			;;
		s )
			seperator
			info "SSH登录安全設定"
			ssh_secure_
			;;
		t )
			seperator
			info "调整系统参数"
			BLA::start_loading_animation "${BLA_classic[@]}"
			tune_ &> /dev/null
			BLA::stop_loading_animation
			;;
		x )
			seperator
			info "安装BBRx"
			if [[ "$virt_tech" =~ "LXC" ]] || [[ "$virt_tech" =~ "lxc" ]]; then
				fail "不支持LXC"
				exit 1
			fi
			BLA::start_loading_animation "${BLA_classic[@]}"
			install_bbrx_ &> /dev/null
			BLA::stop_loading_animation
			;;
		3 )
			seperator
			info "安装BBRv3"
			if [[ "$virt_tech" =~ "LXC" ]] || [[ "$virt_tech" =~ "lxc" ]]; then
				fail "不支持LXC"
				exit 1
			fi
			BLA::start_loading_animation "${BLA_classic[@]}"
			install_bbrv3_ &> /dev/null
			BLA::stop_loading_animation
			;;
		h )
			info "用法： ./tune.sh [选项]"
			info "选项："
			info "  -b  设置每月带库上限"
			info "  -s  SSH登录安全設定"
			info "  -t  调整系统参数"
			info "  -x  安装BBRx"
			info "  -3  安装BBRv3"
			info "  -h  显示此帮助信息"
			exit 0
			;;
		\? )
			info "Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
	esac

done