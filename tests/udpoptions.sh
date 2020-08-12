. vnet.subr

#	  +-------- host --------+
#	  |                      |
#	  |  +--+       +------+ |
#	  |  |tp|------>| echo | |
#	  |  +--+       +-jail-+ |
#	  +----------------------+
#	   epairXa       epairXb
#	 192.0.2.2   192.0.2.1
# 
# epair:     outer
# jail:                   zeist
#
setup_simple() 
{
	echo "setting up simple testnetwork"
	outer=$(vnet_mkepair)
	ifconfig ${outer}a 192.0.2.2/24 up

	vnet_mkjail zeist ${outer}b 
	jexec zeist ifconfig ${outer}b 192.0.2.1/24 up

	disable_udp_options zeist
	#drop_local_icmp_unreach 192.0.2.2

	echo zeist
}

#	  +--------------- host -----------------+
#	  |                                      |
#	  |  +--+       +--------+      +------+ |
#	  |  |tp|<----->| router |<---->| echo | |
#	  |  +--+       +--jail--+      +-jail-+ |
#	  +--------------------------------------+
#	   epairXa       epairXb        epairNa
#	 192.0.2.2   192.0.2.1     192.51.100.2
#			 epairNb
#	    	       192.51.100.1      
# epair:     outer                        inner
# jail:                 tolbooth        bassrock
#
setup_routed() 
{
	echo "setting routed test network"
	outer=$(vnet_mkepair)
	inner=$(vnet_mkepair)

	ethaddroutera=`ifconfig ${outer}a |  grep ether | awk '{print $2}'`
	ethaddrinnera=`ifconfig ${inner}a |  grep ether | awk '{print $2}'`
	ethaddrinnerb=`ifconfig ${inner}b |  grep ether | awk '{print $2}'`

	echo $ethaddroutera
	echo $ethaddrinnera
	echo $ethaddrinnerb

	ifconfig ${outer}a 192.0.2.2/24 up

	vnet_mkjail tolbooth ${outer}b ${inner}b

	jexec tolbooth sysctl net.inet.ip.forwarding=1

	jexec tolbooth ifconfig ${outer}b 192.0.2.1/24 up
	jexec tolbooth ifconfig ${inner}b 192.51.100.1/24 up

	jexec tolbooth arp -s 192.0.2.2 $ethaddroutera
	jexec tolbooth arp -s 192.51.100.2 $ethaddrinnera

	#jexec tolbooth route add -net 192.0.2.0/24 192.0.2.1
	#jexec tolbooth route add -net 192.51.100.0/24 192.51.100.1

	vnet_mkjail bassrock ${inner}a
	jexec bassrock ifconfig ${inner}a 192.51.100.2/24 up
	jexec bassrock arp -s 192.51.100.1 $ethaddrouterb
	#jexec bassrock route add default 192.51.100.1

	disable_udp_options tolbooth
	disable_udp_options bassrock

	#drop_local_icmp_unreach 192.51.100.2

	echo tolbooth bassrock
}

cleanup()
{
	#ipfw -qy flush
	vnet_cleanup
}

enable_udp_options()
{
	jexec $1 sysctl net.inet.udp.process_udp_options=1
}

disable_udp_options()
{
	jexec $1 sysctl net.inet.udp.process_udp_options=0
}

# drop locally generated icmp unreach so scapy processes don't reply with it
drop_local_icmp_unreach()
{
	ipfw table 1 add $1
	ipfw add 00200 deny icmp from me to "table(1)" icmptypes 3
	#jexec $1 ipfw add 00200 deny icmp from me to "table(1)" via vtnet0 icmptypes 3
}

pingtest()
{
	ping -c 1 -t 1 $1 > /dev/null
	if [ $? -ne 0 ]
	then
	        echo "error pinging $1"
		exit
	else
	        echo "success pinging $1"
	fi
}

run_tests()
{
	localif="192.0.2.2"
	routerlocalif="192.0.2.1"
	routerremoteif="192.51.100.1"
	remoteif="192.51.100.2"

	setup_simple
	pingtest $localif
	pingtest $routerlocalif
	echo "tidying up simple test network"
	cleanup

	setup_routed
	pingtest $localif
	pingtest $routerlocalif
	pingtest $routerremoteif
	pingtest $remoteif
	echo "tidying up routed test network"
	cleanup
}

run_tests
