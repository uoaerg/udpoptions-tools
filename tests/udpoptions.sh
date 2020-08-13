. vnet.subr

# default variables used in tests
SRCPORT=2500
DSTPORT=7		# udp echo

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
	outer=$(vnet_mkepair)
	ifconfig ${outer}a 192.0.2.2/24 up

	vnet_mkjail zeist ${outer}b 
	jexec zeist ifconfig ${outer}b 192.0.2.1/24 up

	disable_udp_options zeist
	#drop_local_icmp_unreach 192.0.2.2

	echo zeist ${outer}a
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

	ifconfig ${outer}a 192.0.2.2/24 up
	route add -net 192.51.100.0/24 192.0.2.1

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
	jexec bassrock arp -s 192.51.100.1 $ethaddrinnerb
	jexec bassrock route add -net 192.0.2.0/24 192.51.100.1


	disable_udp_options tolbooth
	disable_udp_options bassrock

	#drop_local_icmp_unreach 192.51.100.2

	echo ERRORINTERFACENAMESHOULDBERETURNEDHERE
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
	tests=$1

	localaddr="192.0.2.2"
	routerlocaladdr="192.0.2.1"
	routerremoteaddr="192.51.100.1"
	remoteaddr="192.51.100.2"

	set `setup_simple`
	remotejail=$1
	testif=$2

	echo "Remote jail: $remotejail test interface: $testif"

	echo "Testing interfaces work with ping"
	pingtest $localaddr
	pingtest $routerlocaladdr

	echo "simple network set up and ping works, press enter to continue"
	read throwaway

	echo "running tests"
	for test in $tests
	do
		$test $remotejail $testif $localaddr $SRCPORT $remoteaddr $DSTPORT
	done

	echo "tidying up simple test network"
	cleanup



#	setup_routed
#	pingtest $localaddr
#	pingtest $routerlocaladdr
#	pingtest $routerremoteaddr
#	pingtest $remoteaddr
#	echo "tidying up routed test network"
#	cleanup
}

test_minimum_udpoptions()
{	
	udpoptions="02 fd 00"
	#        ----- --
	#         ocs  eol
	remotejail=$1
	testif=$2
	shift
	shift
	addrs=$@

	expect=0
	python3 /home/tj/udpoptions-tools/scapy-tests/sendoptions.py -v -e silence -i $testif -s $addrs $udpoptions
	if [ $? -ne $expect ]
	then
		echo "test 'send->silence' failed expected $expect got $?"
	else
		echo "test 'send->silence' passed"
	fi

	echo_server_start $remotejail &
	echoserverpid=$!
	expect=0
	python3 /home/tj/udpoptions-tools/scapy-tests/sendoptions.py -v -e nooptions -i $testif -s $addrs $udpoptions
	if [ $? -ne $expect ]
	then
		echo "test 'send->no options' failed expected $expect got $?"
	else
		echo "test 'send->no options' passed"
	fi

	echo_server_stop $remotejail $echoserverpid

	echo_server_start $remotejail &
	echoserverpid=$!
	expect=0
	python3 /home/tj/udpoptions-tools/scapy-tests/sendoptions.py -v -e options -i $testif -s $addrs $udpoptions
	if [ $? -ne $expect ]
	then
		echo "test 'send->options' failed expected $expect got $?"
	else
		echo "test 'send->options' passed"
	fi

	echo_server_stop $remotejail $echoserverpid
}

# emulate kyua test for now
test_run()
{
	expect = $1
	shift

	$@

	if [ $? -ne $expect ]
	then
		echo "test $1 failed expected $expect got $?"
	fi
}

echo_server_start()
{	
	echoserverpath="/home/tj/udpoptions-tools/usertools/echoserver.bin"
	jexec $1 $echoserverpath &
	echo $!
}

echo_server_stop()
{
	jexec $1 kill $2
}

compile_tools()
{
	cd /home/tj/udpoptions-tools/usertools/

	for x in *.c
	do
		cc $x -o `basename $x .c`.bin
	done
}

compile_tools
run_tests test_minimum_udpoptions
