#!/bin/sh

. vnet.subr

sendextraflags=$@

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

	# returns the jail to run test servers in and the interface scapy needs
	# to capture on for tests
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
	outer=$(vnet_mkepair)
	inner=$(vnet_mkepair)

	ethaddroutera=`ifconfig ${outer}a |  grep ether | awk '{print $2}'`
	ethaddrinnera=`ifconfig ${inner}a |  grep ether | awk '{print $2}'`
	ethaddrinnerb=`ifconfig ${inner}b |  grep ether | awk '{print $2}'`

	ifconfig ${outer}a 192.0.2.2/24 up
	route -q add -net 192.51.100.0/24 192.0.2.1

	vnet_mkjail tolbooth ${outer}b ${inner}b

	jexec tolbooth sysctl net.inet.ip.forwarding=1 > /dev/null

	jexec tolbooth ifconfig ${outer}b 192.0.2.1/24 up
	jexec tolbooth ifconfig ${inner}b 192.51.100.1/24 up
	jexec tolbooth arp -s 192.0.2.2 $ethaddroutera
	jexec tolbooth arp -s 192.51.100.2 $ethaddrinnera

	#jexec tolbooth route add -net 192.0.2.0/24 192.0.2.1
	#jexec tolbooth route add -net 192.51.100.0/24 192.51.100.1

	vnet_mkjail bassrock ${inner}a

	jexec bassrock ifconfig ${inner}a 192.51.100.2/24 up
	jexec bassrock arp -s 192.51.100.1 $ethaddrinnerb
	jexec bassrock route -q add -net 192.0.2.0/24 192.51.100.1

	disable_udp_options tolbooth
	disable_udp_options bassrock

	#drop_local_icmp_unreach 192.51.100.2

	# returns the jail to run test servers in and the interface scapy needs
	# to capture on for tests
	echo bassrock ${outer}a
}

cleanup()
{
	#ipfw -qy flush
	# sleep before trying to tidy up to see if this alleviates the panics
	sleep 5
	vnet_cleanup
}

enable_udp_options()
{
	jexec $1 sysctl net.inet.udp.process_udp_options=1 > /dev/null
}

disable_udp_options()
{
	jexec $1 sysctl net.inet.udp.process_udp_options=0 > /dev/null
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
	fi
}

run_tests()
{
	tests=$1

	localaddr="192.0.2.2"
	routerlocaladdr="192.0.2.1"
	routerremoteaddr="192.51.100.1"
	remoteaddr="192.51.100.2"

	#
	#
	# Simple Network Tests
	#
	#
	set `setup_simple`
	remotejail=$1
	testif=$2

	#echo "Remote jail: $remotejail test interface: $testif"
	pingtest $localaddr
	pingtest $routerlocaladdr

	#echo "simple network set up and ping works, press enter to continue"
	#read throwaway

	echo "running tests in simple network: $tests"
	for test in $tests
	do
		$test $remotejail $testif $localaddr $SRCPORT $routerlocaladdr $DSTPORT
	done

	cleanup

	#
	#
	# Router Network Tests
	#
	#
	set `setup_routed`
	remotejail=$1
	testif=$2

	#echo "Remote jail: $remotejail test interface: $testif"
	pingtest $localaddr
	pingtest $routerlocaladdr
	pingtest $routerremoteaddr
	pingtest $remoteaddr

	#echo "routed network set up and ping works, press enter to continue"
	#read throwaway

	echo "running tests in routed network: $tests"
	for test in $tests
	do
		$test $remotejail $testif $localaddr $SRCPORT $remoteaddr $DSTPORT
	done

	cleanup
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

	cmd="/home/tj/udpoptions-tools/scapy-tests/sendoptions.py -e icmponly -i $testif -s $addrs $udpoptions $sendextraflags"
	test_run "send->icmponly" 0 "$cmd"

	jexec $remotejail /home/tj/udpoptions-tools/usertools/echoserver.bin > /dev/null &
	echoserverpid=$!
	cmd="/home/tj/udpoptions-tools/scapy-tests/sendoptions.py -e nooptions -i $testif -s $addrs $udpoptions $sendextraflags"
	test_run "send->nooptions" 0 "$cmd"
	kill $echoserverpid

	# test echo server with minimal udp options
	enable_udp_options $remotejail
	jexec $remotejail /home/tj/udpoptions-tools/usertools/echoserver.bin > /dev/null &
	echoserverpid=$!
	cmd="/home/tj/udpoptions-tools/scapy-tests/sendoptions.py -e options -i $testif -s $addrs $udpoptions $sendextraflags"
	test_run "send->options" 0 "$cmd"
	kill $echoserverpid
	disable_udp_options $remotejail

}

# emulate kyua test for now
test_run()
{
        testname=$1
        expect=$2
        cmd=$3

        python3 $cmd

        result=$?

        if [ $result -ne $expect ]
        then
                printf "test $testname failed expected $expect got $result\n"
                printf "test:\t $testname expecting $expect running command $cmd\n"
        else
                printf "test $testname passed\n"
        fi
}

compile_tools()
{
	cd /home/tj/udpoptions-tools/usertools/

	for x in *.c
	do
		cc $x -o `basename $x .c`.bin
	done

	cd -
}

kldload if_epair
compile_tools
run_tests test_minimum_udpoptions
