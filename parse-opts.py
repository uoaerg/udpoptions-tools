#!/usr/bin/env python3

import struct

UDPOPT_EOL = 0
UDPOPT_NOP = 1
UDPOPT_OCS = 2
UDPOPT_ACS = 3
UDPOPT_LITE = 4
UDPOPT_MSS = 5
UDPOPT_TIME = 6
UDPOPT_FRAG = 7
UDPOPT_AE = 8
UDPOPT_ECHOREQ = 9
UDPOPT_ECHORES = 10

UDPOLEN_EOL = 0
UDPOLEN_NOP = 0
UDPOLEN_OCS = 2
UDPOLEN_ACS = 4
UDPOLEN_LITE = 4
UDPOLEN_MSS = 4
UDPOLEN_TIME = 10
UDPOLEN_FRAG = 12
UDPOLEN_ECHOREQ = 0
UDPOLEN_ECHORES = 0

# parse udp options tlv into a dictionary
def udp_dooptions(buf):
	print("Processing {} bytes of UDP Options".format(len(buf))	)
	opts = {}
	cnt = len(buf)
	optlen = 0
	cp = 0

	while (cnt > 0):
		cnt = cnt - optlen
		cp = cp + optlen

		opt = buf[cp]
		if opt == UDPOPT_EOL:
			print("UDPOPT_EOL Stopping")
			optlen = 1
			return opts
		if opt == UDPOPT_NOP:
			optlen = 1
			print("UDPOPT_NOP")
			continue

		if opt == UDPOPT_OCS:
			print("UDPOPT_OCS")
			opts['UDPOPT_OCS'] = buf[cp+1]
			optlen = 2
			continue

		optlen = buf[cp+1]

		if opt == UDPOPT_MSS:      
			mss = struct.unpack("!h", buf[optlen:optlen+2])[0]
			opts['UDPOPT_MSS'] = mss
			print("UDPOPT_MSS {}".format(mss))

		if opt == UDPOPT_TIME:     
			tsval, tsecr = struct.unpack("!ii", buf[optlen:optlen+8])
			opts['UDPOPT_TIME'] = (tsval, tsecr)
			print("UDPOPT_TIME {} {}".format(tsval, tsecr))

def udp_addoptions(opts):

	optbuf = bytearray(100)

	# place the ocs
	optbuf[0] = UDPOPT_OCS
	optbuf[1] = 0

	optlen = 2
	
	if 'UDPOPT_TIME' in opts:
		optbuf[optlen] = UDPOPT_TIME
		optbuf[optlen+1] = UDPOLEN_TIME
		optlen = optlen + UDPOLEN_TIME

	if 'UDPOPT_MSS' in opts:
		optbuf[optlen] = UDPOPT_MSS
		optbuf[optlen+1] = UDPOLEN_MSS
		optlen = optlen + UDPOLEN_MSS

	#add a nop
	optbuf[optlen] = UDPOPT_NOP
	optlen = optlen + 1

	optbuf[optlen] = UDPOPT_EOL
	optlen = optlen + 1

	#optbuf[1] = osc(optbuf, optlen)

	return optbuf[:optlen]

if __name__ == "__main__":
	options = udp_dooptions(
		bytearray(
			"\x02\x0F\x06\x0A\x40\x30\x20\x10\x40\x30\x20\x10\x05\04\x0F\x0F\x01\x01\x01\x01\x01\x01\x00",
			'ascii'
		)
	)

	optbuf = udp_addoptions(options)

	print(options)
	print(optbuf)

