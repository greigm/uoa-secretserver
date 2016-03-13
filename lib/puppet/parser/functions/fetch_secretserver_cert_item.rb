require File.join(File.dirname(__FILE__), '..', '..', 'util', 'secretserver')

module Puppet::Parser::Functions

  newfunction(:fetch_secretserver_cert_item, :type => :rvalue) do |args|
    itemname  = args[0]
    itemtype  = args[1]

    wsdl            = call_function('hiera','secretserver::wsdl')
    ssl_verify_mode = call_function('hiera','secretserver::ssl_verify_mode')
    ssl_version     = call_function('hiera','secretserver::ssl_version')
    open_timeout    = call_function('hiera','secretserver::open_timeout')
    read_timeout    = call_function('hiera','secretserver::read_timeout')
    username        = call_function('hiera','secretserver::user')
    password        = call_function('hiera','secretserver::password')
    domain          = call_function('hiera','secretserver::domain')
    org             = call_function('hiera','secretserver::org')
    noop            = lookupvar('::clientnoop')

    secret = Puppet::Util::SecretServer.new(wsdl,ssl_verify_mode,ssl_version,open_timeout,read_timeout)
    secret.authenticate!(username,password,domain,org)
    secrets = secret.get_secrets(itemname)
    data = nil
    if secrets.is_a? Hash
      if secrets[:secret_name] == itemname and secrets[:secret_type_name] == 'Certificate'
        data = secret.get_cert_item(itemtype, secrets[:secret_id], noop)
        return data
      end
    else
      secrets.each do |result|
        if result[:secret_name] == itemname and result[:secret_type_name] == 'Certificate'
          data = secret.get_cert_item(itemtype, result[:secret_id], noop)
          return data
        end
      end
    end
    # We found no matching item type in the named certificate, or no named
    # certificate was present.
    false
  end

end
