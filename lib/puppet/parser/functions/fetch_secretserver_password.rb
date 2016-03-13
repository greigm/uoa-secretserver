require File.join(File.dirname(__FILE__), '..', '..', 'util', 'secretserver')

module Puppet::Parser::Functions

  newfunction(:fetch_secretserver_password,:type=>:rvalue) do |args|
    itemname = args[0]

    wsdl            = call_function('hiera','secretserver::wsdl')
    ssl_verify_mode = call_function('hiera','secretserver::ssl_verify_mode')
    ssl_version     = call_function('hiera','secretserver::ssl_version')
    open_timeout    = call_function('hiera','secretserver::open_timeout')
    read_timeout    = call_function('hiera','secretserver::read_timeout')
    username        = call_function('hiera','secretserver::user')
    password        = call_function('hiera','secretserver::password')
    domain          = call_function('hiera','secretserver::domain')
    org             = call_function('hiera','secretserver::org')

    secret = Puppet::Util::SecretServer.new(wsdl,ssl_verify_mode,ssl_version,open_timeout,read_timeout)
    secret.authenticate!(username,password,domain,org)
    secrets = secret.get_secrets(itemname)
    if secrets
      if secrets.is_a? Hash
        if secrets[:secret_name] == itemname
          data = secret.get_password(secrets[:secret_id])
          data[:items][:secret_item].each do |item|
            if item[:is_password] and item[:field_name] == 'Password' and item[:value]
              password = item[:value]
              return password # So only first result is returned
            end # if is password
          end # data.each
        end # if secret name matches search term
      else # More than one secret returned
        secrets.each do |result|
          if result[:secret_name] == itemname
            data = secret.get_password(result[:secret_id])
            data[:items][:secret_item].each do |item|
              if item[:is_password] and item[:field_name] == 'Password' and item[:value]
                password = item[:value]
                return password # So only first result is returned
              end # if is password
            end # data.each
          end # if secret name matches search term
        end # secrets.each
      end # if only one result - Hash
    else
      # We found no password to return
      false
    end # if secrets
  end

end
