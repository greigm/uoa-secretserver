require File.join(File.dirname(__FILE__), '..', '..', 'util', 'secretserver')
#require 'ruby-debug';debugger

module Puppet::Parser::Functions

  # Creates a new secret if none exists, otherwise updates the password
  # for all matching secrets.
  newfunction(:set_secretserver_password,:type=>:rvalue) do |args|
    itemname        = args[0]
    folder          = args[1]
    template        = args[2]
    password_length = args[3]

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
    password   = secret.gen_password(password_length)
    template ||= 'Unix Account (SSH)'
    folder   ||= 'Drop-box'
    secrets    = secret.get_secrets(itemname)
    if not secrets
      # Secret item doesn't exist - add a new one
      secret.set_password(itemname, folder, template, password, noop)
      return password
    else
      # Secret exists, but are there one or more? If the secret is a Hash, there's just one.
      if secrets.is_a? Hash
        updated = false
        xmlsecret = secret.get_secret(secrets[:secret_id], 'xml')
        doc = Nokogiri::XML::Document.parse(xmlsecret)
        namespaces = doc.collect_namespaces
        ns = {}
        namespaces.each_pair do |key, value|
          ns[key.sub(/^xmlns:/, '')] = value
        end
        secretNode = doc.at_xpath('/soap:Envelope/soap:Body/xmlns:GetSecretResponse/xmlns:GetSecretResult/xmlns:Secret', ns)
        secretNode.at_xpath('//*[name() = \'Items\']').children.each do |secretitem|
          secretitem.children.each do |passitem|
            if passitem.name == 'IsPassword' and passitem.content == 'true'
              passitem.parent.element_children.each do |e|
                if e.name == 'Value'
                  e.content = password
                  updated = true
                end
              end
            end
          end
        end
        if updated
          token = secret.get_token
          updateSoapPackage = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <UpdateSecret xmlns="urn:thesecretserver.com">
      <token></token>
      <secret></secret>
    </UpdateSecret>
  </soap:Body>
</soap:Envelope>'
          updateDoc = Nokogiri::XML::Document.parse(updateSoapPackage)
          updateDoc.at_xpath('//*[name() = \'token\']').content = token
          updateDoc.at_xpath('//*[name() = \'secret\']').add_child(secretNode.children())
          #File.open('/tmp/ss_update', 'w') {|f| f.write(updateDoc) }
          secret.update_secret(updateDoc, noop)
          return password
        else
          return "No password field was found to update. SecretServer item update failed for #{itemname}"
        end
        else
          # The secret was an array, so there's more than one. We need to update all of them.
        updated = false
        secrets.each do |multisecret|
          xmlsecret = secret.get_secret(multisecret[:secret_id], 'xml')
          doc = Nokogiri::XML::Document.parse(xmlsecret)
          namespaces = doc.collect_namespaces
          ns = {}
          namespaces.each_pair do |key, value|
            ns[key.sub(/^xmlns:/, '')] = value
          end
          secretNode = doc.at_xpath('/soap:Envelope/soap:Body/xmlns:GetSecretResponse/xmlns:GetSecretResult/xmlns:Secret', ns)
          secretNode.at_xpath('//*[name() = \'Items\']').children.each do |secretitem|
            secretitem.children.each do |passitem|
              if passitem.name == 'IsPassword' and passitem.content == 'true'
                passitem.parent.element_children.each do |e|
                  if e.name == 'Value'
                    e.content = password
                    updated = true
                  end
                end
                if updated
                  token = secret.get_token
                  updateSoapPackage = '<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <UpdateSecret xmlns="urn:thesecretserver.com">
      <token></token>
      <secret></secret>
    </UpdateSecret>
  </soap:Body>
</soap:Envelope>'
                  updateDoc = Nokogiri::XML::Document.parse(updateSoapPackage)
                  updateDoc.at_xpath('//*[name() = \'token\']').content = token
                  updateDoc.at_xpath('//*[name() = \'secret\']').add_child(secretNode.children())
                  secret.update_secret(updateDoc, noop)
                  return password
                else
                  return "No password field was found to update. SecretServer item update failed for #{itemname}"
                end
              end
            end
          end
        end
      end
    end

  end # Function

end # Module
