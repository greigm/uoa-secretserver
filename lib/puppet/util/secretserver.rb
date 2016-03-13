require 'rubygems'
require 'savon'
require 'nokogiri'
require 'base64'

class Puppet::Util::SecretServer

  attr_accessor :client, :token

  def initialize(wsdl,ssl_verify_mode,ssl_version,open_timeout,read_timeout)
    # Sets up the initial SOAP connection using the Savon gem
    @client = Savon.client(wsdl: wsdl,
                           ssl_verify_mode: ssl_verify_mode.to_sym,
                           ssl_version: ssl_version.to_sym, 
                           open_timeout: open_timeout, 
                           read_timeout: read_timeout)
  end

  def authenticate!(username,password,domain,org)
    # Authenticates to SecretServer
    response = client.call(:authenticate, message: {
                            username:     username,
                            password:     password,
                            organization: org,
                            domain:       domain,
    })

    if not response.success?
      raise RuntimeError, "There was an error authenticating to SecretServer: #{response}"
    end

    self.token = response.to_hash[:authenticate_response][:authenticate_result][:token]
    if self.token.nil? || self.token.empty?
      raise RuntimeError, "There was an error authenticating to SecretServer: #{response}"
    end
    return self.token
  end

  def get_templates
    # Returns a hash containing { 'name_of_template' => template_object } pairs
    # for all available secret templates
    @templates = {}
    response = client.call(:get_secret_templates, message: {
                            token: self.token
    })

    if not response.success?
      raise RuntimeError, "There was an error getting the template list from SecretServer: #{response}"
    end

    response.body[:get_secret_templates_response][:get_secret_templates_result][:secret_templates][:secret_template].each do |template|
      @templates[template[:name]] = template
    end
  end

  def get_folders(folder_name)
    # Returns a hash containing { 'name_of_folder' => folder_object } pairs
    # for all available secret folders
    @folders = {}
    response = client.call(:search_folders, message: {
                            token:       self.token,
                            folder_name: folder_name,
    })

    if not response.success?
      raise RuntimeError, "There was an error getting the folder list from SecretServer: #{response}"
    end

    response.body[:search_folders_response][:search_folders_result][:folders].each do |folder|
      @folders[folder[1][:name]] = folder[1]
    end
  end

  def search_secrets(term)
    # Returns secret summary objects for all secrets containting the text in term
    response = client.call(:search_secrets, message: {
      token:      self.token,
      searchTerm: term,
    })

    if not response.success?
      raise RuntimeError, "There was an error searching for the secret: #{response}"
    end

    result = response.body[:search_secrets_response][:search_secrets_result][:secret_summaries]
    if result
      return result[:secret_summary]
    else
      return false
    end
  end

  def get_secret(secret_id, format)
    # Fetches a secret by id and returns it in the requested format
    # Most processing done by this module just requires the body for parsing
    # but the xml format returns the entire response, as it's needed for
    # updating a secret using XML via the Nokogiri gem.
    response = client.call(:get_secret, message: {
                            token:    self.token,
                            secretId: secret_id,
    })

    if not response.success?
      raise RuntimeError, "There was an error locating the secret: #{response}"
    end

    case format
    when 'xml'
      return response.to_xml
    when 'body'
      return response.body[:get_secret_response][:get_secret_result][:secret]
    else
      return response
    end
  end

  def add_secret(template, name, folder_id, ids, values, noop)
    # Adds a new secret to SecretServer
    if noop
      return "Puppet running in NoOp mode - not updating SecretServer"
    else
      response = client.call(:add_secret, message: {
                              token:              self.token,
                              secret_type_id:     template,
                              secret_name:        name,
                              folder_id:          folder_id,
                              secret_field_ids:   { :int    => ids },
                              secret_item_values: { :string => values },
    })
      if not response.success?
        raise RuntimeError, "There was an error adding the secret: #{response}"
      end
    end
  end

  def update_secret(xmlsecret, noop)
    # Updates an existing secret from an XML object
    if noop == true
      return "Puppet running in NoOp mode - not updating SecretServer"
    else
      xml = fix_xml(xmlsecret)
      #File.open('/tmp/fixed_secret', 'w') {|f| f.write(xml) }
      response = client.call(:update_secret, xml: xml)
      if not response.success?
        raise RuntimeError, "There was an error updating the secret: #{response}"
      end
    end
  end

  def download(secret_id, item_id, noop)
    # Dumps a raw secret attachment to the caller
    response = client.call(:download_file_attachment_by_item_id, message: {
                            token:        self.token,
                            secretId:     secret_id,
                            secretItemId: item_id,
    })

    if not response.success?
      raise RuntimeError, "There was an error downloading the secret: #{response}"
    end

    data = response.body[:download_file_attachment_by_item_id_response][:download_file_attachment_by_item_id_result][:file_attachment]
    if noop
      return "Puppet running in NoOp mode - not downloading secret"
    else
      return Base64.decode64(data)
    end
  end

  # Utility methods follow

  def fix_xml(xmlsecret)
    # Nokogiri strips the 'xsi' prefix which is required,
    # and also puts a 'default' prefix in, which is disallowed.
    # This is ugly, but gets the job done.
    xmlsecret.to_s.
      gsub('nil=', 'xsi:nil=').
      gsub('default:','')
  end

  def get_token
    # Returns the currently valid token for authentication.
    # Needed to update a secret using XML.
    _token = self.token
  end

  def gen_password(length)
    # Generates a password of length 'length' using most printable ASCII chars
    chars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789!@#$%^&*()_-+=[]{};:.,?~'
    len = length.to_i
    password_length = len < 12 ? 12 : len
    password = Array.new(password_length) { chars[rand(chars.length)].chr }.join
    password
  end

  def get_cert_item(type, id, noop)
    # Retrieves an item from a certificate of type 'type'.
    # Used to retireve a certificate, key, CSR, or other type of object.
    secret = get_secret(id, 'body')
    item_id = nil
    secret[:items][:secret_item].each do |item|
      if item[:field_name] == type
        item_id = item[:id]
      end
    end
    if item_id
      unless noop
        data = download(id, item_id, noop)
        return data
      end
    else
      raise RuntimeError, "This certificate secret does not have a #{type} field!"
    end
  end

  def get_password(id)
    # Retrieves the current password for a secret.
    secret = get_secret(id, 'body')
    item_id = nil
    secret[:items][:secret_item].each do |item|
      if item[:field_name] == 'Password'
        item_id = item[:id]
      end
    end
    if item_id
      return secret
    else
      raise RuntimeError, "This certificate secret does not have a #{type} field!"
    end
  end

  def set_password(name, folder, template, password, noop)
    # Adds a new secret after validation of folder and template
    ids = []
    values = []
    user = name.split('@')[0]
    host = name.split('@')[1]
    params = { 'Username' => user, 'Machine' => host, 'Password' => password }
    if not @templates
      get_templates
      if not @templates[template]
        raise ArgumentError, "Unknown template: #{template}"
      end
      template = @templates[template]
    end
    if not @folders
      get_folders(folder)
      raise ArgumentError, "Unknown folder: #{folder}" unless @folders[folder]
      folder = @folders[folder]
      folder_id = folder[:id]
    end
    template[:fields][:secret_field].each do |field|
      displayname = params[field[:display_name]]
      ids.push(field[:id])
      if displayname
        values.push(displayname)
        params.delete(field[:display_name])
      else
        values.push('')
      end
    end
    if not params.empty?
      raise ArgumentError, "field #{params.keys.join(',')} not found in template"
    end
    add_secret(template[:id], name, folder_id, ids, values, noop)
  end 

  def get_secrets(searchtext)
    # Returns all secrets with a name matching a given search string.
    secrets = search_secrets(searchtext)
    if secrets
      return secrets
    end
  end
      
end # class
