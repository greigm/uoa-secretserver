# Enables data storage and retrieval from Thycotic SecretServer.
# parameters are automatically sourced from hiera via automatic parameter lookup
# See: https://docs.puppetlabs.com/hiera/3.0/puppet.html#automatic-parameter-lookup
class secretserver {

  # Hiera defined parameters - all prefaced with secretserver:: in your yaml
  # user             - The username to authenticate to secretserver
  # password         - The password for the secretserver user - ideally stored encrypted in eyaml
  # host             - The hostname of the secretserver
  # wsdl             - The URL to the WSDL used by secretserver
  # domain           - The domain used by the auth account to secretserver
  # org              - The organization, for secretserver authentication
  # ssl_verify_mode  - Whether to verify the certificate offered by the secretserver
  # ssl_version      - The type and version of SSL to use - :TLSv1 by default
  # open_timeout     - How long in second to wait for opening a connection to secretserver
  # read_timeout     - How long to wait in seconds for a read operation to complete
  # certificate_path - The default path where certificates are stored on the system
  # service_name     - The name of the web service on the system
  # folder           - The default folder on SecretServer to store secrets
  # template         - The default secret template used to create password secrets
  # password_length  - The length for a new password

}
