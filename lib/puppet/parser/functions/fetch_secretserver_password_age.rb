require File.join(File.dirname(__FILE__), '..', '..', 'util', 'secretserver')

module Puppet::Parser::Functions

  # Returns the password age of the provided username using the included
  # custom passwd_age fact.
  newfunction(:fetch_secretserver_password_age,:type=>:rvalue) do |args|
    username = args[0]

    age = lookupvar("::passwd_age_#{username}")
    if age
      return age
    else
      return -1
    end

  end # Function

end # Module
