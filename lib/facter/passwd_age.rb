accounts   = {}
uids       = {}

# For just the system users
case Facter.value(:osfamily)
when 'RedHat'
  if Facter.value(:lsbmajdistrelease) == '6'
    maxuid = 500
  else
    maxuid = 1000
  end
when 'Debian'
  maxuid = 500
else
  maxuid = 500
end

if File.exists?("/etc/passwd") then
  File.open("/etc/passwd").each do |line|
    uids[$1] = $2.to_i if line =~ /^([^:\s]+):[^:]+:(\d+):/
  end
end

if File.exists?("/etc/shadow") then
  File.open("/etc/shadow").each do |line|
    username   = nil
    passwd_age = nil
    username = $1 and passwd_age = $2 if line =~ /^([^:\s]+):[^:]+:(\d+):/ && uids[$1] && uids[$1] < maxuid
    if ( username != nil && passwd_age != nil ) then
      accounts['passwd_age_'+username] =
        ((Time.now-Time.at(passwd_age.to_i*24*3600))/(24*3600)).floor
    end
  end
end

accounts.each do |name, passwd_age|
  Facter.add(name) do
    setcode do
      passwd_age
    end
  end
end
