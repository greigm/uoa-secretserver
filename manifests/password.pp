# Change account password if older than $max_age days
define secretserver::password (
  $username        = $name,
  $max_age         = $secretserver::max_age,
  $min_reset       = $secretserver::min_reset,
  $folder          = $secretserver::folder,
  $template        = $secretserver::template,
  $password_length = $secretserver::template,
) {

  $itemname = "${username}@${::fqdn}"

  include ::secretserver

  $account_age   = fetch_secretserver_password_age($username)
  $secret_exists = fetch_secretserver_password($itemname)

  if $secret_exists == false or $account_age > $max_age {
    if $::noop {
      notify { "secretserver::password::${itemname}":
        message => "Not updating password for ${itemname} because we are running in noop mode",
      }
    } else {
      $password = set_secretserver_password($itemname, $folder, $template, $password_length)
      if $password {
        exec { "chpasswd_${username}":
          command => "/usr/bin/chage -m '${min_reset}' '${username}';/bin/echo '${username}:${password}'|/usr/sbin/chpasswd",
          onlyif  => "/bin/egrep '^${username}:' /etc/passwd",
        }
      } else {
        notify { "secretserver::password::chpasswd::${username}":
          message => "Not updating password for ${username} because the SecretServer update failed",
        }
      }
    }
  }

}
