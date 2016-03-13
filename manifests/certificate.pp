# Fetches certificate items (including SSH keys) from Thycotic's SecretServer
define secretserver::certificate (
  $certificate_path  = secretserver::certificate_path,
  $certificate       = "${certificate_path}/${name}.crt",
  $key               = "${certificate_path}/${name}.key",
  $service           = true,
  $service_name      = secretserver::service_name,
  $fetch_key         = true,
  $fetch_certificate = true,
  $owner             = 'root',
  $group             = 'root',
  $mode              = '0640',
) {

  include ::secretserver

  # Do we need to refresh a service?
  if $service {
    if ! defined (Service[$service_name]) {
      service { $service_name:
        ensure     => running,
        hasstatus  => true,
        hasrestart => true,
        enable     => true,
      }
    }
    $refresh_service = [Service[$service_name]]
  } else {
    $refresh_service = undef
  }

  if $fetch_certificate {
    $certificate_content = fetch_secretserver_cert_item($name, 'Certificate')
    if $certificate_content == '' {
      notify { "secretserver::certificate::${name}.crt":
        message  => "ERROR: No certificate found in SecretServer for ${name}",
      }
    } else {
      file { $certificate:
        ensure  => file,
        content => $certificate_content,
        owner   => $owner,
        group   => $group,
        mode    => $mode,
        notify  => $refresh_service,
      }
    }
  }

  if $fetch_key {
    $private_key_content = fetch_secretserver_cert_item($name, 'Private Key')
    if $certificate_content == '' {
      notify { "secretserver::certificate::${name}.crt":
        message  => "ERROR: No certificate found in SecretServer for ${name}",
      }
    } else {
      file { $key:
        ensure  => file,
        content => $private_key_content,
        owner   => $owner,
        group   => $group,
        mode    => $mode,
        notify  => $refresh_service,
      }
    }
  }

}
