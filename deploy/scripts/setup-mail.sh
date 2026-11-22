# shellcheck shell=bash
# The mail server's options of setup.sh (ADR-0053, slice 2), sourced by it:
#
#   --smtp-host HOST            the mail server (smtp.office365.com with an application)
#   --smtp-port PORT            its port (587)
#   --smtp-from ADDRESS         the address EasyRMM sends from: with an application,
#                               the mailbox it signs in to
#   --smtp-tenant-id ID         a Microsoft 365 application's Directory (tenant) ID,
#                               or one of the tenant's domain names
#   --smtp-client-id ID         its Application (client) ID
#   --smtp-client-secret-file FILE
#                               a file holding its client secret's Value; without
#                               it, or a certificate, setup.sh asks on a terminal
#   --smtp-client-cert-file FILE --smtp-client-key-file FILE
#                               its certificate and RSA private key (PEM), instead
#
# The secret, or the certificate and key, are copied into
# ${EASYRMM_DATA_ROOT}/secrets (root:65532, the directory 0750, the files
# 0440), which the server mounts at /run/secrets/easyrmm; .env names them by
# their paths there, and never holds them. With an existing .env, the mail
# options may be given alone: the rest is read from .env, and only the mail
# settings change. An application needs root (sudo). The patching engine
# cannot sign in with one, so patching sends no email meanwhile.
#
# Each option replaces its setting; with an application, the tenant, the
# application and the credential not given are kept from .env.

smtp_host=""
smtp_port=""
smtp_from=""
smtp_tenant_id=""
smtp_client_id=""
smtp_secret_file=""
smtp_cert_file=""
smtp_key_file=""
# mail_args counts the words of the --smtp-* options given.
mail_args=0
# The settings mail_set has mail_write_env write to .env.
mail_keys=()
mail_values=()

# The files in secrets/, and their paths in the server's container.
mail_secret_name=smtp-client-secret
mail_cert_name=smtp-client.crt
mail_key_name=smtp-client.key
mail_container_dir=/run/secrets/easyrmm

mail_guid='^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$'
mail_domain='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
mail_ipv4='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
mail_address='^[A-Za-z0-9._%+-]+@([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
mail_withheld="EasyRMM's mail server will sign in with a Microsoft 365 application, which the patching engine cannot do: the engine is given no mail server, so patching sends no email and no monthly reports until a later release moves them to EasyRMM. For patching's email meanwhile, send through a relay, or sign in with a password."

# mail_option OPTION VALUE takes one --smtp-* option; it fails for another.
mail_option() {
  case "$1" in
    --smtp-host) smtp_host="$2" ;;
    --smtp-port) smtp_port="$2" ;;
    --smtp-from) smtp_from="$2" ;;
    --smtp-tenant-id) smtp_tenant_id="$2" ;;
    --smtp-client-id) smtp_client_id="$2" ;;
    --smtp-client-secret-file) smtp_secret_file="$2" ;;
    --smtp-client-cert-file) smtp_cert_file="$2" ;;
    --smtp-client-key-file) smtp_key_file="$2" ;;
    *) return 1 ;;
  esac
  mail_args=$((mail_args + 2))
}

# mail_read VAR KEY sets VAR to KEY's value in .env, as Compose reads it,
# empty without one. env_value refuses a value it cannot read as Compose
# does; that refusal stops setup.sh here, wherever mail_read is called (a
# condition included), rather than be taken for an empty value, as it
# would be in a command's argument or inside [[ ]].
mail_read() {
  local mail_read_value=""
  if [[ -e .env ]]; then
    mail_read_value=$(env_value "$2") || exit 1
  fi
  printf -v "$1" '%s' "$mail_read_value"
}

# mail_set KEY VALUE has mail_write_env set KEY to VALUE in .env, unless
# .env has it so already. A setting kept from .env is left as it is written
# there, quotes, comment and all: Compose reads it as it did. Every value
# that changes was checked first: a host name, a port, an address, a GUID,
# a keyword or a path, none of which needs quotes in .env.
mail_set() {
  local kept
  if grep -q "^$1=" .env; then
    mail_read kept "$1"
    if [[ "$kept" == "$2" ]]; then
      return 0
    fi
  fi
  mail_keys+=("$1")
  mail_values+=("$2")
}

# mail_write_env writes mail_set's settings into .env at once: each
# replaces its key's line, and any repeat of it, or is added at the end.
# The values reach awk through its environment, never its program, so no
# character in them means anything to it; the new .env is written beside
# the old, given its owner and mode, and renamed over it, so .env is never
# left half written.
mail_write_env() {
  [[ ${#mail_keys[@]} -gt 0 ]] || return 0
  local tmp
  tmp=$(mktemp .env.mail.XXXXXX) || die "could not write a new .env beside the old"
  if ! (
    for i in "${!mail_keys[@]}"; do
      export "MAIL_K$i=${mail_keys[$i]}" "MAIL_V$i=${mail_values[$i]}"
    done
    export MAIL_N=${#mail_keys[@]}
    chmod --reference=.env "$tmp" && chown --reference=.env "$tmp" &&
      awk '
        BEGIN { n = ENVIRON["MAIL_N"]; for (i = 0; i < n; i++) { k[i] = ENVIRON["MAIL_K" i]; v[i] = ENVIRON["MAIL_V" i] } }
        {
          for (i = 0; i < n; i++) {
            if (index($0, k[i] "=") == 1) {
              if (!(i in done)) { print k[i] "=" v[i]; done[i] = 1 }
              next
            }
          }
          print
        }
        END { for (i = 0; i < n; i++) if (!(i in done)) print k[i] "=" v[i] }
      ' .env > "$tmp" && mv -f "$tmp" .env
  ); then
    rm -f "$tmp"
    die "could not write the mail settings to .env; it is as it was"
  fi
  mail_keys=()
  mail_values=()
}

# mail_kept KEY NAME: whether .env names secrets/NAME for its setting, and the
# file is there: a credential kept.
mail_kept() {
  local key="$1" name="$2" value
  mail_read value "$key"
  [[ "$value" == "$mail_container_dir/$name" && -f "$data_root/secrets/$name" && ! -L "$data_root/secrets/$name" ]]
}

# mail_check_secret TEXT dies unless TEXT is a client secret: one line of
# printable characters, at most 1,024.
mail_check_secret() {
  local s="$1" what="$2"
  [[ -n "$s" ]] || die "${what} is empty"
  [[ "$s" != *$'\n'* ]] || die "${what} is more than one line: it must hold the secret's Value alone"
  [[ ${#s} -le 1024 ]] || die "${what} is longer than 1,024 characters"
  [[ "$s" =~ ^[[:graph:]]+$ ]] || die "${what} has spaces or characters that cannot be printed"
}

# mail_check_certificate CERT KEY dies unless CERT is an RSA certificate in
# PEM, unexpired, and KEY its private key, unencrypted; it warns within 30
# days of the certificate's end.
mail_check_certificate() {
  local cert="$1" key="$2" end
  [[ -f "$cert" ]] || die "--smtp-client-cert-file: ${cert} is not a file"
  [[ -f "$key" ]] || die "--smtp-client-key-file: ${key} is not a file"
  openssl x509 -in "$cert" -noout 2>/dev/null || die "--smtp-client-cert-file: ${cert} is not a certificate in PEM"
  # As the server takes it: CERTIFICATE blocks alone, nothing around them.
  awk '/^-----BEGIN CERTIFICATE-----\r?$/ { if (inside) exit 1; inside = 1; n++; next }
    /^-----END CERTIFICATE-----\r?$/ { if (!inside) exit 1; inside = 0; next }
    inside || /^[[:space:]]*$/ { next }
    { exit 1 }
    END { if (inside || n == 0) exit 1 }' "$cert" ||
    die "--smtp-client-cert-file: ${cert} must hold PEM certificates alone (-----BEGIN CERTIFICATE----- blocks), with no other text or keys: openssl x509 -in ${cert} -out plain.crt writes the certificate alone"
  openssl x509 -in "$cert" -noout -text 2>/dev/null | grep -q 'Public Key Algorithm: rsaEncryption' ||
    die "--smtp-client-cert-file: the certificate's key is not RSA: Entra signs in applications with RSA certificates"
  openssl pkey -in "$key" -passin pass: -noout 2>/dev/null ||
    die "--smtp-client-key-file: ${key} is not a private key in PEM, or it is encrypted: give it without a passphrase (openssl pkey -in key.pem -out plain.pem)"
  [[ "$(openssl pkey -in "$key" -passin pass: -pubout 2>/dev/null)" == "$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null)" ]] ||
    die "--smtp-client-key-file: the private key is not the certificate's"
  end=$(openssl x509 -in "$cert" -noout -enddate | sed 's/^notAfter=//')
  openssl x509 -in "$cert" -noout -checkend 0 > /dev/null ||
    die "--smtp-client-cert-file: the certificate expired (${end}): make a new one and upload it to the application in Entra"
  if ! openssl x509 -in "$cert" -noout -checkend $((30 * 24 * 3600)) > /dev/null; then
    echo "Warning: the application's certificate ends within 30 days (${end}). Make a new one, upload it to the application in Entra, and give it to setup.sh." >&2
  fi
}

# mail_no_dollar WHAT VALUE [OF] dies when VALUE has a $. In .env, Compose
# reads $NAME and ${NAME} as variables and $$ as one $, which setup.sh's
# env_value and the updater do not: refused, so that all three read the
# same value. A sender's name with a $ is rare.
mail_no_dollar() {
  [[ "$2" != *'$'* ]] || die "${1} has a \$: a \$ in .env is read by Compose as a variable; leave it out${3:+ of $3}"
}

# mail_validate checks the --smtp-* options against what .env has, before
# anything is written, and decides the mail settings: mail_app says a
# Microsoft 365 application signs in; mail_credential is secret,
# certificate, keep or ask.
mail_validate() {
  mail_app=false
  if [[ -n "$smtp_tenant_id$smtp_client_id$smtp_secret_file$smtp_cert_file$smtp_key_file" ]]; then
    [[ $(id -u) -eq 0 ]] || die "the --smtp-tenant-id, --smtp-client-* options need root (sudo): the secret or key goes into ${data_root}/secrets"
  fi
  # No $ in what is given, nor in what is read back from .env.
  mail_no_dollar --smtp-host "$smtp_host"
  mail_no_dollar --smtp-port "$smtp_port"
  mail_no_dollar --smtp-from "$smtp_from" "the address"
  mail_no_dollar --smtp-tenant-id "$smtp_tenant_id"
  mail_no_dollar --smtp-client-id "$smtp_client_id"
  local key value auth tls
  mail_read auth EASYRMM_SMTP_AUTH
  mail_read tls EASYRMM_SMTP_TLS
  mail_no_dollar "EASYRMM_SMTP_AUTH in .env" "$auth"
  mail_no_dollar "EASYRMM_SMTP_TLS in .env" "$tls"
  if [[ -n "$smtp_tenant_id$smtp_client_id$smtp_secret_file$smtp_cert_file$smtp_key_file" || "$auth" == microsoft365 ]]; then
    mail_app=true
  fi
  # What is given is checked; what .env has, the server checked.
  smtp_host="${smtp_host,,}"
  [[ -z "$smtp_host" || "$smtp_host" =~ $mail_domain || "$smtp_host" =~ $mail_ipv4 ]] ||
    die "--smtp-host must be a DNS name such as smtp.example.com, or an IPv4 address"
  [[ -z "$smtp_port" || ( "$smtp_port" =~ ^[0-9]{1,5}$ && "$smtp_port" -ge 1 && "$smtp_port" -le 65535 ) ]] || die "--smtp-port must be a port, 1 to 65535"
  [[ -z "$smtp_from" || "$smtp_from" =~ $mail_address ]] || die "--smtp-from must be an email address such as rmm@example.com"
  [[ -n "$smtp_host" ]] || mail_read smtp_host EASYRMM_SMTP_HOST
  [[ -n "$smtp_port" ]] || mail_read smtp_port EASYRMM_SMTP_PORT
  smtp_port=${smtp_port:-587}
  [[ -n "$smtp_from" ]] || mail_read smtp_from EASYRMM_SMTP_FROM
  # What was given had none, so a $ now came from .env.
  mail_no_dollar "EASYRMM_SMTP_HOST in .env" "$smtp_host"
  mail_no_dollar "EASYRMM_SMTP_PORT in .env" "$smtp_port"
  mail_no_dollar "EASYRMM_SMTP_FROM in .env" "$smtp_from" "the sender's name"
  if [[ "$mail_app" == true ]]; then
    smtp_host=${smtp_host:-smtp.office365.com}
  fi
  [[ -n "$smtp_host" ]] || die "--smtp-host is required"
  [[ -n "$smtp_from" ]] || die "--smtp-from is required: the address EasyRMM sends from"
  [[ "$mail_app" == true ]] || return 0

  [[ $(id -u) -eq 0 ]] || die "a Microsoft 365 application needs root (sudo): its secret or key goes into ${data_root}/secrets"
  mail_secrets_safe
  [[ -n "$smtp_tenant_id" ]] || mail_read smtp_tenant_id EASYRMM_SMTP_TENANT_ID
  [[ -n "$smtp_client_id" ]] || mail_read smtp_client_id EASYRMM_SMTP_CLIENT_ID
  mail_no_dollar "EASYRMM_SMTP_TENANT_ID in .env" "$smtp_tenant_id"
  mail_no_dollar "EASYRMM_SMTP_CLIENT_ID in .env" "$smtp_client_id"
  for key in EASYRMM_SMTP_CLIENT_SECRET_FILE EASYRMM_SMTP_CLIENT_CERT_FILE EASYRMM_SMTP_CLIENT_KEY_FILE; do
    mail_read value "$key"
    mail_no_dollar "${key} in .env" "$value"
  done
  [[ -n "$smtp_tenant_id" ]] || die "--smtp-tenant-id is required: the Directory (tenant) ID from the application's Overview page in Entra"
  [[ "$smtp_tenant_id" =~ $mail_guid || ( ${#smtp_tenant_id} -le 253 && "$smtp_tenant_id" =~ $mail_domain ) ]] ||
    die "--smtp-tenant-id must be the tenant's ID (a GUID) or one of its domain names, such as contoso.onmicrosoft.com"
  [[ -n "$smtp_client_id" ]] || die "--smtp-client-id is required: the Application (client) ID from the application's Overview page in Entra"
  [[ "$smtp_client_id" =~ $mail_guid ]] || die "--smtp-client-id must be the Application (client) ID, a GUID"
  if [[ -n "$smtp_secret_file" && -n "$smtp_cert_file$smtp_key_file" ]]; then
    die "give --smtp-client-secret-file, or --smtp-client-cert-file with --smtp-client-key-file, not both"
  elif [[ -n "$smtp_secret_file" ]]; then
    [[ -f "$smtp_secret_file" ]] || die "--smtp-client-secret-file: ${smtp_secret_file} is not a file"
    mail_secret=$(< "$smtp_secret_file")
    mail_check_secret "${mail_secret%$'\r'}" "--smtp-client-secret-file: ${smtp_secret_file}"
    mail_credential=secret
  elif [[ -n "$smtp_cert_file$smtp_key_file" ]]; then
    [[ -n "$smtp_cert_file" && -n "$smtp_key_file" ]] || die "--smtp-client-cert-file and --smtp-client-key-file go together"
    mail_check_certificate "$smtp_cert_file" "$smtp_key_file"
    mail_credential=certificate
  elif mail_kept EASYRMM_SMTP_CLIENT_SECRET_FILE "$mail_secret_name" ||
    { mail_kept EASYRMM_SMTP_CLIENT_CERT_FILE "$mail_cert_name" && mail_kept EASYRMM_SMTP_CLIENT_KEY_FILE "$mail_key_name"; }; then
    mail_credential=keep
  else
    [[ -t 0 ]] || die "--smtp-client-secret-file, or --smtp-client-cert-file with --smtp-client-key-file, is required when setup.sh cannot ask"
    read -r -s -p "The application's client secret (its Value, not shown): " mail_secret
    echo
    mail_check_secret "$mail_secret" "The client secret"
    mail_credential=secret
  fi
  # A token goes only over TLS: STARTTLS unless .env says TLS from the first byte.
  mail_tls=starttls
  [[ "$tls" != implicit ]] || mail_tls=implicit
}

# mail_env writes the mail settings to .env: the files' paths in the
# container, never the secret or the key.
mail_env() {
  mail_set EASYRMM_SMTP_HOST "$smtp_host"
  mail_set EASYRMM_SMTP_PORT "$smtp_port"
  mail_set EASYRMM_SMTP_FROM "$smtp_from"
  if [[ "$mail_app" != true ]]; then
    mail_write_env
    return 0
  fi
  mail_set EASYRMM_SMTP_TLS "$mail_tls"
  mail_set EASYRMM_SMTP_AUTH microsoft365
  mail_set EASYRMM_SMTP_TENANT_ID "$smtp_tenant_id"
  mail_set EASYRMM_SMTP_CLIENT_ID "$smtp_client_id"
  mail_set EASYRMM_SMTP_USERNAME ""
  mail_set EASYRMM_SMTP_PASSWORD ""
  case "$mail_credential" in
    secret)
      mail_set EASYRMM_SMTP_CLIENT_SECRET_FILE "$mail_container_dir/$mail_secret_name"
      mail_set EASYRMM_SMTP_CLIENT_CERT_FILE ""
      mail_set EASYRMM_SMTP_CLIENT_KEY_FILE ""
      ;;
    certificate)
      mail_set EASYRMM_SMTP_CLIENT_SECRET_FILE ""
      mail_set EASYRMM_SMTP_CLIENT_CERT_FILE "$mail_container_dir/$mail_cert_name"
      mail_set EASYRMM_SMTP_CLIENT_KEY_FILE "$mail_container_dir/$mail_key_name"
      ;;
  esac
  mail_write_env
  echo "Mail: EasyRMM signs in to ${smtp_host}:${smtp_port} as ${smtp_from} with the Microsoft 365 application ${smtp_client_id}."
}

# mail_secrets_safe dies unless root can give secrets/ and its files their
# owner and modes without changing anything outside them: the data root
# root's and writable by root alone, so no one else can swap what is in it;
# secrets/ not a symbolic link; no file in it with another link, as a hard
# link to a file elsewhere has. What is not there yet, root makes.
mail_secrets_safe() {
  local dir="$data_root/secrets" owner mode f
  if [[ -e "$data_root" ]]; then
    read -r owner mode < <(stat -L -c '%u %a' "$data_root")
    [[ -d "$data_root" && "$owner" == 0 && $((8#$mode & 8#022)) -eq 0 ]] ||
      die "${data_root} must be a directory of root's that only root can write to (sudo chown root ${data_root}; sudo chmod go-w ${data_root})"
  fi
  [[ ! -L "$dir" ]] || die "${dir} is a symbolic link: it must be a directory of its own"
  for f in "$dir"/*; do
    if [[ -f "$f" && ! -L "$f" && "$(stat -c %h "$f")" != 1 ]]; then
      die "${f} has other links, as a hard link to a file elsewhere has: remove it, and run setup.sh again"
    fi
  done
}

# mail_secrets_dir makes secrets/, as tls/ is: root's, readable by the
# server's group (65532), and gives what is in it its owner and modes.
mail_secrets_dir() {
  mail_secrets_safe
  install -d -m 0750 -o root -g 65532 "$data_root/secrets"
  # Only root can put a file in it now: one put there before is checked again.
  mail_secrets_safe
  local f
  for f in "$data_root/secrets"/*; do
    if [[ -f "$f" && ! -L "$f" ]]; then
      chown root:65532 "$f"
      chmod 0440 "$f"
    fi
  done
}

# mail_put NAME writes its input to secrets/NAME, root:65532 0440. Only root
# can write in secrets/, so nothing there was planted; the file is written
# beside it and renamed into place.
mail_put() {
  local path="$data_root/secrets/$1" tmp
  tmp=$(mktemp "$data_root/secrets/.new.XXXXXX")
  if ! { cat > "$tmp" && chown root:65532 "$tmp" && chmod 0440 "$tmp" && mv -T -f "$tmp" "$path"; }; then
    rm -f "$tmp"
    die "could not write ${path}"
  fi
}

# mail_files copies the credential into secrets/, removes the other kind's,
# and says what comes next.
mail_files() {
  [[ "$mail_app" == true ]] || return 0
  mail_secrets_dir
  case "$mail_credential" in
    secret)
      printf '%s\n' "${mail_secret%$'\r'}" | mail_put "$mail_secret_name"
      rm -f "$data_root/secrets/$mail_cert_name" "$data_root/secrets/$mail_key_name"
      ;;
    certificate)
      mail_put "$mail_cert_name" < "$smtp_cert_file"
      mail_put "$mail_key_name" < "$smtp_key_file"
      rm -f "$data_root/secrets/$mail_secret_name"
      ;;
  esac
  echo
  echo "Warning: patching's email stops. ${mail_withheld}" >&2
  echo
  echo "After docker compose up -d, check that EasyRMM signs in to the mail server, sending nothing:"
  echo "  sudo docker compose exec server easyrmm-server mail check"
}

# mail_only is the --smtp-* options alone, on an existing .env: the rest is
# read from it, and only the mail settings change.
mail_only() {
  [[ -e .env ]] || die "the --smtp-* options alone need the deployment's .env here; to install, give --hostname too"
  mail_read data_root EASYRMM_DATA_ROOT
  data_root=${data_root:-/srv/easyrmm}
  mail_validate
  mail_env
  mail_files
  echo "Only the mail settings in .env changed. Apply them: sudo docker compose up -d"
}
