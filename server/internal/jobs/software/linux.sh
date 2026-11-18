# EasyRMM software action (ADR-0028), run by the EasyRMM agent as root with
# the computer's own package manager: apt-get, dnf, yum or zypper.
# Arguments: install, upgrade or uninstall; the package; for install, an
# optional version. The EasyRMM server accepts only plain package names and
# versions, and they are never part of this script's text.
set -eu
action=$1
pkg=$2
version=${3-}

say() { printf '%s\n' "$*"; }

run() {
	say "+ $*"
	"$@"
}

rpm_installed() { rpm -q "$pkg" >/dev/null 2>&1; }

not_installed() {
	say "$pkg is not installed."
	exit "$1"
}

case $action in
install | upgrade | uninstall) ;;
*)
	say "Unknown action: $action"
	exit 2
	;;
esac

if command -v apt-get >/dev/null 2>&1; then
	export DEBIAN_FRONTEND=noninteractive
	apt() {
		run apt-get -y -q -o DPkg::Lock::Timeout=600 \
			-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
	}
	refresh() { apt update || say "Refreshing the package lists failed; going on with the lists as they are."; }
	case $action in
	install)
		spec=$pkg
		[ -z "$version" ] || spec=$pkg=$version
		refresh
		apt install "$spec"
		;;
	upgrade)
		dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q ' installed$' || not_installed 3
		refresh
		apt install --only-upgrade "$pkg"
		;;
	uninstall)
		dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q ' installed$' || not_installed 0
		apt remove "$pkg"
		;;
	esac
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
	mgr=dnf
	command -v dnf >/dev/null 2>&1 || mgr=yum
	case $action in
	install)
		spec=$pkg
		[ -z "$version" ] || spec=$pkg-$version
		run "$mgr" -y install "$spec"
		;;
	upgrade)
		rpm_installed || not_installed 3
		run "$mgr" -y upgrade "$pkg"
		;;
	uninstall)
		rpm_installed || not_installed 0
		run "$mgr" -y remove "$pkg"
		;;
	esac
elif command -v zypper >/dev/null 2>&1; then
	# zypper's informational exit codes: 102 a restart is needed, 103 zypper
	# updated itself, 106 some repositories could not be refreshed.
	zyp() {
		say "+ zypper $*"
		rc=0
		zypper --non-interactive --no-color "$@" || rc=$?
		case $rc in
		0 | 103 | 106) ;;
		102) say "Restart the computer to finish." ;;
		*) return "$rc" ;;
		esac
	}
	case $action in
	install)
		spec=$pkg
		[ -z "$version" ] || spec=$pkg=$version
		zyp install "$spec"
		;;
	upgrade)
		rpm_installed || not_installed 3
		zyp update "$pkg"
		;;
	uninstall)
		rpm_installed || not_installed 0
		zyp remove "$pkg"
		;;
	esac
else
	say "This computer has none of the package managers EasyRMM uses: apt-get, dnf, yum or zypper."
	exit 2
fi
