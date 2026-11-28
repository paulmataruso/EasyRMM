#!/bin/sh
# EasyRMM maintenance action (feature 11, slice 3), run by the EasyRMM agent
# as root. Arguments: restart, shutdown, service_start, service_stop or
# service_restart; for the service actions, the unit's name. The EasyRMM
# server accepts only plain names, and they are never part of this script's
# text. A restart or shutdown starts one minute from now, so that the run
# can report before the computer goes down.
set -eu
action=$1
unit=${2-}

say() { printf '%s\n' "$*"; }

case $action in
restart)
	say "Restarting in one minute."
	shutdown -r +1 "EasyRMM scheduled restart" || systemctl reboot
	;;
shutdown)
	say "Shutting down in one minute."
	shutdown -P +1 "EasyRMM scheduled shutdown" || systemctl poweroff
	;;
service_start | service_stop | service_restart)
	if [ -z "$unit" ]; then
		say "Name the service."
		exit 2
	fi
	verb=${action#service_}
	say "+ systemctl $verb $unit"
	systemctl "$verb" -- "$unit"
	if [ "$verb" != stop ]; then
		state=$(systemctl is-active -- "$unit" || true)
		say "$unit is $state."
		[ "$state" = active ] || exit 1
	fi
	;;
*)
	say "Unknown action: $action"
	exit 2
	;;
esac
