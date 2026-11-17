#!/bin/sh
# Removes the EasyPatch agent from this Mac: sudo /Library/EasyPatch/uninstall.sh
#
# Stops the agent, tells the EasyPatch server it was uninstalled (best effort: works offline too), then deletes the
# agent, its settings, identity and logs, and the package receipt. The agent's own uninstall job also runs this
# script, from a separate launchd job, so it never asks anything.
set -u

label=com.dhitechnical.easypatch.agent
plist=/Library/LaunchDaemons/$label.plist
home=/Library/EasyPatch
agent=$home/easypatch-agent
logs=/Library/Logs/EasyPatch
link=/usr/local/bin/easypatch-agent

# The whole script is read before anything runs, because it deletes its own directory.
main() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "Run as root: sudo $0" >&2
        exit 1
    fi

    echo "Uninstalling the EasyPatch agent"
    if launchctl bootout "system/$label" >/dev/null 2>&1; then
        echo "  stopped $label"
    else
        echo "  $label was not loaded"
    fi
    # bootout can return before the agent has exited (it gets ExitTimeOut, 75 s, to stop).
    waited=0
    while launchctl print "system/$label" >/dev/null 2>&1 && [ "$waited" -lt 90 ]; do
        sleep 1
        waited=$((waited + 1))
    done

    if [ -x "$agent" ]; then
        # unenroll succeeds whether or not the server could be told (it is told when the agent is enrolled and it is reachable).
        if "$agent" unenroll --reason "Agent uninstalled" >/dev/null 2>&1; then
            echo "  unenrolled (the server marks the endpoint decommissioned if it could be reached)"
        else
            echo "  could not unenroll; continuing"
        fi
    fi

    remove "$plist"
    remove "$home"
    remove "$logs"
    if [ -L "$link" ] && [ "$(readlink "$link")" = "$agent" ]; then
        remove "$link"
    fi

    if pkgutil --forget "$label" >/dev/null 2>&1; then
        echo "  forgot the package receipt $label"
    fi
    echo "Done."
    exit 0
}

remove() {
    if [ -e "$1" ] || [ -L "$1" ]; then
        if rm -rf "$1"; then
            echo "  removed $1"
        else
            echo "  could not remove $1" >&2
        fi
    fi
}

main "$@"
