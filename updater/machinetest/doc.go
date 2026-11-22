// Package machinetest drives the host updater on a whole machine (ADR-0052;
// internal/vmtest, ADR-0051): a Debian 12 virtual machine with Docker, where
// setup.sh installs a deployment from a bundle and the updater upgrades it,
// fails to and rolls it back. Its test runs with the build tag vm; see
// upgrade_vm_test.go and `make test-vm-updater`.
package machinetest
