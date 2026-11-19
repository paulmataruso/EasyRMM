"""What EasyRMM's deployment sets in Authentik besides its blueprint.

The authentik-setup service of deploy/docker-compose.yml runs this with
Authentik's own command, after every start of Authentik:

    ak shell -c "exec(open('/easyrmm/bin/setup.py').read())"

It waits until the worker has applied EasyRMM's blueprint, then:

* sets the system settings blueprints cannot: people may not change their
  email address or username (EasyRMM's administrator set them), and avatars
  are initials, so no browser asks Gravatar for anyone's picture;
* creates the invitation setup.sh decided, if one is pending: its id (the
  link setup.sh printed), the administrator's email, fixed, and when it
  expires. It is single-use, for EasyRMM's enrollment flow only, and
  replaces any earlier invitation of setup.sh's that is still unused. The
  pending file is removed once the invitation exists, so a used one, which
  Authentik deletes, never comes back. (Authentik uses an invitation up when
  its link is opened; an unfinished sign-up goes on in the same browser.)
"""

import os
import sys
import time
from datetime import UTC, datetime
from uuid import UUID

from authentik.blueprints.models import BlueprintInstance, BlueprintInstanceStatus
from authentik.core.models import User
from authentik.events.models import Event, EventAction
from authentik.flows.models import Flow
from authentik.stages.invitation.models import Invitation
from authentik.tenants.models import Tenant

BLUEPRINT = "EasyRMM - Sign-in"
FLOW = "easyrmm-enrollment"
PENDING = "/easyrmm/invitations/pending"
NAME_PREFIX = "easyrmm-administrator-"
WAIT_SECONDS = 900


def log(message):
    print(f"authentik-setup: {message}", flush=True)


def wait_for_blueprint():
    deadline = time.monotonic() + WAIT_SECONDS
    while True:
        instance = BlueprintInstance.objects.filter(name=BLUEPRINT).first()
        if instance is not None and instance.status == BlueprintInstanceStatus.SUCCESSFUL:
            if Flow.objects.filter(slug=FLOW).exists():
                return
        if instance is not None and instance.status == BlueprintInstanceStatus.ERROR:
            log(f"the blueprint {BLUEPRINT!r} failed to apply; see the authentik-worker log")
            sys.exit(1)
        if time.monotonic() > deadline:
            log(f"the blueprint {BLUEPRINT!r} was not applied within {WAIT_SECONDS} seconds")
            sys.exit(1)
        time.sleep(3)


def settings():
    tenant = Tenant.objects.get(schema_name="public")
    tenant.default_user_change_email = False
    tenant.default_user_change_username = False
    tenant.avatars = "initials"
    tenant.save()


def read_pending():
    with open(PENDING, encoding="utf-8") as f:
        values = dict(line.split("=", 1) for line in f.read().splitlines() if "=" in line)
    return (
        UUID(values["id"].strip()),
        values["email"].strip().lower(),
        datetime.fromtimestamp(int(values["expires"].strip()), tz=UTC),
    )


def invitation():
    if not os.path.exists(PENDING):
        return
    invite_id, email, expires = read_pending()
    used = Event.objects.filter(
        action=EventAction.INVITE_USED, context__invitation_uuid=invite_id.hex
    ).exists()
    if used:
        log("the pending invitation was already used; run setup.sh --new-invitation for another")
    elif not Invitation.objects.filter(pk=invite_id).exists():
        Invitation.objects.filter(name__startswith=NAME_PREFIX).exclude(pk=invite_id).delete()
        Invitation.objects.create(
            invite_uuid=invite_id,
            name=NAME_PREFIX + invite_id.hex[:8],
            flow=Flow.objects.get(slug=FLOW),
            single_use=True,
            expires=expires,
            fixed_data={"email": email, "username": email},
            created_by=User.objects.get(username="akadmin"),
        )
        log(f"invitation for {email} created; it expires {expires:%Y-%m-%d %H:%M} UTC")
    os.remove(PENDING)
    if expires <= datetime.now(tz=UTC):
        log("that invitation has expired already; run setup.sh --new-invitation for another")


wait_for_blueprint()
settings()
invitation()
log("done")
