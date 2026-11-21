"""What EasyRMM's deployment sets in Authentik at every start.

The authentik-setup service of deploy/docker-compose.yml runs this with
Authentik's own command, after every start of Authentik:

    ak shell -c "exec(open('/easyrmm/bin/setup.py').read())"

It waits until the worker has applied EasyRMM's blueprint, then:

* compares what the blueprint makes of .env as it is now (this container's
  environment) with what Authentik holds, and applies the blueprint again
  only if they differ. The worker applies a blueprint only when the file's
  bytes change, and the values the blueprint reads from .env (!Env) are not
  part of the file, so a changed EASYRMM_PUBLIC_URL or
  EASYRMM_AUTHENTIK_CLIENT_SECRET would never reach Authentik. Applying
  takes a minute or more, in one transaction that can hold up sign-ins, so
  it is not done when nothing changed. After applying, it fails unless
  Authentik then matches. It also fails if the blueprint reads anything
  else from outside its file, which the comparison would miss;
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

import hmac
import os
import sys
import time
from datetime import UTC, datetime
from uuid import UUID

import yaml
from django.db.models.signals import post_save, pre_delete
from django.utils.timezone import now

from authentik.blueprints.models import BlueprintInstance, BlueprintInstanceStatus
from authentik.blueprints.v1.common import BlueprintLoader, Env, File, YAMLTag
from authentik.blueprints.v1.importer import Importer
from authentik.core.management.commands.shell import Command as Shell
from authentik.core.models import Application, User
from authentik.events.models import Event, EventAction
from authentik.flows.models import Flow
from authentik.providers.oauth2.models import OAuth2Provider
from authentik.stages.invitation.models import Invitation
from authentik.stages.redirect.models import RedirectStage
from authentik.tenants.models import Tenant

BLUEPRINT = "EasyRMM - Sign-in"
# What the blueprint reads from .env (!Env). differences() compares all it
# makes of them; check_inputs() refuses a blueprint that reads anything else.
INPUTS = {"EASYRMM_PUBLIC_URL", "EASYRMM_AUTHENTIK_CLIENT_SECRET"}
# Where the blueprint puts EASYRMM_PUBLIC_URL: the provider's redirect URI,
# the enrollment flow's last stage, which goes on to EasyRMM's sign-in through
# this provider (sso.DeploymentProviderID), and the application's launch URL.
# EASYRMM_AUTHENTIK_CLIENT_SECRET is the provider's client secret.
PROVIDER = "EasyRMM"
APPLICATION = "easyrmm"
ENROLLMENT_REDIRECT = "easyrmm-enrollment-redirect"
CALLBACK = "/api/v1/auth/sso/callback"
SIGN_IN = "/api/v1/auth/sso/b2927669-72ce-48a1-a83d-8215013be7ab/start"
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
                return instance
        if instance is not None and instance.status == BlueprintInstanceStatus.ERROR:
            log(f"the blueprint {BLUEPRINT!r} failed to apply; see the authentik-worker log")
            sys.exit(1)
        if time.monotonic() > deadline:
            log(f"the blueprint {BLUEPRINT!r} was not applied within {WAIT_SECONDS} seconds")
            sys.exit(1)
        time.sleep(3)


def check_inputs(content):
    """Fails if the blueprint reads from outside its file anything but INPUTS:
    another variable (!Env) or a file (!File), which differences() would not
    compare, so a change to it would never reach Authentik."""
    unchecked = set()

    def walk(node):
        if isinstance(node, dict):
            children = [*node.keys(), *node.values()]
        elif isinstance(node, list | tuple):
            children = node
        elif isinstance(node, YAMLTag):
            if isinstance(node, Env) and node.key not in INPUTS:
                unchecked.add(f"!Env {node.key}")
            if isinstance(node, File):
                unchecked.add(f"!File {node.path}")
            children = vars(node).values()
        else:
            return
        for child in children:
            walk(child)

    walk(yaml.load(content, BlueprintLoader))
    if unchecked:
        log(f"the blueprint {BLUEPRINT!r} reads {', '.join(sorted(unchecked))}, which this does not check")
        sys.exit(1)


def differences():
    """What Authentik holds that differs from what the blueprint makes of
    .env as it is now, one line each. The client secret is compared here
    only, and never printed."""
    public_url = os.environ["EASYRMM_PUBLIC_URL"].removesuffix("/")
    secret = os.environ["EASYRMM_AUTHENTIK_CLIENT_SECRET"]
    provider = OAuth2Provider.objects.filter(name=PROVIDER).first()
    redirect = RedirectStage.objects.filter(name=ENROLLMENT_REDIRECT).first()
    application = Application.objects.filter(slug=APPLICATION).first()
    missing = [
        f"{what} is missing"
        for what, held in [
            (f"the provider {PROVIDER!r}", provider),
            (f"the stage {ENROLLMENT_REDIRECT!r}", redirect),
            (f"the application {APPLICATION!r}", application),
        ]
        if held is None
    ]
    if missing:
        return missing
    checks = [
        (
            "the provider's redirect URI",
            ", ".join(uri.url for uri in provider.redirect_uris),
            public_url + CALLBACK,
        ),
        ("the enrollment flow's redirect", redirect.target_static, public_url + SIGN_IN),
        ("the application's launch URL", application.meta_launch_url, public_url),
    ]
    wrong = [f"{what} is {held!r}, not {want!r}" for what, held, want in checks if held != want]
    if not hmac.compare_digest(provider.client_secret.encode(), secret.encode()):
        wrong.append("the provider's client secret is not EASYRMM_AUTHENTIK_CLIENT_SECRET")
    return wrong


def apply_blueprint(instance, content):
    """Applies the blueprint as the worker does: the file, in one transaction,
    and records when, as the worker does.

    Like the worker's, it records no event per object saved, which ak shell
    otherwise does: about 60 each time.
    """
    post_save.disconnect(Shell.post_save_handler)
    pre_delete.disconnect(Shell.pre_delete_handler)
    try:
        importer = Importer.from_string(content, instance.context)
        valid, _ = importer.validate()
        applied = valid and importer.apply()
    finally:
        post_save.connect(Shell.post_save_handler)
        pre_delete.connect(Shell.pre_delete_handler)
    if not applied:
        log(f"the blueprint {BLUEPRINT!r} failed to apply; see the lines above")
        sys.exit(1)
    BlueprintInstance.objects.filter(pk=instance.pk).update(last_applied=now())


def follow_env():
    """Applies the blueprint again if Authentik differs from .env, then
    fails unless it matches."""
    instance = wait_for_blueprint()
    content = instance.retrieve()
    check_inputs(content)
    wrong = differences()
    if not wrong:
        log("Authentik matches .env; nothing applied")
        return
    for line in wrong:
        log(line)
    log(f"applying the blueprint {BLUEPRINT!r} again, with .env as it is now")
    apply_blueprint(instance, content)
    wrong = differences()
    for line in wrong:
        log(line)
    if wrong:
        log(
            "Authentik does not match .env after applying: EASYRMM_PUBLIC_URL must be "
            "an https:// origin, without a path"
        )
        sys.exit(1)
    log(f"applied: EasyRMM's provider, enrollment flow and application are at {os.environ['EASYRMM_PUBLIC_URL']}")


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


follow_env()
settings()
invitation()
log("done")
