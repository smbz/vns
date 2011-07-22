from django.db.models import Q

import models as db


def allowed_user_access_create(user, pos=None, org=None):
    """If pos and org are None, returns True if this user can in principle
    create other users and False otherwise.  Otherwise, returns True if user
    can create a user with the give position and organization, else False."""

    if not user.has_perm("auth.add_user"):
        return False

    if pos is None and org is not None:
        raise ValueError("Either pos and org must both be None, or neither must be None")
    if pos is not None and org is None:
        raise ValueError("Either pos and org must both be None, or neither must be None")

    if pos is None and org is None:
        # We already know we're allowed to create users in principle
        return True
    else:

        # If we're trying to create a user in a different organization and we're
        # not allowed to
        if org != user.get_profile().org:
            if not user.has_perm("vnswww.userprofile_add_different_org"):
                return False
        try:
            return user.has_perm(db.UserProfile.PERMISSIONS[pos])
        except KeyError:
            # If that type of user doesn't exist, they're not allowed to
            # create one
            return False

def allowed_user_access_change(usera, userb):
    """Returns True if usera is allowed to change userb's profile, password, etc"""
    return ((usera == userb or usera.has_perm("vnswww.userprofile_change_any") or (usera.has_perm("vnswww.userprofile_change_org") and usera.get_profile().org == userb.get_profile().org))
             and not userb.get_profile().retired)

def allowed_user_access_delete(usera, userb):
    """True if usera is allowed to delete userb"""
    return (usera == userb and usera.has_perm("vnswww.userprofile_delete_self")
            or usera.has_perm("vnswww.userprofile_delete_any")
            or (usera.has_perm("vnswww.userprofile_delete_org") and usera.get_profile().org == userb.get_profile().org))

def allowed_user_access_use(usera, userb):
    """True if usera is allowed to view userb's profile"""
    return usera == userb or usera.has_perm("vnswww.userprofile_use_any") or (usera.has_perm("vnswww.userprofile_use_org") and usera.get_profile().org == userb.get_profile().org)


def allowed_topology_access_create(user):
    """True if user can create topologies"""
    return user.has_perm("vnswww.add_topology")

def allowed_topology_access_change(user, topology):
    """Returns True if the user is allowed write access to the topology.
    @param user  The user trying to gain access
    @param topology  The topology they're trying to gain access to"""
    return topology.owner == user or user.has_perm("vnswww.topology_change_any") or (user.has_perm("vnswww.topology_change_org") and user.get_profile().org == topology.org)

def allowed_topology_access_delete(user, topology):
    """Returns True if the user is allowed to delete topology.
    @param user  The user trying to gain access
    @param topology  The topology they're trying to gain access to"""
    return topology.owner == user or user.has_perm("vnswww.topology_delete_any") or (user.has_perm("vnswww.topology_delete_org") and user.get_profile().org == topology.org)

def allowed_topology_access_use(user, topology):
    """Returns True if user is allowed read access to topology, False otherwise
    @param user  The user who is trying to gain access
    @param topology  The topology they're trying to gain access to"""
    return (topology.allowed_users.filter(id=user.id).exists()
            or user == topology.owner
            or topology.public
            or user.has_perm("vnswww.topology_use_any")
            or (user.has_perm("vnswww.topology_use_org")
                and topology.org == user.get_profile().org))


def allowed_topologytemplate_access_create(user):
    """True if user can create topologies"""
    return user.has_perm("vnswww.add_topologytemplate")

def allowed_topologytemplate_access_change(user, template):
    """Returns True if user is allowed write access to template, False otherwise
    @param user  The user who is trying to gain access
    @param topology  The template they're trying to gain access to"""
    return template.owner == user or user.has_perm("vnswww.topologytemplate_change_any") or (user.has_perm("vnswww.topologytemplate_change_org") and template.org == user.get_profile().org)

def allowed_topologytemplate_access_delete(user, template):
    """Returns True if user is allowed to delete template, False otherwise
    @param user  The user who is trying to gain access
    @param topology  The template they're trying to gain access to"""
    return template.owner == user or user.has_perm("vnswww.topologytemplete_delete_any") or (user.has_perm("vnswww.topologytemplete_delete_org") and template.org == user.get_profile().org)

def allowed_topologytemplate_access_use(user, template):
    """Returns True if user is allowed read access to template, False otherwise
    @param user  The user who is trying to gain access
    @param topology  The template they're trying to gain access to"""
    return (template.visibility == db.TopologyTemplate.PUBLIC
        or (template.visibility == db.TopologyTemplate.PROTECTED
                and template.org == user.get_profile().org)
        or template.owner == user
        or user.has_perm("vnswww.topology_use_any")
        or (user.has_perm("vnswww.topology_use_org")
                and template.org == user.get_profile().org))


def allowed_organization_access_use(user, org):
    """Returns True if user is allowed read access to org, False otherwise
    @param user  The user who is trying to gain access
    @param org  The organization they're trying to access"""
    if user.has_perm("vnswww.organization_use_any"):
        return True
    elif user.has_perm("vnswww.organization_use_org"):
        return org == user.get_profile().org


def allowed_ipblock_access_use(user, ipblock):
    if user.has_perm("vnswww.ipblock_use_any"):
        return True
    elif user.has_perm("vnswww.ipblock_use_org"):
        if ipblock.org == user.get_profile().org:
            return True
        elif ipblock.org == user.get_profile().org.parentOrg and ipblock.usable_by_child_orgs:
            return True
    return False


def get_allowed_templates(user):
    """Returns a QuerySet of all the templates that this user has read access to.
    @param user  The user to consider access for."""
    if user.has_perm("vnswww.topologytemplate_use_any"):
        # We can view and use any templates
        templates = db.TopologyTemplate.objects.filter()
    else:
        q_public = Q(visibility = db.TopologyTemplate.PUBLIC)
        q_protected_org = Q(visibility = db.TopologyTemplate.PROTECTED, org = user.get_profile().org)
        q_org = Q(org = user.get_profile().org)
        q_own = Q(owner = user)
        if user.has_perm("vnswww.topologytemplate_use_org"):
            # We can view and use any from the user's organization
            templates = db.TopologyTemplate.objects.filter(q_public | q_org | q_own)
        else:
            # We can view any from our own organization which are protected
            templates = db.TopologyTemplate.objects.filter(q_public | q_protected_org | q_own)

    return templates


def get_allowed_topologies(user):
    """Returns a QuerySet of all the topologies that a user has read access to.
    @param user The user to consider access for."""
    if user.has_perm("vnswww.topology_use_any"):
        # We can view and use any templates
        topos = db.Topology.objects.filter()
    else:
        q_own = Q(owner=user)
        q_permitted = Q(allowed_users=user)
        q_org = Q(org=user.get_profile().org)
        q_public = Q(public=True)
        if user.has_perm("vnswww.topology_use_org"):
            print "Allowed all topos in own org"
            # We can view and use any from the user's organization
            topos = db.Topology.objects.filter(q_permitted | q_org | q_own)
        else:
            print "NOT allowed all topos in own org"
            # We can view any from our own organization which are protected
            topos = db.Topology.objects.filter(q_permitted | q_own)

    return topos


def get_allowed_ipblocks(user):
    """Returns a list of IP blocks that this user is allowed to use.
    @user The user to consider access for."""
    if user.has_perm("vnswww.ipblock_use_any"):
        # Can use any blocks
        blocks = db.IPBlock.objects.filter()
    else:
        q_org = Q(org=user.get_profile().org)
        q_childorg = Q(org=user.get_profile().org.parentOrg, usable_by_child_orgs=True)
        print user.get_all_permissions()
        if user.has_perm("vnswww.ipblock_use_org"):
            print "Using blocks from own organization"
            blocks = db.IPBlock.objects.filter(q_org | q_childorg)
        else:
            print "Not using blocks from own organization"
            blocks = []

    return blocks


def get_allowed_positions(user):
    """Returns a list of tuples of positions that this user can assign to other
    users.  The tuples are of the form (id, name)."""
    r = []
    for (pk,perm) in db.UserProfile.PERMISSIONS.iteritems():
        if user.has_perm(perm):
            r.append( (pk, dict(db.UserProfile.POSITIONS)[pk]) )
    return r


def get_allowed_users(user):
    """Returns an QuerySet of UserProfiles which this user is allowed to view"""
    if user.has_perm("vnswww.userprofile_use_any"):
        return db.UserProfile.objects.all()
    elif user.has_perm("vnswww.userprofile_use_org"):
        return db.UserProfile.objects.filter(org=user.get_profile().org)
    else:
        return db.UserProfile.objects.filter(pk=user.get_profile().id)
