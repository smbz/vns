from django import forms
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.views.generic.simple import direct_to_template

import models as db
import permissions


def org_access_check(request, callee, action, **kwargs):
    """Checks that the user can access the functions they're trying to, and
    if they can calls callee
    @param request  An HTTP request
    @param callee  Gives the Callable to call
    @param action  One of "add", "change", "use", "delete", describing the
    permissions needed
    @param on  The name of the organization in question; not used for
    action = "add"
    @exception ValueError  If an action is unrecognised
    @exception KeyError  If an option is missing"""

    def denied():
        """Generate an error message and redirect if we try do something to a
        template we're not allowed to"""
        messages.error(request, "Either this organization doesn't exist or you don't "
                                "have permission to %s it." % action)
        return HttpResponseRedirect('/')

    def denied_add():
        """Generate an error message and redirect if we try to create a template
        and are not allowed to"""
        messages.error(request, "You don't have permission to create organizations.")
        return HttpResponseRedirect('/')
    
    # If we're trying to add a template, don't need to get the template itself
    if action == "add":
        if permissions.allowed_organization_access_create(request.user):
            return callee(request, **kwargs)
        else:
            return denied_add()

    else:

        # Try getting the template - if it doesn't exist, show the same message
        # as for permission denied
        on = kwargs["on"]
        try :
            org = db.Organization.objects.get(name=on)
        except db.Organization.DoesNotExist:
            return denied()

        if action == "use":
            if permissions.allowed_organization_access_use(request.user, org):
                return callee(request, org, **kwargs)
            else:
                return denied()
        elif action == "change":
            if permissions.allowed_organization_access_change(request.user, org):
                return callee(request, org, **kwargs)
            else:
                return denied()
        elif action == "delete":
            if permissions.allowed_organization_access_delete(request.user, org):
                return callee(request, org, **kwargs)
            else:
                return denied()
        else:
            raise ValueError("Unknown action: %s" % options["action"])

def org_users(request, org, on):
    tn = 'vns/org_users.html'
    org = db.Organization.objects.get(name=on)
    users = list(permissions.get_allowed_users(request.user).filter(org=org, retired=False))
    users.sort(db.UserProfile.cmp_pos_order)
    return direct_to_template(request, tn, {'org':org, 'users':users})

