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

    # Get a list of visible users from this organization
    users = list(permissions.get_allowed_users(request.user).filter(org=org, retired=False))
    users.sort(db.UserProfile.cmp_pos_order)

    # Get a list of users which this user can delete
    l = lambda up: permissions.allowed_user_access_delete(request.user, up.user)
    deletable_users = filter(l, list(users))

    return direct_to_template(request, tn, {'org':org,
                                            'users':users,
                                            'deletable_users':deletable_users})

class OrganizationForm(forms.Form):
    name = forms.CharField(label="Organization name", max_length=128)

def org_create(request):
    tn = 'vns/org_create.html'
    
    if request.method == "POST":
        form = OrganizationForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            org = db.Organization()
            org.parentOrg = request.user.get_profile().org
            org.name = name
            org.save()
            messages.success(request, "Successfully created %s" % name)
            return HttpResponseRedirect('/organizations/')
        else:
            messages.error(request, "Invalid form submitted - organization name must be <= 128 chars")
            return direct_to_template(request, tn, {'form':form})
    else:
        form = OrganizationForm()
        return direct_to_template(request, tn, {'form':form})
