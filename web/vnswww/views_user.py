import datetime
import re

from django import forms
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth.models import User, Group
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.utils.safestring import mark_safe, mark_for_escaping
from django.views.generic.simple import direct_to_template
from django.http import HttpResponseRedirect

import models as db
import permissions


def user_access_check(request, callee, action, **kwargs):
    """Checks that the user can access the functions they're trying to, and
    if they can calls callee"""
    """Check that the user is allowed access, and if they are call the given
    Callable.
    @param request  An HTTP request
    @param callee  Gives the Callable to call
    @param action  One of "add", "change", "use", "delete", describing the
    permissions needed
    @param user_id  The ID of the user in question; not used for
    action = "add"
    @exception ValueError  If an action is unrecognised
    @exception KeyError  If an option is missing"""

    def denied():
        """Generate an error message and redirect if we try do something to a
        template we're not allowed to"""
        messages.error(request, "Either this user doesn't exist or you don't "
                                "have permission to %s it." % action)
        return HttpResponseRedirect('/')

    def denied_add():
        """Generate an error message and redirect if we try to create a template
        and are not allowed to"""
        messages.error(request, "You don't have permission to create users.")
        return HttpResponseRedirect('/')
    
    # If we're trying to add a template, don't need to get the template itself
    if action == "add":
        if permissions.allowed_user_access_create(request.user):
            return callee(request)
        else:
            return denied_add()

    else:

        # Try getting the template - if it doesn't exist, show the same message
        # as for permission denied
        user_name = kwargs["un"]
        try :
            user = User.objects.get(username=user_name)
        except User.DoesNotExist:
            return denied()

        if action == "use":
            if permissions.allowed_user_access_use(request.user, user):
                return callee(request, user.get_profile())
            else:
                return denied()
        elif action == "change":
            if permissions.allowed_user_access_change(request.user, user):
                return callee(request, user.get_profile())
            else:
                return denied()
        elif action == "delete":
            if permissions.allowed_user_access_delete(request.user, user):
                return callee(request, user.get_profile())
            else:
                return denied()
        else:
            raise ValueError("Unknown action: %s" % options["action"])

def make_registration_form(user):
    pos_choices = [p for p in permissions.get_allowed_positions(user)]
    class RegistrationForm(forms.Form):
        username   = forms.CharField(label='Username', max_length=30)
        first_name = forms.CharField(label='First Name', max_length=30)
        last_name  = forms.CharField(label='Last Name', max_length=30)
        email      = forms.CharField(label='E-mail Address', max_length=75)
        pw_method  = forms.ChoiceField(label='Password assignment',
                                       choices=(('email','Email random password'),
                                                ('raven','Require raven login'),
                                                ('given','Set password given below')),
                                       widget=forms.widgets.RadioSelect)
        pw         = forms.CharField(label='Password',
                                     widget=forms.PasswordInput(render_value=False),
                                     required=False)
        pos        = forms.ChoiceField(label='Position', choices=pos_choices)

        # See if we're allowed to add users at different organizations; if we
        # are, show a choice of organizations
        if permissions.allowed_user_access_create_different_org(user):
            orgs = db.Organization.objects.all()
            org_choices = [(o.name, o.name) for o in orgs]
            org = forms.ChoiceField(label='Organization',
                                    choices=org_choices)

        def clean_username(self):
            un = self.cleaned_data['username']
            if not re.match('^\w+$', un):
                raise forms.ValidationError("Only alphanumeric characters and underscores are allowed in a user's name.")
            return un

        def clean(self):
            """Makes sure that the form data is valid; in particular, that a
            password has been supplied if the choice of login method requires
            it."""
            login = self.cleaned_data['pw_method']
            pw = self.cleaned_data['pw']
            if login == 'given' and len(pw) < 6:
                raise forms.ValidationError("Password must be at least 6 characters")
            return self.cleaned_data

    return RegistrationForm

def user_create(request):

    tn = 'vns/user_create.html'
    RegistrationForm = make_registration_form(request.user)
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            
            try:
                # Get the form data
                username = form.cleaned_data['username']
                first_name = form.cleaned_data['first_name']
                last_name = form.cleaned_data['last_name']
                email = form.cleaned_data['email']
                pw = form.cleaned_data['pw']
                pw_method = form.cleaned_data['pw_method']
                pos = form.cleaned_data['pos']
                pos = int(pos)

                # If we've been given an organization, use that org; otherwise
                # use the org of the user who's creating the new user
                try:
                    org_name = form.cleaned_data['org']
                    org = db.Organization.objects.get(name=org_name)
                except KeyError:
                    org = request.user.get_profile().org

                # Check that we're allowed to create a user with this position/organization
                if not permissions.allowed_user_access_create(request.user, pos, org):
                    messages.error(request, "You cannot create this user")
                    return HttpResponseRedirect('/user/create')

                # Work out what password to set
                if pw_method == "email":
                    pw = User.objects.make_random_password()
                elif pw_method == "raven":
                    pw = None

                # Try to create the user
                try:
                    user = User.objects.create_user(username, email, pw)
                except IntegrityError:
                    messages.error(request, "Unable to create the user: the requested username '%s' is already taken" % username)
                    return direct_to_template(request, tn, { 'form': form })
                user.last_name = last_name
                user.first_name = first_name
                user.groups.add(Group.objects.get(name=db.UserProfile.GROUPS[pos]))

                # Create the user profile
                up = db.UserProfile()
                up.user = user
                up.pos = pos
                up.org = org
                up.generate_and_set_new_sim_auth_key()

                # See if we need to create a superuser
                if (up.pos == 0):
                    user.is_staff = True
                    user.is_superuser = True

                # Save everything
                user.save()
                up.save()

                # Email the user their password, if necessary
                if pw_method == "email":
                    user.email_user("VNS Account", "The password for your "
                                    "new VNS account is %s\n\nPlease log "
                                    "in and change this ASAP." % pw)
                    
                messages.success(request, "Successfully created new user: %s" % username)
                return HttpResponseRedirect('/user/%s/' % username)

            except:
                # Unknown exception, probably the database isn't set up correctly
                try:
                    user.delete()
                except:
                    # Give up trying to do anything
                    pass
                # Re-raise the error, so we can see what's going on in debug mode
                raise
        else:
            messages.error(request, "Invalid form")
            return direct_to_template(request, tn, {'form':form})

    else:
        form = RegistrationForm()
        return direct_to_template(request, tn, { 'form': form })

class AdminChangePasswordForm(forms.Form):
    new_pw1  = forms.CharField(label='New Password', min_length=6, widget=forms.PasswordInput(render_value=False))
    new_pw2  = forms.CharField(label='New Password (again)', widget=forms.PasswordInput(render_value=False))

class ChangePasswordForm(forms.Form):
    old_pw   = forms.CharField(label='Current Password', widget=forms.PasswordInput(render_value=False))
    new_pw1  = forms.CharField(label='New Password', min_length=6, widget=forms.PasswordInput(render_value=False))
    new_pw2  = forms.CharField(label='New Password (again)', widget=forms.PasswordInput(render_value=False))

def user_change_pw(request, up):
    tn = 'vns/user_change_pw.html'
    is_admin = up.user != request.user
    Form = AdminChangePasswordForm if is_admin else ChangePasswordForm
    if request.method == 'POST':
        form = Form(request.POST)
        if form.is_valid():
            if not is_admin:
                old_pw = form.cleaned_data['old_pw']
            new_pw1 = form.cleaned_data['new_pw1']
            new_pw2 = form.cleaned_data['new_pw2']

            if new_pw1 != new_pw2:
                messages.error(request, "Try again: the two versions of your new password do not match.")
                return direct_to_template(request, tn, { 'form': form, 'un':up.user.username })

            if not is_admin and not authenticate(username=up.user.username, password=old_pw):
                messages.error(request, "Incorrect current password.")
                return direct_to_template(request, tn, { 'form': form, 'un':up.user.username })

            up.user.set_password(new_pw1)
            up.user.save()

            if is_admin:
                messages.success(request, "You have successfully updated %s's password." % up.user.username)
            else:
                messages.success(request, "You have successfully updated your password.")
            return HttpResponseRedirect('/user/%s/' % up.user.username)
    else:
        form = Form()

    return direct_to_template(request, tn, { 'form': form, 'un':up.user.username })

def user_renew_auth_key(request, up):
    up.generate_and_set_new_sim_auth_key()
    up.save()
    messages.success(request, "Auth key successfully changed for %s" % up.user.username)
    return HttpResponseRedirect("/user/%s/" % up.user.username)

def user_delete(request, up, **kwargs):

    # Check we're not doing this from a GET request
    if request.method != 'POST':
        return direct_to_template(request, 'vns/confirm.html',
                                  {'title': 'Delete user %s' % up.user.username,
                                   'button': 'Delete %s' % up.user.username,
                                   'url': '/user/%s/delete/' % up.user.username})

    # Mark the user as retired
    user = up.user
    un = user.username
    on = up.org.name
    up.retired = True
    up.save()

    # Insert journal entries to delete their topologies - the main VNS process
    # will delete them if it is safe
    for t in db.Topology.objects.filter(owner=up.user):
        je = db.JournalTopologyDelete()
        je.topology = t
        je.save()

    messages.success(request, mark_for_escaping("You have successfully deleted %s." % un))
    return HttpResponseRedirect('/org/%s/' % on)

def user_undelete(request, up, **kwargs):
    tn = 'vns/user_undelete.html'

    # If this isn't a POST request, then show a confirmation form
    if request.method != 'POST':
        return direct_to_template(request, tn,
                                  {'title':'Undelete user %s' % up.user.username,
                                   'button':'Undelete %s' % up.user.username, 
                                   'url':'/user/%s/undelete/' % up.user.username})

    user = up.user
    un = user.username
    on = up.org.name
    up.retired = False
    up.save()

    # Attempt to remove any pending topology deletions
    db.JournalTopologyDelete.objects.filter(topology__owner=up.user).delete()
    
    messages.success(request, "You have successfully restored %s; some of their topologies may not have been recovered." % un)
    return HttpResponseRedirect('/org/%s/' % on)

def user_profile(request, up):
    tn = 'vns/user_profile.html'
    topos_allowed = permissions.get_allowed_topologies(request.user)
    topos_owned = topos_allowed.filter(owner=up.user)
    topos_assigned = topos_allowed.filter(allowed_users=up.user)
    can_change = permissions.allowed_user_access_change(request.user, up.user)
    return direct_to_template(request, tn, {'up':up,
                                            'can_change':can_change,
                                            'topos_owned':topos_owned,
                                            'topos_assigned':topos_assigned})

def post_login(request):
    """Logs the fact that a user has just logged on."""
    try:
        up = request.user.get_profile()
    except AttributeError:
        return HttpResponseRedirect('/')
    up.last_login = datetime.datetime.now()
    up.save()
    return HttpResponseRedirect('/')
