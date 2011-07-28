from django import forms
from django.db import IntegrityError
from django.contrib import messages
from django.contrib.auth.models import User, Group
from django.views.generic.simple import direct_to_template
from django.http import HttpResponseRedirect

import models as db
import permissions

def group_view(request, gn):
    tn='vns/group_view.html'

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login/')

    # Find the user profiles in this group which the user is allowed to see
    users = permissions.get_allowed_users(request.user)
    users = users.filter(user__groups__name=gn)

    # Find the user profiles which this user is allowed to delete
    l = lambda up: permissions.allowed_user_access_delete(request.user, up.user)
    deletable_users = filter(l, list(users))

    # Switch to a template to print them out
    return direct_to_template(request, tn, {'users':users,
                                            'deletable_users':deletable_users})

class UserError(Exception):
    pass

class UserSyntaxError(UserError):
    pass

class UserUserError(UserError):
    pass

class UserGroupError(UserError):
    pass

class UserPermissionError(UserError):
    pass

def insert_users(user, users, group_name, pos):
    """Inserts user into the database.  If an exception is raised, no changes
    are made to the DB.
    @param users  A string listing users, one per line, whitespace-
    separated, of the form <username> <email> <firstname> <lastname>.
    Any lines starting with # are ignored, as are blank lines.
    @param user  The user who is creating the other users
    @param group_name  The name of the group to add the users to - empty or None
    implies no group
    @param pos  An int giving the position of the new users
    @exception UserSyntaxError if there is a syntax error in users
    @exception UserGroupError if a group by that name already exists
    @exception UserUserError if a user by that name already exists
    @exception UserPermissionError if the user creating the users doesn't have
    the right permission"""

    include_group = group_name != "" and group_name != None

    userlist = []
    
    lines = users.splitlines()
    for i,l in enumerate(lines):
        l = l.strip()
        if l == "" or l.startswith("#"):
            continue
        
        toks = l.split(None, 3)
        if len(toks) < 4:
            raise UserSyntaxError("Syntax error on line %d: too few tokens")
        username = toks[0]
        email = toks[1]
        firstname = toks[2]
        lastname = toks[3]
        userlist.append( (username, email, firstname, lastname) )

    # Check that the group doesn't exist
    if include_group:
        try:
            group = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            pass
        else:
            raise UserGroupError("Error: That group already exists")

    # Check that the users don't exist; put any that do in a list
    existing_users = []
    for (username, _, _, _) in userlist:
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            pass
        else:
            existing_users.append(username)
    
    # If users do already exist, format the list in a nice way and raise an error
    if len(existing_users) != 0:
        display_list = ', '.join(existing_users[0:5])
        if len(existing_users) > 5:
            display_list += ", ..."
        raise UserUserError("Error: %d user(s) already exist: %s" % (len(existing_users), display_list))

    # Add the group to the DB
    if include_group:
        try:
            group = Group()
            group.name = group_name
            group.save()
        except IntegrityError:
            raise UserGroupError("Error: That group already exists")

    if not permissions.allowed_user_access_create(user, pos, user.get_profile().org):
        raise UserPermissionError("Error: You do not have permission to create "
                                  " that type of user at that organization.")

    # Add the new users to the DB, since we haven't had any errors
    for (username, email, firstname, lastname) in userlist:
        
        # Create the django user - password is None, so they won't initially be able to log in
        new_user = User.objects.create_user(username, email, None)
        print("%s %s" % (firstname, lastname))
        new_user.first_name = firstname
        new_user.last_name = lastname
        pos_group = Group.objects.get(name=db.UserProfile.GROUPS[pos])
        new_user.groups.add(pos_group)
        if include_group:
            new_user.groups.add(group)
        
        # Create the user profile
        up = db.UserProfile()
        up.user = new_user
        up.pos = pos
        up.org = user.get_profile().org
        up.generate_and_set_new_sim_auth_key()

        new_user.save()
        up.save()

def make_group_add_form(user):
    pos_choices = list(permissions.get_allowed_positions(user))
    class GroupAddForm(forms.Form):
        group_name = forms.CharField(label='Group name', max_length=30)
        pos = forms.ChoiceField(label='Position', choices=pos_choices)
        users = forms.CharField(label='Users, e.g. fs123 fs123@example.com Fred Smith',
                                widget=forms.Textarea)
    return GroupAddForm

def group_add(request):
    """Add many new users, and possibly put them in a group"""
    tn='vns/group_add.html'

    GroupAddForm = make_group_add_form(request.user)
    if request.method == 'POST':
        form = GroupAddForm(request.POST)
        if form.is_valid():
            group_name = form.cleaned_data['group_name']
            pos = form.cleaned_data['pos']
            users = form.cleaned_data['users']

            # Parse the list of users
            try:
                insert_users(request.user, users, group_name, int(pos))
            except UserError as e:
                messages.error(request, str(e))
                return HttpResponseRedirect('/group/create/')

            messages.success(request, 'Users added successfully')
            return HttpResponseRedirect('/')

        else:
            messages.error(request, 'Invalid form')
            return HttpResponseRedirect('/group/create')

    else:
        form = GroupAddForm()
        return direct_to_template(request, tn, {'form':form})
