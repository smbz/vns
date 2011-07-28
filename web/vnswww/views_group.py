from django import forms
from django.db import IntegrityError
from django.contrib import messages
from django.contrib.auth.models import User, Group
from django.views.generic.simple import direct_to_template
from django.http import HttpResponseRedirect

from vns.AddressAllocation import instantiate_template

import models as db
import permissions

def group_view(request, gn):
    """View a list of users in a group.  Does not show users that are not
    visible to the user making the request.
    @param request  An HttpRequest
    @oaram gn  The name of the group to view
    @return HttpResponse"""

    tn='vns/group_view.html'

    # Check this isn't a built-in group
    if gn in db.UserProfile.GROUPS.values():
        messages.error(request, "You cannot view built-in groups.")
        return HttpResponseRedirect("/groups/")

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login/')

    # Find the group
    try:
        group = Group.objects.get(name=gn)
    except Group.DoesNotExist:
        messages.error(request, "Group %s does not exist." % gn)
        return HttpResponseRedirect("/groups/")

    # Find the user profiles in this group which the user is allowed to see
    try:
        users = permissions.get_allowed_users(request.user)
        users = users.filter(user__groups=group)
    except User.DoesNotExist:
        messages.info(request, "There are no users in group %s which you "
                       "can view." % gn)
        return HttpResponseRedirect("/groups/")

    # Find the user profiles which this user is allowed to delete
    l = lambda up: permissions.allowed_user_access_delete(request.user, up.user)
    deletable_users = filter(l, list(users))

    # Switch to a template to print them out
    return direct_to_template(request, tn, {'users':users,
                                            'group':group,
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
    """Add many new users, and possibly put them in a group.
    @param request  An HttpRequest
    @return HttpResponse"""
    tn='vns/group_add.html'

    GroupAddForm = make_group_add_form(request.user)
    if request.method == 'POST':
        form = GroupAddForm(request.POST)
        if form.is_valid():
            group_name = form.cleaned_data['group_name']
            pos = form.cleaned_data['pos']
            users = form.cleaned_data['users']

            # Check that the group is not a group with permissions
            if group_name in db.UserProfile.GROUPS.values():
                messages.error(request, "You cannot create a group called %s." % group_name)

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

def group_delete(request, gn):
    """Deletes all the users in a group that the user can delete.
    @param request  An HTTP request
    @param gn  The name of the group to delete
    @return HttpResponse"""

    # Check this isn't a built-in group
    if gn in db.UserProfile.GROUPS.values():
        messages.error(request, "You cannot delete built-in groups.")
        return HttpResponseRedirect("/groups/")

    # Get the group
    try:
        group = Group.objects.get(name=gn)
    except Group.DoesNotExist:
        messages.error(request, "This group does not exist")
        return HttpResponseRedirect('/')

    # Get all users in the group
    try:
        users = User.objects.filter(groups=group)
    except User.DoesNotExist:
        group.delete()
        messages.error(request, "There are no users in this group")
        return HttpResponseRedirect('/')

    # Do permission checking and mark the users as retired if
    # the permission check passes
    no_perms = False
    has_deleted = False
    for u in users:
        if permissions.allowed_user_access_delete(request.user, u):
            u.get_profile().retired=True
            u.save()
            has_deleted = True

            # Delte any topologies this user owns
            topos = db.Topology.filter(owner=u)
            for t in topos:
                t.delete()
        else:
            no_perms = True

    # If the group is empty, delete it
    if not no_perms:
        group.delete()
    
    # Display a message indicating eny errors or success
    if no_perms and not has_deleted:
        messages.error(request, "Could not delete users because of permissions.")
    elif no_perms and has_deleted:
        messages.info(request, "Some users could not be deleted because of permissions.  Other users have been deleted.")
    else:
        messages.success(request, "Successfully deleted group %s" % gn)

    return HttpResponseRedirect('/')

def group_topology_delete(request, gn):
    """Delete any topologies owned by users in this group.
    @param request  An HttpRequest
    @param gn  The name of the group to delete
    @return HttpResponse"""

    # Check this isn't a built-in group
    if gn in db.UserProfile.GROUPS.values():
        messages.error(request, "You cannot change built-in groups.")
        return HttpResponseRedirect("/groups/")

    # Get the group, users and topologies
    group = Group.objects.get(name=gn)
    users = User.objects.filter(groups=group)
    topos = db.Topology.objects.filter(owner__in=users)

    # Try to delete the topologies, with permissions checking
    no_perms = False
    has_deleted = False
    for t in topos:
        if permissions.allowed_topology_access_delete(request.user, t):
            t.delete()
            has_deleted = True
        else:
            no_perms = True

    # Display either a success message or a helpful error message
    if no_perms and not has_deleted:
        messages.error(request, "You do not have permission to delete topologies from this group")
        return HttpResponseRedirect('/')
    elif no_perms and has_deleted:
        messages.info(request, "You do not have permissions to delete some of the topologies "
                      "from this group, but some other topologies have been deleted.")
        return HttpResponseRedirect('/')
    else:
        messages.success(request, "Topologies for this group have been successfully deleted.")
        return HttpResponseRedirect('/')

def group_topology_create(request, gn):
    """Create topologies for a group, with each user in the group becoming the
    owner of one topology.
    @param request  An HttpRequest
    @param gn  The name of the group to add the topologies for"""

    tn = "vns/group_topology_create.html"

    # Check this isn't a built-in group
    if gn in db.UserProfile.GROUPS.values():
        messages.error(request, "You cannot change built-in groups.")
        return HttpResponseRedirect("/groups/")

    # Check we're allowed to create topologies
    if not permissions.allowed_topology_access_create(request.user):
        messages.info("Please login as a user who is permitted to create topologies.")
        return HttpResponseRedirect('/login/?next=/topology/create/')

    # Get the group
    try:
        group = Group.objects.get(name=gn)
    except Group.DoesNotExist:
        messages.error("No group %s" % gn)
        return HttpResponseRedirect("/groups/")

    # Import a function to create the form
    from views_topology import make_ctform
    CreateTopologyForm = make_ctform(request.user)
    
    if request.method == "POST":
        form = CreateTopologyForm(request.POST)
        if form.is_valid():
            template_id = form.cleaned_data['template']
            ipblock_id = form.cleaned_data['ipblock']
            num_to_create = form.cleaned_data['num_to_create']

            # Do lots of permissions and existence checks - need a topology
            # template and IP block
            try:
                template = db.TopologyTemplate.objects.get(pk=template_id)
            except db.TopologyTemplate.DoesNotExist:
                messages.error(request, "No such template")
                return direct_to_template(request, tn, { 'form': form,
                                                         'group': group})

            try:
                ipblock = db.IPBlock.objects.get(pk=ipblock_id)
            except db.IPBlock.DoesNotExist:
                messages.error(request, "No such IP block")
                return direct_to_template(request, tn, { 'form': form,
                                                         'group': group})

            if not permissions.allowed_topologytemplate_access_use(request.user, template):
                messages.error(request, "You cannot create topologies from this template")
                return direct_to_template(request, tn, { 'form': form,
                                                         'group': group})
            
            if not permissions.allowed_ipblock_access_use(request.user, ipblock):
                messages.error(request, "You cannot create topologies in this IP block")
                return direct_to_template(request, tn, { 'form': form,
                                                         'group': group})

            if num_to_create > 30:
                messages.error(request, "You cannot create >30 topologies at once")
                return direct_to_template(request, tn, { 'form': form,
                                                         'group': group})
            # Get a list of users
            try:
                users = User.objects.filter(groups=group)
            except User.DoesNotExist:
                messages.error("No users in this group to create topologies for")
                return HttpResponseRedirect("/")

            # Otherwise, we're good to actually create the topologies, subject
            # to permissions checks on each user.
            # These variables track the number with permissions errors, the
            # number successfully created and the number rwith other errors
            # to report to the user.
            num_perms = 0
            num_created = 0
            num_errs = 0
            for u in users:
                
                # Check we have permission to change this user
                if not permissions.allowed_user_access_change(request.user, u):
                    num_perms += 1
                    continue

                # Create the topology
                err,_,_,_ = instantiate_template(org=u.get_profile().org,
                                                 owner=u,
                                                 template=template,
                                                 ip_block_from=ipblock,
                                                 src_filters=[],
                                                 temporary=False)
                
                # Update the numbers with/without errors
                if err is not None:
                    num_errs += 1
                else:
                    num_created += 1

            # Report to the user
            topology_create_message(request, num_errs, num_perms, num_created)
            return HttpResponseRedirect('/group/%s/' % gn)

        else:
            # The form is not valid
            messages.error(request, "Invalid form")
            return direct_to_template(request, tn, {'form':form,
                                                    'group':group})

    else:
        # request.method != 'POST'
        # Need to give them a form but do nothing else
        return direct_to_template(request, tn, {'form':CreateTopologyForm(),
                                                'group':group})

def topology_create_message(request, num_errs, num_perms, num_created):
    """Create and show a message describing any error conditions"""
    # Note that the case num_perms == num_errs == num_created == 0
    # cannot occur, because users is guaranteed to have at least one entry
    if num_perms == 0 and num_errs == 0:
        messages.success(request, "Successfully created %d topologies." % num_created)
    elif num_created == 0 and num_errs == 0:
        messages.error(request, "You did not have permission to create "
                       "topologies for %d users.  No topologies have "
                       "been created." % num_perms)
    elif num_created == 0 and num_perms == 0:
        messages.error(request, "There were errors creating topologies "
                       "for %d users.  No topologies have been created."
                       % num_errs)
    elif num_created == 0:
        messages.error(request, "You do not have permission to create "
                       "topologies for %d users, and there were "
                       "unknown errors creating topologies for %d "
                       "users.  No topologies have been created."
                       % (num_perms, num_errs))
    elif num_perms == 0:
        messsages.info(request, "There were errors creating topologies "
                       "for %d users but %d topologies were still "
                       "created successfully." % (num_errs, num_created))
        
    elif num_errs == 0:
        messages.info(request, "You do not have permission to create "
                      "topologies for %d users, but %d topologies for "
                      "other users were created successfully." % 
                      (num_perms, num_created))
    else:
        messages.info(request, "%d topologies were successfully "
                      "created, %d had permissions errors and %d had "
                      "other errors." % (num_created, num_perms,
                                         num_errs)
                      )
