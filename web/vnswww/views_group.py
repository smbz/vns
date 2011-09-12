import re
from string import Template

from django import forms
from django.db import IntegrityError
from django.contrib import messages
from django.contrib.auth.models import User, Group
from django.views.generic.simple import direct_to_template
from django.http import HttpResponseRedirect

from vns.AddressAllocation import instantiate_template

import models as db
import permissions

def group_access_check(request, callee, action, **kwargs):
    """Checks that the user can access the functions they're trying to, and
    if they can calls callee.
    @param request  An HTTP request
    @param callee  Gives the Callable to call
    @param action  One of "add", "change", "use", "delete", describing the
    permissions needed
    @param gid  The ID of the group in question; not used for
    action = "add"
    @exception ValueError  If an action is unrecognised
    @exception KeyError  If an option is missing
    @return HttpResponse"""

    def denied():
        """Generate an error message and redirect if we try do something to a
        group we're not allowed to"""
        messages.error(request, "Either this group doesn't exist or you don't "
                                "have permission to %s it." % action)
        return HttpResponseRedirect('/login/')

    def denied_add():
        """Generate an error message and redirect if we try to create a group
        and are not allowed to"""
        messages.error(request, "You don't have permission to create groups.")
        return HttpResponseRedirect('/login/')

    
    # If we're trying to add a group, don't need to get the group itself
    if action == "add":
        if permissions.allowed_group_access_create(request.user):
            return callee(request)
        else:
            return denied_add()

    else:

        # Try getting the group - if it doesn't exist, show the same message
        # as for permission denied.  If we don't have org / group name
        # arguments, django will show an internal error, which is what we want.
        gn = kwargs['gn']
        on = kwargs['on']
        try :
            group = db.Group.objects.get(org__name=on, name=gn)
        except db.Group.DoesNotExist:
            return denied()

        if action == "use":
            if permissions.allowed_group_access_use(request.user, group):
                 return callee(request, group=group, **kwargs)
            else:
                return denied()
        elif action == "change":
            if permissions.allowed_group_access_change(request.user, group):
                return callee(request, group=group, **kwargs)
            else:
                return denied()
        elif action == "delete":
            if permissions.allowed_group_access_delete(request.user, group):
                return callee(request, group=group, **kwargs)
            else:
                return denied()
        else:
            raise ValueError("Unknown action: %s" % options["action"])


def group_list(request, on=None):
    """View a list of groups; doesn't show groups which are not visible to the
    user making the request.  Note that both the group name and the organization
    are needed to specify the group uniquely.
    @param request An HttpRequest
    @param on  The name of the organization for which to show groups"""
    
    # The name of the template to view the list through
    tn = 'vns/groups.html'

    if on is not None:
        # Get the organization from the database
        try:
            org = db.Organization.objects.get(name=on)
        except db.Organization.DoesNotExist:
            messages.error(request, "No such organization: %s" % on)
            return HttpResponseRedirect('/organizations/')

        # Get a list of groups
        groups = list(db.Group.objects.filter)

    else:
        # on is None - we want all groups
        groups = list(db.Group.objects.all())

    # Filter the list so that we only see groups we're allowed to
    pred = lambda g: permissions.allowed_group_access_use(request.user, g)
    groups = filter(pred, groups)

    # Give the groups to a template to display
    return direct_to_template(request, tn, {'groups':groups})


def group_view(request, group, **kwargs):
    """View a list of users in a group.  Does not show users that are not
    visible to the user making the request.
    @param request  An HttpRequest
    @oaram group  The group to view
    @return HttpResponse"""

    tn='vns/group_view.html'

    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login/')

    # Find the user profiles in this group which the user is allowed to see
    try:
        users = permissions.get_allowed_users(request.user)
        users = users.filter(user__vns_groups=group)
    except User.DoesNotExist:
        messages.info(request, "There are no users in group %s which you "
                       "can view." % gn)
        return HttpResponseRedirect("/%s/groups/" % request.user.org.name)

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

def insert_users(user, users, group_name, pos, org, create_and_email_pw=False):
    """Inserts user into the database.  If an exception is raised, no changes
    are made to the DB.
    @param users  A string listing users, one per line, whitespace-
    separated, of the form <username> <email> <firstname> <lastname>.
    Any lines starting with # are ignored, as are blank lines.
    @param user  The user who is creating the other users
    @param group_name  The name of the group to add the users to - empty or None
    implies no group
    @param pos  An int giving the position of the new users
    @param org  An Organization to which the group and users will belong
    @exception UserSyntaxError if there is a syntax error in users
    @exception UserGroupError if a group by that name already exists
    @exception UserUserError if a user by that name already exists or there
    is an invalid username
    @exception UserPermissionError if the user creating the users doesn't have
    the right permission"""

    include_group = group_name != "" and group_name != None

    userlist = []

    # Parse the lines and add the user details to userlist; check that all the
    # usernames are valid
    lines = users.splitlines()
    for i,l in enumerate(lines):
        l = l.strip()
        if l == "" or l.startswith("#"):
            continue
        
        toks = l.split(',')
        if len(toks) != 4:
            raise UserSyntaxError("Syntax error on line %d: expected a line of "
                                  "the form <username>, <email>, <firstname>, <lastname>")
        username = toks[0].strip()
        email = toks[1].strip()
        firstname = toks[2].strip()
        lastname = toks[3].strip()
        userlist.append( (username, email, firstname, lastname) )

        # Check for valid username
        if re.match(r'^\w+$', username) is None:
            raise UserUserError("The username %s is invalid." % username)

    # Check that the group doesn't exist
    if include_group:
        try:
            _ = db.Group.objects.get(name=group_name, org=org)
        except db.Group.DoesNotExist:
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

    # Check we can create users at this position and organization
    if not permissions.allowed_user_access_create(user, pos, org):
        raise UserPermissionError("Error: You do not have permission to create "
                                  " that type of user at that organization.")

    # Check that we can create groups at this organization
    if not permissions.allowed_group_access_create(user, org):
        raise UserPermissionError("Error: You do not have permission to create "
                                  " groups at that organization.")

    # Add the group to the DB
    if include_group:
        try:
            group = db.Group()
            group.name = group_name
            group.org = org
            group.save()
        except IntegrityError:
            raise UserGroupError("Error: That group already exists")

    # Add the new users to the DB, since we haven't had any errors
    for (username, email, firstname, lastname) in userlist:
        
        # Create the django user
        new_user = User.objects.create_user(username, email, None)
        print("%s %s" % (firstname, lastname))
        new_user.first_name = firstname
        new_user.last_name = lastname
        pos_group = Group.objects.get(name=db.UserProfile.GROUPS[pos])
        new_user.groups.add(pos_group)
        if include_group:
            new_user.vns_groups.add(group)

        # Make the user a superuser if necessary
        if pos == 0:
            new_user.is_staff = True
            new_user.is_superuser = True
        
        # Create the user profile
        up = db.UserProfile()
        up.user = new_user
        up.pos = pos
        up.org = org
        up.generate_and_set_new_sim_auth_key()

        new_user.save()
        up.save()

        # If they need to have an initial password, set it and email it to them
        if create_and_email_pw:
            pw = User.objects.make_random_password()
            new_user.set_password(pw)
            print("Emailing %s with password" % new_user)
            new_user.email_user("VNS Account", "The password for your new VNS "
                                "account is %s\n\nPlease log in and change "
                                "this ASAP." % pw)
            new_user.save()

def make_group_add_form(user):
    """Makes a form for use with group_add.  Only shows options which are
    relevant to user's permissions.
    @param user  The User who will be shown this form"""
    pos_choices = list(permissions.get_allowed_positions(user))
    class GroupAddForm(forms.Form):
        group_name = forms.CharField(label='Group name', max_length=30)
        pos        = forms.ChoiceField(label='Position', choices=pos_choices)
        login      = forms.ChoiceField(label='Password allocation',
                                       choices=((0, 'External login only'),
                                                (1, 'Email random password')),
                                       widget=forms.widgets.RadioSelect)
        users      = forms.CharField(label='Users, e.g. fs123,fs123@example.com,Fred,Smith',
                                     widget=forms.Textarea)

        # See if we are allowed to create users at different organizations, and if
        # we are, make a field for it
        if permissions.allowed_user_access_create_different_org(user):

            # Get a list of organizations
            orgs = db.Organization.objects.all()
            org_choices = [(o.name, o.name) for o in orgs]
            org = forms.ChoiceField(label='Organization',
                                    choices=org_choices)

        def clean_group_name(self):
            """Ensure the group name is valid"""
            group_name = self.cleaned_data['group_name']
            if re.match(r'^\w+$', group_name) is None:
                raise forms.ValidationError("Group names can contain only alphanumeric characters and underscores")
            return group_name
    
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

            # Get form data which is guaranteed to be present
            group_name = form.cleaned_data['group_name']
            pos = form.cleaned_data['pos']
            login = form.cleaned_data['login']
            users = form.cleaned_data['users']

            # See if there is an organization field
            try:
                orgname = form.cleaned_data['org']
                org = db.Organization.objects.get(name=orgname)
            except KeyError:
                # We didn't give the user an option for organization
                org = request.user.get_profile().org

            # Parse the list of users
            try:
                insert_users(request.user, users, group_name, int(pos), org,
                             create_and_email_pw = (login == '1'))
            except UserError as e:
                messages.error(request, str(e))
                return direct_to_template(request, tn, {'form':form})

            messages.success(request, 'Users added successfully')
            return HttpResponseRedirect('/')

        else:
            messages.error(request, 'Invalid form')
            return direct_to_template(request, tn, {'form':form})

    else:
        form = GroupAddForm()
        return direct_to_template(request, tn, {'form':form})

def group_delete(request, group, **kwargs):
    """Deletes all the users in a group that the user can delete.
    @param request  An HTTP request
    @param group  The group to delete
    @return HttpResponse"""

    # Make sure this is a POST request
    if request.method != 'POST':
        return direct_to_template(request, 'vns/confirm.html',
                                  {'title':'Delete group %s from %s' % (group.name, group.org.name),
                                   'button':'Delete %s' % group.name,
                                   'url':'/org/%s/%s/delete' % (group.org.name, group.name)})

    # Get all users in the group
    try:
        users = User.objects.filter(vns_groups=group)
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
            up = u.get_profile()
            up.retired=True
            up.save()
            has_deleted = True

            # Delete any topologies this user owns
            topos = db.Topology.objects.filter(owner=u)
            for t in topos:
                je = db.JournalTopologyDelete()
                je.topology = t
                je.save()
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
        messages.success(request, "Successfully deleted group %s" % group.name)

    return HttpResponseRedirect('/')

def group_topology_delete(request, group, **kwargs):
    """Delete any topologies owned by users in this group.
    @param request  An HttpRequest
    @param group  The group to delete
    @return HttpResponse"""

    if request.method != 'POST':
        return direct_to_template(request, 'vns/confirm.html',
                                  {'title':'Delete topologies for group %s from %s'
                                   % (group.name, group.org.name),
                                   'button':'Delete topologies',
                                   'url':'/org/%s/%s/deletetopo/'
                                   % (group.org.name, group.name)})

    # Get the group, users and topologies
    users = User.objects.filter(vns_groups=group)
    topos = db.Topology.objects.filter(owner__in=users)

    # Insert journal entries for the main VNS process to delete the topologies,
    # subject to permissions checks
    no_perms = False
    has_deleted = False
    for t in topos:
        if permissions.allowed_topology_access_delete(request.user, t):
            je = db.JournalTopologyDelete()
            je.topology = t
            je.save()
            has_deleted = True
        else:
            no_perms = True

    # Display either a success message or a helpful error message
    if no_perms and not has_deleted:
        messages.error(request, "You do not have permission to delete topologies from this group")
        return HttpResponseRedirect('/')
    elif no_perms and has_deleted:
        messages.info(request, "You do not have permissions to delete some of the topologies "
                      "from this group, but some other topologies have been marked for deletion.")
        return HttpResponseRedirect('/')
    else:
        messages.success(request, "Topologies for this group have been marked for deletion.")
        return HttpResponseRedirect('/')

def make_ctform(user):
    user_org = user.get_profile().org
    parent_org = user_org.parentOrg
    template_choices = [(t.id, t.name) for t in permissions.get_allowed_templates(user)]
    ipblock_choices = [(t.id, str(t)) for t in permissions.get_allowed_ipblocks(user)]
    class CTForm(forms.Form):
        template = forms.ChoiceField(label='Template', choices=template_choices)
        ipblock = forms.ChoiceField(label='IP Block to Allocate From', choices=ipblock_choices)
        num_to_create = forms.IntegerField(label='# to Create per User', initial='1')
        ip_subnet = forms.IPAddressField(label='IP address subnet to allow', required=False)
        ip_subnet_mask = forms.IntegerField(label='Significant bits in subnet', required=False,
                                      min_value=0, max_value=32)

        def clean_ip_subnet_mask(self):
            try:
                ip_subnet_mask = self.cleaned_data['ip_subnet_mask']
            except KeyError:
                # The subnet shouldn't be provided either
                try:
                    ip_subnet = self.cleaned_data['ip_subnet']
                except KeyError:
                    return None
                else:
                    raise ValidationError("You must provide a subnet mask if "
                                          "you specify a subnet")
            
            try:
                ip_subnet = self.cleaned_data['ip_subnet']
            except KeyError:
                # We've provided a subnet mask but not a subnet
                raise ValidationError("You must provide a subnet if you "
                                      "specify a subnet mask")

            # Otherwise, we have both; check that the subnet mask is a suitable
            # size
            if ip_subnet_mask < 0 or ip_subnet_mask > 32:
                raise ValidationError("The subnet mask must be between 0 and "
                                      "32 inclusive")

            return ip_subnet_mask

    return CTForm

def group_topology_create(request, group, **kwargs):
    """Create topologies for a group, with each user in the group becoming the
    owner of one topology.
    @param request  An HttpRequest
    @param group  The group to add the topologies for"""

    tn = "vns/group_topology_create.html"

    # Check we're allowed to create topologies
    if not permissions.allowed_topology_access_create(request.user):
        messages.info("Please login as a user who is permitted to create topologies.")
        return HttpResponseRedirect('/login/?next=/topology/create/')

    # Import a function to create the form
    CreateTopologyForm = make_ctform(request.user)
    
    if request.method == "POST":
        form = CreateTopologyForm(request.POST)
        if form.is_valid():
            template_id = form.cleaned_data['template']
            ipblock_id = form.cleaned_data['ipblock']
            num_to_create = form.cleaned_data['num_to_create']
            ip = form.cleaned_data['ip_subnet']
            mask = form.cleaned_data['ip_subnet_mask']

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

            if num_to_create > 5:
                messages.error(request, "You cannot create >5 topologies / user at once")
                return direct_to_template(request, tn, { 'form': form,
                                                         'group': group})
            # Get a list of users
            try:
                users = User.objects.filter(vns_groups=group)
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

                # Make a list of source IP filters
                if ip != None and mask != None:
                    src_filters = [(ip, mask)]
                else:
                    src_filters = []

                # Create the topology
                for _ in range(0,num_to_create):
                    err,_,_,_ = instantiate_template(org=u.get_profile().org,
                                                     owner=u,
                                                     template=template,
                                                     ip_block_from=ipblock,
                                                     src_filters=src_filters,
                                                     temporary=False)
                
                    # Update the numbers with/without errors
                    if err is not None:
                        num_errs += 1
                    else:
                        num_created += 1

            # Report to the user
            topology_create_message(request, num_errs, num_perms, num_created)
            return HttpResponseRedirect('/org/%s/%s/' % (group.org.name, group.name))

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


class GroupEmailForm(forms.Form):
    subject = forms.CharField(label="Email subject")
    text = forms.CharField(label="Email text", widget=forms.Textarea)


def group_email(request, group, **kwargs):
    """Emails all users in a group with a user-input email"""
    
    tn = 'vns/group_email.html'

    if request.method == 'POST':
        form = GroupEmailForm(request.POST)
        
        if form.is_valid():

            # Get the fields from the form
            subject = form.cleaned_data['subject']
            text = form.cleaned_data['text']

            # Make a dict of tokens to replace which are the same for all users
            global_sub = {'GROUP' : group.name,
                          'ORGANIZATION' : group.org.name,
                          'ORGANISATION' : group.org.name}

            # Use python template strings to do these substitutions on the email
            text = Template(text).safe_substitute(global_sub)
            subject = Template(subject).safe_substitute(global_sub)

            # Loop through the users, sending each an email
            users = group.users.all()
            for u in users:

                # Make any user-specific substitutions
                sub = {'USERNAME' : u.username,
                       'FULLNAME' : u.get_full_name(),
                       'FIRSTNAME' : u.first_name,
                       'LASTNAME' : u.last_name}
                text = Template(text).safe_substitute(sub)
                subject = Template(subject).safe_substitute(sub)
                
                # Send the email
                u.email_user(subject, text)

            # Send a nice confirmation message
            messages.success(request, "Successfully emailed group %s" % group.name)
            return HttpResponseRedirect('/org/%s/%s/' % (group.org.name, group.name))

        else:
            return direct_to_template(request, tn, {'form':form, 'group':group})

    else:
        return direct_to_template(request, tn, {'form':GroupEmailForm(), 'group':group})
