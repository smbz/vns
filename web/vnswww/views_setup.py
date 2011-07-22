from django.contrib import messages
from django.contrib.auth.models import User, Group, Permission
from django.forms import Form, CharField, BooleanField, IPAddressField, IntegerField
from django.http import HttpResponseRedirect
from django.views.generic.simple import direct_to_template

import models as db
from vns import initial
from views_topologytemplate import insert_topologytemplate

class SetupForm(Form):
    first_name = CharField(label="Your first name", max_length=30)
    last_name = CharField(label="Your last name", max_length=30)
    organization_name = CharField(label="Organization name", max_length=64)
    server_ip = IPAddressField(label="Server IP address")
    gateway_ip = IPAddressField(label="Gateway IP address")
    gateway_mac = CharField(label="Gateway MAC address, e.g. 01:23:45:67:89:AB")
    block_ip = IPAddressField(label="IP of block for which to allocate from topologies")
    block_mask = IntegerField(label="Significant bits in IP of block", max_value = 32, min_value = 0)
    default_templates = BooleanField(label="Import default topology templates", initial=True)

def do_setup_doc():
    from vns import initial

    # Get rid of all our current documentation
    for d in db.Doc.objects.filter():
        d.delete()

    for (name, text) in initial.DOCS.iteritems():
        d = db.Doc()
        d.name = name
        d.text = text
        d.save()

def setup_doc(request):
    """Refreshes all the documentation from the setup file"""
    if not request.user.is_superuser:
        messages.info(request, "Logon to set up VNS")
        return HttpResponseRedirect('/login/')
    do_setup_doc()
    messages.info(request, "Refreshed documentation")
    return HttpResponseRedirect('/')

def setup(request):
    """Allows a web-based setup for some initial settings.  Requires
    manage.py syncdb first."""

    tn = 'vns/setup.html'

    if not request.user.is_superuser:
        messages.info(request, "Logon to set up VNS")
        return HttpResponseRedirect('/login/')
    
    if request.method == 'POST':
        form = SetupForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            organization_name = form.cleaned_data['organization_name']
            default_templates = form.cleaned_data['default_templates']
            server_ip = form.cleaned_data['server_ip']
            gateway_ip = form.cleaned_data['gateway_ip']
            gateway_mac = form.cleaned_data['gateway_mac']
            block_ip = form.cleaned_data['block_ip']
            block_mask = form.cleaned_data['block_mask']

            # Create the default groups
            from vns import initial
            for (group, perms) in initial.GROUP_PERMS.iteritems():
                g = Group()
                g.name = group
                g.save()
                for perm in perms:

                    # If the "%all%" permission occurs, we assign that group
                    # all possible permissions
                    if perm == "%all%":
                        all_perms = Permission.objects.filter()
                        for p in all_perms:
                            g.permissions.add(p)
                        break
                    else:
                        p = Permission.objects.get(codename=perm)
                        g.permissions.add(p)
                g.save()

            # Create the organisation
            org = db.Organization()
            org.name = organization_name
            org.boss = request.user
            org.save()

            # Create a user profile for our admin
            up = db.UserProfile()
            up.user = request.user
            up.pos = db.UserProfile.ADMIN
            up.org = org
            up.generate_and_set_new_sim_auth_key()
            up.save()

            # Create a simulator
            sim = db.Simulator()
            sim.name = "VNS"
            sim.ip = server_ip
            sim.gatewayIP = gateway_ip
            sim.gatewayMAC = gateway_mac
            sim.save()

            # Create an IP block
            b = db.IPBlock()
            b.org = org
            b.subnet = block_ip
            b.mask = block_mask
            b.usable_by_child_orgs = True
            b.simulator = sim
            b.save()

            # Create topology templates
            if default_templates:
                for (name, (description, readme, rtable)) in initial.TEMPLATES.iteritems():
                    insert_topologytemplate(description, rtable, readme, request.user, name)

            # Create the documentation
            do_setup_doc()

            messages.success(request, "VNS is now set up and ready to use!")
            return HttpResponseRedirect('/')

        else:
            messages.error("Invalid")
            return HttpResponseRedirect('/setup/')

    else:
        form = SetupForm()
        return direct_to_template(request, tn, { 'form':form })
