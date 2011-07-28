from socket import inet_ntoa
import struct

from django import forms
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.views.generic.simple import direct_to_template
from django.http import HttpResponse, HttpResponseRedirect
from SubnetTree import SubnetTree

import models as db
import permissions
import crypto
from vns.AddressAllocation import instantiate_template
from vns.Topology import Topology as VNSTopology

def make_ctform(user):
    user_org = user.get_profile().org
    parent_org = user_org.parentOrg
    template_choices = [(t.id, t.name) for t in permissions.get_allowed_templates(user)]
    ipblock_choices = [(t.id, str(t)) for t in permissions.get_allowed_ipblocks(user)]
    class CTForm(forms.Form):
        template = forms.ChoiceField(label='Template', choices=template_choices)
        ipblock = forms.ChoiceField(label='IP Block to Allocate From', choices=ipblock_choices)
        num_to_create = forms.IntegerField(label='# to Create', initial='1')
    return CTForm

def topology_create(request):
    # make sure the user is logged in
    if not request.user.has_perm("vnswww.add_topology"):
        messages.info("Please login as a user who is permitted to create topologies.")
        return HttpResponseRedirect('/login/?next=/topology/create/')

    tn = 'vns/topology_create.html'
    CTForm = make_ctform(request.user)
    if request.method == 'POST':
        form = CTForm(request.POST)
        if form.is_valid():
            template_id = form.cleaned_data['template']
            ipblock_id = form.cleaned_data['ipblock']
            num_to_create = form.cleaned_data['num_to_create']

            try:
                template = db.TopologyTemplate.objects.get(pk=template_id)
            except db.TopologyTemplate.DoesNotExist:
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'invalid template' })

            try:
                ipblock = db.IPBlock.objects.get(pk=ipblock_id)
            except db.IPBlock.DoesNotExist:
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'invalid IP block'})

            if not permissions.allowed_topologytemplate_access_use(request.user, template):
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'you cannot create topologies from this template' })
            
            if not permissions.allowed_ipblock_access_use(request.user, ipblock):
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'you cannot create topologies in this IP block' })

            if num_to_create > 30:
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'you cannot create >30 topologies at once' })

            # TODO: should validate that request.user can use the requested
            #       template and IP block

            # try to create the topologies
            src_filters = []
            for i in range(num_to_create):
                err, _, _, _ = instantiate_template(request.user.get_profile().org,
                                                    request.user,
                                                    template,
                                                    ipblock,
                                                    src_filters,
                                                    temporary=False,
                                                    use_recent_alloc_logic=False,
                                                    public=False,
                                                    use_first_available=True)
                if err is not None:
                    messages.error(request, "Successfully allocated %d '%s' topologies from %s.  Failed to make the other request topologies: %s." % (i, template.name, ipblock, err))
                    return direct_to_template(request, tn)
            messages.success(request, "Successfully allocated %d '%s' topologies from %s." % (num_to_create, template.name, ipblock))
            return direct_to_template(request, tn)
    else:
        form = CTForm()

    return direct_to_template(request, tn, { 'form': form })

def topology_access_check(request, callee, action, **kwargs):
    """Checks that the user can access the functions they're trying to, and
    if they can calls callee.  There are two valid authentication methods - 
    django logihn, as normally used for the website, and a cryptographic token
    supplied in the HTTP GET, as used for clack.
    @param request  An HTTP request
    @param callee  Gives the Callable to call
    @param action  One of "add", "change", "use", "delete", describing the
    permissions needed
    @param tid  The ID of the topology in question; not used for
    action = "add"
    @exception ValueError  If an action is unrecognised
    @exception KeyError  If an option is missing
    @return HttpResponse"""

    def denied():
        """Generate an error message and redirect if we try do something to a
        topology we're not allowed to"""
        messages.error(request, "Either this topology doesn't exist or you don't "
                                "have permission to %s it." % action)
        return HttpResponseRedirect('/login/')

    def denied_add():
        """Generate an error message and redirect if we try to create a topology
        and are not allowed to"""
        messages.error(request, "You don't have permission to create topologies.")
        return HttpResponseRedirect('/login/')

    
    # If we're trying to add a template, don't need to get the template itself
    if action == "add":
        if permissions.allowed_topology_access_create(request.user):
            return callee(request)
        else:
            return denied_add()

    else:

        # Try getting the template - if it doesn't exist, show the same message
        # as for permission denied.  If we don't have a "tid" argument, django
        # will show an internal error, which is what we want.
        tid = int(kwargs["tid"])
        kwargs["tid"] = tid
        try :
            topo = db.Topology.objects.get(pk=tid)
        except db.Topology.DoesNotExist:
            return denied()

        if action == "use":
            # See if there is an HTTP GET token - if there is, try to use the token
            # method for authentication
            try:
                token = request.GET["token"]
            except KeyError:
                pass
            else:
                # See if the token is valid
                user = crypto.validate_token(token)
                if user != None and permissions.allowed_topology_access_use(user, topo):
                    request.user = user
                    return callee(request, topo=topo, **kwargs)
            if permissions.allowed_topology_access_use(request.user, topo):
                 return callee(request, topo=topo, **kwargs)
            else:
                return denied()

        elif action == "change":
            if permissions.allowed_topology_access_change(request.user, topo):
                return callee(request, topo=topo, **kwargs)
            else:
                return denied()
        elif action == "delete":
            if permissions.allowed_topology_access_delete(request.user, topo):
                return callee(request, topo=topo, **kwargs)
            else:
                return denied()
        else:
            raise ValueError("Unknown action: %s" % options["action"])

    

def topology_info(request, tid, topo):    
    # Create an authentication token valid for 30 minutes for the user to access
    # Clack stuff with
    token = crypto.create_token(request.user, 1800)
    
    # See what permissions the user has on this topology
    can_change = permissions.allowed_topology_access_change(request.user, topo)
    can_delete = permissions.allowed_topology_access_change(request.user, topo)
    return direct_to_template(request, 'vns/topology.html', {'t':topo,
                                                             'tid':tid,
                                                             'token':token,
                                                             'change':can_change,
                                                             'delete':can_delete})

@login_required
def topologies_list(request):

    # Get a QuerySet of the topologies we have access to
    topos = permissions.get_allowed_topologies(request.user)

    # Order the topologies by organization
    topos = topos.order_by('owner__userprofile__org__name', 'owner__username', 'template__name', 'id')

    orgs = {}
    # count the number of times each org/owner/template appears
    for t in topos:
        v, owners = orgs.get(t.owner.get_profile().org.name, (0,{}))
        orgs[t.owner.get_profile().org.name] = (v + 1, owners)
        v, templates = owners.get(t.owner.username, (0,{}))
        owners[t.owner.username] = (v + 1, templates)
        v = templates.get(t.template.name, 0)
        templates[t.template.name] = v + 1
    
    # embed counts of how many of the next orgs/owners/templates are the same as
    # the first one in each streak of these (hierarchical); 0 if not first
    pon = pun = ptn = None
    for t in topos:
        on = t.owner.get_profile().org.name
        un = t.owner.username
        tn = t.template.name
        
        t.org_num = t.owner_num = t.template_num = 0
        
        if on != pon:
            pun = None
            t.org_num, owners = orgs[on]
        
        if un != pun:
            ptn = None
            t.owner_num, templates = owners[un]
            
        if tn != ptn:
            t.template_num = templates[tn]
        
        pon = on
        pun = un
        ptn = tn
    
    return direct_to_template(request, 'vns/topologies.html', {'topos_list':topos})


def make_apu_form(user, topo):
    user_org = user.get_profile().org
    existing_allowed_users = topo.allowed_users.all()
    user_choices = [(up.user.username,up.user.username) for up in db.UserProfile.objects.filter(org=user_org, retired=False).exclude(user=user).exclude(user__in=existing_allowed_users)]

    class APUForm(forms.Form):
        usr = forms.ChoiceField(label='User', choices=user_choices)
    return APUForm

def topology_permitted_user_add(request, tid, topo):
    tn = 'vns/topology_add_permitted_user.html'
    APUForm = make_apu_form(request.user, topo)
    if request.method == 'POST':
        form = APUForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['usr']

            try:
                user = db.UserProfile.objects.get(user__username=username, retired=False).user
            except db.UserProfile.DoesNotExist:
                return direct_to_template(request, tn, {'form':form, 'more_error':'invalid username', 'tid':tid})

            if topo.owner == user:
                messages.error(request, 'This topology is already owned by %s.' % username)
                return HttpResponseRedirect('/topology%d/' % tid)

            topo.allowed_users.add(user)
    else:
        form = APUForm()
    return direct_to_template(request, tn, {'form':form, 'tid':tid })

def topology_permitted_user_remove(request, tid, topo, un):
    user = User.objects.get(username=un)
    topo.allowed_users.remove(user)
    messages.success(request, "Successfully removed %s from the permitted users for topology %d." % (un, tid))
    return HttpResponseRedirect('/topology%d/' % tid)

class APSIPForm(forms.Form):
    ip = forms.IPAddressField(label='IP Subnet')
    mask = forms.ChoiceField(label='Mask', choices=map(lambda x : (x,'/%d'%x), range(1,33)))

def topology_permitted_sip_add(request, tid, topo):
    tn = 'vns/topology_add_permitted_sip.html'
    if request.method == 'POST':
        form = APSIPForm(request.POST)
        if form.is_valid():
            ip = str(form.cleaned_data['ip'])
            mask = int(form.cleaned_data['mask'])

            # build a tree of existing filters
            st = SubnetTree()
            st['0/0'] = False # default value
            for x in db.TopologySourceIPFilter.objects.filter(topology=topo):
                sn = str('%s/%d' % (x.ip, x.mask))
                st[sn] = sn

            # check that the new filter isn't covered by one of the existing ones
            new_sn = '%s/%d' % (ip, mask)
            sn_within = st[ip]
            if sn_within:
                messages.error(request, 'The range %s is already covered by the existing filter %s.' % (new_sn, sn_within))
                return HttpResponseRedirect('/topology%d/' % tid)
            else:
                new_sip = db.TopologySourceIPFilter()
                new_sip.topology = topo
                new_sip.ip = ip
                new_sip.mask = mask
                new_sip.save()
                messages.success(request, "%s (%s) has been added to the permitted source IP range list." % (new_sip.subnet_mask_str(), new_sn))
                return HttpResponseRedirect('/topology%d/' % tid)
    else:
        form = APSIPForm()
    return direct_to_template(request, tn, {'form':form, 'tid':tid })

def topology_permitted_sip_remove(request, tid, topo, sn):
    success = False
    try:
        for x in db.TopologySourceIPFilter.objects.filter(topology=topo):
            if sn == x.subnet_mask_str():
                x.delete()
                messages.success(request, "%s is no longer a permitted source IP range on this topology." % sn)
                success = True
                break
    except db.TopologySourceIPFilter.DoesNotExist:
        pass
    if not success:
        messages.error(request, "%s isn't a permitted source IP range on this topology anyway." % sn)
    return HttpResponseRedirect('/topology%d/' % tid)

def topology_delete(request, tid, topo, **kwargs):
    topo.delete()
    messages.success(request, 'Topology %d has been deleted.' % tid)
    return HttpResponseRedirect('/topologies/')

def topology_readme(request, tid, topo):
    return HttpResponse(topo.get_readme(), mimetype='text/plain')

def topology_rtable(request, tid, topo):
    return HttpResponse(topo.get_rtable(), mimetype='text/plain')

def topology_to_xml(request, tid, topo):
    """Creates XML that can be loaded with the Clack Graphical Router.
    @param request  An HTTP request
    @param tid  Database ID of the topology to convert to XML
    @param topo  The topology to convert to XML"""
    # The argument topo is the DB's Topology object passed from the access  
    # checker - ignore it and instead create the needed vns.Topology object.
    topo = VNSTopology(tid, None, None, request.user, False)
    
    # populate xml IDs
    id = 1
    for node in topo.nodes:
        for intf in node.interfaces:
            intf.xml_id = id
            id += 1

    # build XML for nodes
    nodes_xml = ''
    for node in topo.nodes:
        for intf in node.interfaces:
            if intf.link:
                intf.neighbors = [str(intf.link.get_other(intf).xml_id)]
            else:
                intf.neighbors = []

        virtual = node.get_type_str() == 'Virtual Node'
        xml_hdr = '<host name="%s" offlimits="%d">\n' % (node.name, not virtual)
        xml_body = ''
        itag = ('v' if virtual else 'e') + 'interface'
        for intf in node.interfaces:
            xml_body += '<%s id="%d" name="%s" neighbors="%s" ip="%s" mask="%s" addr="%s"></%s>' % (
                        itag, intf.xml_id, intf.name, ','.join(intf.neighbors),
                        inet_ntoa(intf.ip), inet_ntoa(intf.mask),
                         ':'.join(['%02X' % struct.unpack('B', b)[0] for b in intf.mac]), itag)
        nodes_xml += xml_hdr + xml_body + '</host>\n'

    # build the topology's XML
    xml = '<topology id="%d" server="%s" port="3250">\n%s</topology>' % (topo.id, request.META['SERVER_NAME'], nodes_xml)
    return HttpResponse(xml, mimetype='text/xml')
