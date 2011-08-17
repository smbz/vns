from django import forms
from django.forms import CharField
from django.contrib import messages
from django.contrib.auth.decorators import permission_required, login_required
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.views.generic.simple import direct_to_template

import permissions
import models as db


def topologytemplate_access_check(request, callee, action, template_id=None):
    """Check that the user is allowed access, and if they are call the given
    Callable.
    @param request  An HTTP request
    @param callee  Gives the Callable to call
    @param action  One of "add", "change", "use", "delete", describing the
    permissions needed
    @param template_id  The ID of the template in question; not used for
    action = "add"
    @exception ValueError  If an action is unrecognised
    @exception KeyError  If an option is missing"""

    def denied():
        """Generate an error message and redirect if we try do something to a
        template we're not allowed to"""
        messages.error(request, "Either this topology template doesn't exist or"
                                " you don't have permission to %s it."
                       % action)
        return HttpResponseRedirect('/')

    def denied_add():
        """Generate an error message and redirect if we try to create a template
        and are not allowed to"""
        messages.error(request, "You don't have permission to create topology "
                                "templates.")
        return HttpResponseRedirect('/')
    
    # If we're trying to add a template, don't need to get the template itself
    if action == "add":
        if request.user.has_perm("vnswww.add_topologytemplate"):
            return callee(request)
        else:
            return denied_add()

    else:

        # Try getting the template - if it doesn't exist, show the same message
        # as for permission denied
        template_id = template_id
        try :
            template = db.TopologyTemplate.objects.get(id=template_id)
        except db.TopologyTemplate.DoesNotExist:
            return denied()

        if action == "use":
            if permissions.allowed_topologytemplate_access_use(request.user, template):
                return callee(request, template)
            else:
                return denied()
        elif action == "change":
            if permissions.allowed_topologytemplate_access_change(request.user, template):
                return callee(request, template)
            else:
                return denied()
        elif action == "delete":
            if permissions.allowed_topologytemplate_access_delete(request.user, template):
                return callee(request, template)
            else:
                return denied()
        else:
            raise ValueError("Unknown action: %s" % options["action"])


class TopologySyntaxError(Exception):
    """Raised by insert_topologytemplate if there is a syntax error."""
    pass

class TopologyNameError(Exception):
    """Raised by insert_topologytemplate if there is an unknown name."""
    pass

class TopologyArgumentError(Exception):
    """Raised by insert_topologytemplate if a line has the wrong number of arguments"""
    pass


def insert_topologytemplate(description, rtable, readme, user, template_name, visibility=db.TopologyTemplate.PROTECTED):
    """Parses a topology description and inserts the necessary fields into
    the DB."""

    # Check we don't already have a template by this name
    # TODO: change so that django doesn't require a unique name, so we don't
    # have to do this check which allows any user who can create a template to
    # see the names already in use
    duplicate = True
    try:
        _ = db.TopologyTemplate.objects.get(name = template_name)
    except db.TopologyTemplate.DoesNotExist:
        duplicate = False
    
    if duplicate:
        raise TopologyNameError("This topology name is already in use")
    
    # Dictionaries for the nodes, ports and links so we don't start putting
    # stuff in the DB and then come across an error

    # nodes is a dictionary mapping a node name to a type
    nodes = {}

    # paths maps names of webservers to paths
    paths = {}

    # ip_offsets maps node names to ip offsets
    ip_offsets = {}

    # ports is a dictionary mapping a node name to a list of interfaces
    ports = {}

    # links maps (name, iface) pairs together, and should be symmetric
    links = {}

    line_no = 0

    # List of node types that are grouped in Node
    # WebServer is a class of its own, since it has extra attributes, so is not
    # included here
    node_types = {"gateway":db.Node.GATEWAY_ID,
                  "hub":db.Node.HUB_ID,
                  "blackhole":db.Node.BLACK_HOLE_ID,
                  "virtual":db.Node.VIRTUAL_NODE_ID}

        
    def check_valid_name(name):
        """Check that a potential name is valid, i.e. starts wth a letter and
        contains only letters and numbers"""
        if name == "" or not name[0].isalpha() or not name.isalnum():
            raise TopologyNameError("Line %d: invalid name for node or interface; names must begin with a letter and contain only alphanumeric characters" % line_no)

    def create_node(name, node_type, ip_offset):
        check_valid_name(name)
        try:
            ip_offset = int(ip_offset)
        except ValueError:
            raise TopologyArgumentError("Line %d: IP offset must be an integer" % line_no)
        if name in nodes:
            raise TopologyNameError("Line %d: Duplicate node name" % line_no)
        nodes[name] = node_type
        ip_offsets[name] = ip_offset

    def create_link(line):
        
        # We expect a line of the form "name1.iface1=name2.iface2"
        parts = line.split('=')
        if len(parts) != 2:
            raise TopologySyntaxError("Line %d: syntax error" % line_no)
        
        ni1 = parts[0].split('.')
        if len(ni1) != 2:
            raise TopologySyntaxError("Line %d: syntax error" % line_no)

        ni2 = parts[1].split('.')
        if len(ni2) != 2:
            raise TopologySyntaxError("Line %d: syntax error" % line_no)

        name1 = ni1[0].strip()
        iface1 = ni1[1].strip()
        name2 = ni2[0].strip()
        iface2 = ni2[1].strip()

        check_valid_name (name1);
        check_valid_name (name2);
        check_valid_name (iface1);
        check_valid_name (iface2);

        # Check the nodes exist
        if name1 not in nodes:
            raise TopologyNameError("Line %d: node name '%s' does not exist" % (line_no, name1))
        if name2 not in nodes:
            raise TopologyNameError("Line %d: node name '%s' does not exist" % (line_no, name2))

        # Check the ports don't already exist
        if (name1, iface1) in links:
            (name3, iface3) = links[(name1, iface1)]
            raise TopologySyntaxError("Line %d: %s.%s is already connected to %s.%s" % (line_no, name1, iface1, name3, iface3))
        if (name2, iface2) in links:
            (name3, iface3) = links[(name1, iface1)]
            raise TopologySyntaxError("Line %d: %s.%s is already connected to %s.%s" % (line_no, name2, iface2, name3, iface3))
        
        # If we've got this far, it's safe to insert the link
        if name1 not in ports:
            ports[name1] = [iface1]
        else:
            if iface1 not in (ports[name1]):
                ports[name1].append(iface1)
        if name2 not in ports:
            ports[name2] = [iface2]
        else:
            if iface2 not in (ports[name2]):
                ports[name2].append(iface2)
                
        links[(name1, iface1)] = (name2, iface2)
        links[(name2, iface2)] = (name1, iface1)

    
    lines = description.splitlines()
    for l in lines:

        line_no += 1
        
        if l == "":
            # Ignore blank lines
            continue
        
        toks = l.split()
        if len(toks) < 1:
            continue
        
        if toks[0] == "webserver":
            # Create a new webserver node
            if len(toks) == 3:
                # We don't have to assign it a particular IP
                name = toks[1]
                path = toks[2]
                create_node(name, "webserver", -2)
                paths[name] = path
            elif len(toks) == 4:
                # We do have to assign it a particular IP
                create_node(toks[1], "webserver", toks[3])
                paths[toks[1]] = toks[2]
            else:
                raise TopologyArgumentError("Line %d: Wrong number of arguments - expect webserver <name> <path> [ip_offset]" % line_no)

        elif toks[0] in node_types:
            # Create a new node of a non-webserver type
            if len(toks) == 2:
                # No IP offset
                create_node(toks[1], toks[0], -2)
            elif len(toks) == 3:
                # IP offset is present
                create_node(toks[1], toks[0], toks[2])
            else:
                raise TopologyArgumentError("Line %d: Wrong number of erguments - expect %s <name> [ip_offset]" % (line_no, toks[0]))
        else:
            # It doesn't start with a node type; assume it's inserting a link 
            create_link(l)

    # Add everything to the DB
    tt = db.TopologyTemplate()
    tt.name = template_name
    tt.owner = user
    tt.org = user.get_profile().org
    tt.visibility = visibility
    tt.readme = readme
    tt.rtable = rtable
    tt.specification = description
    tt.save()

    dbnodes = {}
    dbports = {}
    links_inserted = {}

    # Insert nodes into the database
    for (node_name, node_type) in nodes.iteritems():
        n = None
        if node_type == "webserver":
            # A webserver is a different class, as it has a path to serve
            p = db.WebServerPath()
            p.path = paths[node_name]
            p.save()
            n = db.WebServer()
            n.path_to_serve=p
            n.type=db.Node.WEB_SERVER_ID
            n.name=node_name
            n.template=tt
        else:
            n = db.Node()
            n.type=node_types[node_type]
            n.name=node_name
            n.template=tt
        n.save()
        dbnodes[node_name] = n

    # Add the ports to the database
    for (node_name, ifaces) in ports.iteritems():
        offset_2 = 0
        for iface in ifaces:

            # If we have an IP offset for the node, assign consecutive
            # IP offsets for each interface
            if ip_offsets[node_name] >= 0:
                ip = ip_offsets[node_name] + offset_2
                offset_2 += 1
            else:
                ip = ip_offsets[node_name]
            p = db.Port()
            p.node=dbnodes[node_name]
            p.name=iface
            p.ip_offset=ip
            dbports[(node_name, iface)] = p
            p.save()

    for (i1, i2) in links.iteritems():
        # links contains two entries, one in each direction, for each link, so
        # exclude duplicates
        if i1 not in links_inserted and i2 not in links_inserted:
            l = db.Link()
            l.port1=dbports[i1]
            l.port2=dbports[i2]
            l.lossiness=0.0
            links_inserted[i1] = True
            links_inserted[i2] = True
            l.save()


class CreateTopologyTemplateForm(forms.Form):
    name = CharField(label="Name", min_length=3, max_length=24)
    description = CharField("Topology template written in the topology description language", widget=forms.Textarea)
    rtable = CharField(label="Default routing table", widget=forms.Textarea)
    readme = CharField(label="Default readme", widget=forms.Textarea)

def topologytemplate_create(request):
    """Creates a topology template from the template description that's given"""
    
    tn = 'vns/topologytemplate_create.html'

    if request.method == 'POST':
        form = CreateTopologyTemplateForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            description = form.cleaned_data['description']
            rtable = form.cleaned_data['rtable']
            readme = form.cleaned_data['readme']

            try:
                insert_topologytemplate(description=description, rtable=rtable, readme=readme, user=request.user, template_name=name)
            except (TopologyArgumentError, TopologySyntaxError, TopologyNameError) as err:
                messages.error(request, str(err))
                return direct_to_template(request, tn, {'form':form})

            messages.success(request, "Successfully created topology template")
            return HttpResponseRedirect('/')

        else:
            messages.error(request, "Invalid form - did you forget to fill in the readme and routing table?")
            return HttpResponseRedirect('/')

    else:
        f = CreateTopologyTemplateForm()
        return direct_to_template(request, tn, {'form':f})


def topologytemplate_list(request):
    """Shows a list of topology templates, taking into account the user's permissions and
    the template's visibility level."""
    tn = 'vns/topologytemplate_list.html'

    # Get the templates we're allowed to see
    templates = permissions.get_allowed_templates(request.user)

    # Sort by template name
    templates.order_by("name");

    # Convert to a list
    templates = [t for t in templates]

    return direct_to_template(request, tn, {"templates":templates});


def topologytemplate_view(request, template):
    """Show details about a topology template"""
    tn = 'vns/topologytemplate_view.html'

    return direct_to_template(request, tn, {"t":template})


def topologytemplate_spec(request, template):
    """Show the specification (code) which a topology was created from"""
    return HttpResponse(template.specification, mimetype="text/plain")


def topologytemplate_readme(request, template):
    """Show the README for a template."""
    return HttpResponse(template.readme, mimetype="text/plain")

def topologytemplate_rtable(request, template):
    """Show the rtable for a template."""
    return HttpResponse(template.rtable, mimetype="text/plain")

def topologytemplate_delete(request, template):
    """Delete the topology template and all topologies based on it"""
    name = tempalte.name()
    template.delete()
    messages.success(request, "Topology template %s and all topologies based on it have been deleted.")
    return HttpResponseRedirect('/templates')
