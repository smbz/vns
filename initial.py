#
# This specifies some initial settings for use during setup.
# Changing this file does nothing to your already set up
# installation!
#

STUDENT_PERMS = ["userprofile_use_org"]

SELFGUIDED_PERMS = ["userprofile_use_org",
                    "add_topology",
                    "ipblock_use_org"]

TA_PERMS = ["userprofile_use_org",
            "userprofile_add_student",
            "userprofile_add_selfguided",
            "add_topology",
            "ipblock_use_org",
            "add_user"]

INSTRUCTOR_PERMS = ["userprofile_use_org",
                    "userprofile_add_student",
                    "userprofile_add_selfguided",
                    "add_topology",
                    "ipblock_use_org",
                    "add_user",
                    "userprofile_add_ta",
                    "add_topologytemplate",
                    "topology_use_org",
                    "topology_change_org",
                    "topology_delete_org",
                    "topologytemplate_use_org",
                    "topologytemplate_change_org",
                    "topologytemplate_delete_org",
                    "organization_use_org",
                    "organization_change_org",
                    "userprofile_change_org",
                    "userprofile_delete_org"]
                    

ADMIN_PERMS = ["%all%"]


GROUP_PERMS = {"student":STUDENT_PERMS,
               "selfguided":SELFGUIDED_PERMS,
               "ta":TA_PERMS,
               "instructor":INSTRUCTOR_PERMS,
               "admin":ADMIN_PERMS}


DOC_TEMPLATE = """
<p>You can use a simple topology description language to create topology 
templates on VNS.  This is used in the "Description" field of the 
Create Template page.</p>

<p>The language has two types of statements: node statements and link 
statements.  Node statements create nodes, are of the form <i>nodetype</i>
<i>nodename</i> <i>[optional_args]</i>.  Link statements create links between 
nodes, and are of the form <i>nodename1</i>.<i>iface1</i>=<i>nodename2</i>.
<i>iface2</i>.  Interfaces are created implicitly from link statements.</p>

<p>The available node types are:
<ul>
  <li><i>virtual</i>  A virtual node which a VNS client can connect to</li>
  <li><i>gateway</i>  A gateway from the topology to the real world</li>
  <li><i>webserver</i>  A web server.  Takes one additional argument, the path
to serve relative to vns_web_server_www/.</li>
  <li><i>hub</i>  An ethernet hub, which simply repeats packets on all interfaces
except the one that received the packet.</li>
  <li><i>blackhole</i>  Drops any received packets and doesn't send any packets.
</li>
</ul>
Every type can also take an optional integer argument at the end of the line 
which specifies the offset of the node's IP address(es) from the start of the 
block the topology is assigned.  One IP address is assigned to each interface 
whether or not this argument is present.</p>"""


DOCS = {"Templates":DOC_TEMPLATE}


TEMPLATE_SIMPLE = ("""
gateway gw
virtual vrhost
webserver web1 .
webserver web2 .

gw.eth0 = vrhost.eth0
web1.eth0 = vrhost.eth1
web2.eth0 = vrhost.eth2""",
"no readme",
"no routing table")

TEMPLATE_PWOSPF = ("""
gateway gw
virtual vhost1
virtual vhost2
virtual vhost3
webserver web1 .
webserver web2 .

gw.eth0 = vhost1.eth0
vhost1.eth1 = vhost2.eth0
vhost1.eth2 = vhost3.eth0
vhost2.eth1 = web1.eth0
vhost3.eth1 = web2.eth0
vhost2.eth2 = vhost3.eth2""",

"""PWOSPF template readme""",

"no routing table")

TEMPLATES = {
    "simple":TEMPLATE_SIMPLE,
    "pwospf":TEMPLATE_PWOSPF}
