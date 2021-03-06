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
                    "userprofile_delete_org",
                    "group_add_org",
                    "group_use_org",
                    "group_change_org",
                    "group_delete_org"]
                    

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
whether or not this argument is present.</p>

<p>The README and rtable strings have the ability to substitute for the IPs of
nodes.  The same substitutions are available in both.  Available substitutions
are:
<ul>
  <li>$&lt;node&gt;.&lt;intf&gt;.ip  The IP address of the given interface</li>
  <li>$&lt;node&gt;.&lt;intf&gt;.ip15  The IP address of the given interface, 
  right-padded with spaces until it is 15 characters long.</li>
  <li>$&lt;node&gt;.&lt;intf&gt;.ip15R  The IP address of the given interface, 
  left-padded with spaces until it is 15 characters long.</li>
  <li>$topo.id  The ID number of the topology.</li>
  <li>$topo.gatewayip  The IP address of the gateway.</li>
  <li>$topo.gatewayip15  The IP address of the gateway, right-padded with spaces
  to 15 characters.</li>
</ul>
"""


DOC_GROUP_EMAIL = """
<p>The group email form has several substitutions which can be made.  These 
can be used by placing "$NAME_OF_VARIABLE" in the text or the subject of the
email, e.g.</p>
<p>Dear $FULLNAME,<br/>
Your username on VNS is $USERNAME...</p>
<p>Available substitutions are:</p>
<ul>
  <li>$GROUP  The name of the group which was emailed.</li>
  <li>$ORGANIZATION <em>or</em> $ORGANISATION  The name of the organization the
group (not the user) belongs to.</li>
  <li>$FULLNAME  The full name of the user, e.g. John Smith</li>
  <li>$FIRSTNAME  The first name of the user, e.g. John</li>
  <li>$LASTNAME  The last name of the user, e.g. Smith</li>
  <li>$USERNAME  The username the user is identified by on VNS, e.g. john_smith
or js123</li>
</ul>
<p>Anything unrecognized is not substituted for and does not produce an error.
Single dollar signs can be produced by entering "$$".  Extra text can be
included immediately after the substitution by the use of braces, e.g.
"${GROUP}group".  For more details, see the Python string.Template
documentation.</p>"""


DOCS = {"Templates":DOC_TEMPLATE,
        "Group_email":DOC_GROUP_EMAIL}



TEMPLATE_SIMPLE = ("""
gateway Gateway
virtual vrhost
webserver web1 .
webserver web2 .

Gateway.eth0 = vrhost.eth0
web1.eth0 = vrhost.eth1
web2.eth0 = vrhost.eth2""",
"""Topology $topo.id looks like this:

                                                                          +---------------------+
                                                                          |                     |
                                                                          |      Web server 1   |
                                                    $vrhost.eth1.ip15       |      Name: "web1"   |
 +------------------------+         +----------------------+       /------|eth0                 |
 |                        |         |                  eth1|------/       +---------------------+
 |  Internet gateway      |         |      Virtual node    |           $web1.eth0.ip
 |  Name: "Gateway"   eth0|---------|eth0  Name: "vrhost"  |           $web2.eth0.ip
 |                        |         |                  eth2|------\       +---------------------+
 +------------------------+         +----------------------+       \------|eth0                 |
                $topo.gatewayip15   $vrhost.eth0.ip15   $vrhost.eth2.ip15       |      Web server 2   |
                                                                          |      Name: "web2"   |
                                                                          |                     |
                                                                          +---------------------+
""",
"""0.0.0.0 $topo.gatewayip 0.0.0.0 eth0
$web1.eth0.ip $web1.eth0.ip 255.255.255.255 eth1
$web2.eth0.ip $web2.eth0.ip 255.255.255.255 eth2
""")

TEMPLATE_PWOSPF = ("""
gateway Gateway
virtual vhost1
virtual vhost2
virtual vhost3
webserver web1 .
webserver web2 .

Gateway.eth0 = vhost1.eth0
vhost1.eth1 = vhost2.eth0
vhost1.eth2 = vhost3.eth0
vhost2.eth1 = web1.eth0
vhost3.eth1 = web2.eth0
vhost2.eth2 = vhost3.eth2""",

"""This file describes your particular setup for the VNS pwospf assignment.

You have been assigned topology $topo.id which looks like this:

                                  eth0:$vhost2.eth0.ip
                                  +======================+
                                  |  router #2         (eth1) ======= App Server 1 ($web1.eth0.ip)
                                  |  vhost2              | eth1:$vhost2.eth1.ip
                                  +=====(eth0)=====(eth2)+
                                          /          ||    eth2:$vhost2.eth2.ip
                                         /           ||
                                        /            ||
                                       /             ||
                                      /              ||  vhost1:
  (internet)           +============(eth1)==+        ||    eth0: $vhost1.eth0.ip
  gateway rtr ======= (eth0)  router #1     |        ||    eth1: $vhost1.eth1.ip
  $topo.gatewayip         |      vhost1        |        ||    eth2: $vhost1.eth2.ip
                       +============(eth2)==+        ||
                                      \              ||
                                       \             ||
                                        \            ||
                                         \           ||
                                          \          ||    eth2:$vhost3.eth2.ip
                                  +=====(eth0)=====(eth2)+
                                  |  router #2           | eth1:$vhost3.eth1.ip
                                  |  vhost3            (eth1) ======= App Server 2 ($web2.eth0.ip)
                                  +======================+
                                  eth0:$vhost3.eth0.ip
""",

"no routing table")

TEMPLATES = {
    "simple":TEMPLATE_SIMPLE,
    "pwospf":TEMPLATE_PWOSPF}
