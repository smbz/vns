from django.conf.urls.defaults import *
from django.contrib import admin
from django.views.generic import list_detail
from django.views.generic.simple import direct_to_template, redirect_to

from vnswww import models as db
from vnswww.views import checked_delete, homepage
from vnswww.views_doc import *
from vnswww.views_group import *
from vnswww.views_org import *
from vnswww.views_setup import setup, setup_doc
from vnswww.views_stats import stats_search
from vnswww.views_topology import *
from vnswww.views_topologytemplate import *
from vnswww.views_user import *

admin.autodiscover()

summary_info = {
    'queryset': db.UsageStats.objects.filter(active=True).order_by('id'),
    'template_name': 'vns/current_usage.html',
    'template_object_name': 'stats'
}

organizations_info = {
    'queryset': db.Organization.objects.exclude(name='Public').order_by('name'),
    'template_name': 'vns/organizations.html',
    'template_object_name': 'orgs'
}


def access_check(call, user, permissions, args=None):
    """Checks that a user has the necessary permissions and, if they do,
    call call.
    @param call  A Callable to call if the permission check succeeds.
    @param user  The user who's trying to access the page
    @param permissions  A list of permissions, any one of which grants access
    @param args  Argument to pass to call"""
    for p in permissions:
        if user.has_perm(p):
            call(args)
            break

def make_access_check_dict(callee, action):
    return { 'callee':callee, 'action':action }

# dictionaries which specify access requirements for various topology views
dict_topology_create    = make_access_check_dict(topology_create, "add")
dict_topology_view      = make_access_check_dict(topology_info, "use")
dict_topology_delete    = make_access_check_dict(topology_delete, "delete")
dict_topology_sip_add   = make_access_check_dict(topology_permitted_sip_add, "change")
dict_topology_sip_remove= make_access_check_dict(topology_permitted_sip_remove, "change")
dict_topology_user_add  = make_access_check_dict(topology_permitted_user_add, "change")
dict_topology_user_remove=make_access_check_dict(topology_permitted_user_remove, "change")
dict_topology_readme    = make_access_check_dict(topology_readme, "use")
dict_topology_rtable    = make_access_check_dict(topology_rtable, "use")
dict_topology_to_xml    = make_access_check_dict(topology_to_xml, "use")

# dictionaries which specify access requirements for various user/org views
dict_user_create    = make_access_check_dict(user_create, "add")
dict_user_change_pw = make_access_check_dict(user_change_pw, "change")
dict_user_renew_auth= make_access_check_dict(user_renew_auth_key, "change")
dict_user_delete    = make_access_check_dict(user_delete, "delete")
dict_user_undelete  = make_access_check_dict(user_undelete, "delete")
dict_user_profile   = make_access_check_dict(user_profile, "use")

# dictionaries which specify access requirements for various topology template views
dict_topologytemplate_view        = make_access_check_dict(topologytemplate_view, "use")
dict_topologytemplate_spec        = make_access_check_dict(topologytemplate_spec, "use")
dict_topologytemplate_readme      = make_access_check_dict(topologytemplate_readme, "use")
dict_topologytemplate_rtable      = make_access_check_dict(topologytemplate_rtable, "use")
dict_topologytemplate_create      = make_access_check_dict(topologytemplate_create, "add")
dict_topologytemplate_delete      = make_access_check_dict(topologytemplate_spec, "delete")

# dictionaries which specify access requirements for various organization views
dict_org_users      = make_access_check_dict(org_users, "use")

# dictionaries which specify access requirements for various group views
dict_group_add      = make_access_check_dict(group_add, "add")

def redirect_to_file(request, folder, file, ext):
    return redirect_to(request, folder + file + '.' + ext)

# TODO: stats
urlpatterns = patterns('web.vnswww.views',
    (r'^admin/',                                        include(admin.site.urls)),
    (r'^$',                                             homepage),
    (r'^summary/?$',                                    list_detail.object_list, summary_info),
    (r'^vns[.]css$',                                    direct_to_template, {'mimetype':'text/css', 'template':'vns.css'}),
    (r'^organizations/?$',                              list_detail.object_list, organizations_info),
    (r'^org/(?P<on>[^/]+)/?$',                          org_access_check, dict_org_users),
    (r'^topologies/?$',                                 topologies_list),
    (r'^topology/create/?$',                            topology_access_check, dict_topology_create),
    (r'^topology(?P<tid>\d+)/?$',                       topology_access_check, dict_topology_view),
    (r'^topology(?P<tid>\d+)/allow_new_user/?$',        topology_access_check, dict_topology_user_add),
    (r'^topology(?P<tid>\d+)/disallow_user/(?P<un>\w+)/?$',    topology_access_check, dict_topology_user_remove),
    (r'^topology(?P<tid>\d+)/allow_new_srcip/?$',              topology_access_check, dict_topology_sip_add),
    (r'^topology(?P<tid>\d+)/disallow_srcip/(?P<sn>[^/]+/\d+)/?$', topology_access_check, dict_topology_sip_remove),
    (r'^topology(?P<tid>\d+)/delete/?$',               topology_access_check, dict_topology_delete),
    (r'^topology(?P<tid>\d+)/readme/?$',                topology_access_check, dict_topology_readme),
    (r'^topology(?P<tid>\d+)/rtable/?$',                topology_access_check, dict_topology_rtable),
    (r'^topology(?P<tid>\d+)/xml/?$',                   topology_access_check, dict_topology_to_xml),
    (r'^topology=(?P<tid>\d+)/?$',                      topology_access_check, dict_topology_to_xml),
    (r'^templates/?$',                                  topologytemplate_list),
    (r'^template/create/?$',                            topologytemplate_access_check, dict_topologytemplate_create),
    (r'^template(?P<template_id>\d+)/?$',               topologytemplate_access_check, dict_topologytemplate_view),
    (r'^template(?P<template_id>\d+)/spec/?$',          topologytemplate_access_check, dict_topologytemplate_spec),
    (r'^template(?P<template_id>\d+)/readme/?$',        topologytemplate_access_check, dict_topologytemplate_readme),
    (r'^template(?P<template_id>\d+)/rtable/?$',        topologytemplate_access_check, dict_topologytemplate_rtable),
    (r'^template(?P<template_id>\d+)/delete/?$',        topologytemplate_access_check, dict_topologytemplate_delete),
    (r'^user/create/?$',                                user_access_check, dict_user_create),
    (r'^user/(?P<un>\w+)/?$',                           user_access_check, dict_user_profile),
    (r'^user/(?P<un>\w+)/renew_auth_key/?$',            user_access_check, dict_user_renew_auth),
    (r'^user/(?P<un>\w+)/change_password/?$',           user_access_check, dict_user_change_pw),
    (r'^user/(?P<un>\w+)/delete/?$',                    user_access_check, dict_user_delete),
    (r'^user/(?P<un>\w+)/undelete/?$',                  user_access_check, dict_user_undelete),
    (r'^group/create/?$',                               user_access_check, dict_group_add),
    (r'^group/(?P<gn>\w+)/?$',                          group_view),
    (r'^group/(?P<gn>\w+)/delete/?$',                   group_delete),
    (r'^doc/(?P<name>\w.*)?$',                          doc_view),
    (r'^setup/?$',                                      setup),
    (r'^setup/doc/.*$',                                 setup_doc)
)

urlpatterns += patterns('',
    (r'^favicon[.]ico$', redirect_to, {'url':'/media/favicon.ico'}),
    (r'^js/(?P<file>.*)[.]js$', redirect_to_file, {'folder':'/media/js/', 'ext':'js'}),
    (r'^login/?$', 'django.contrib.auth.views.login', {'template_name': 'vns/login.html'}),
    (r'^logout/?$', 'django.contrib.auth.views.logout', {'template_name': 'vns/logout.html'}),
)
