import models as db
from django.utils.safestring import mark_safe
from django.views.generic.simple import direct_to_template

def doc_view (request, name):
    """Shows a piece of documentation which has the given name"""
    tn = 'vns/doc_view.html'
    
    try:
        doc = db.Doc.objects.get(name=name).text
    except db.Doc.DoesNotExist:
        doc = "No documentatation by this name exists."
    
    return direct_to_template(request, tn, {'name':name, 'text':mark_safe(doc)})
