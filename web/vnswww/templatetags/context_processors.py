from django.conf import settings


def server_email(context):
    """Returns a spambot-resistant version of the server email."""
    return {'SERVER_EMAIL_SPAMBOT': settings.SERVER_EMAIL.replace("@", " $AT$ ")}
