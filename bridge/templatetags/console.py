import json

from django import template

register = template.Library()


@register.filter
def human(value):
    if value == "dead":
        return "Failed"
    return str(value).replace("_", " ").capitalize()


@register.filter
def operation_name(value):
    return {
        "private_record.read": "Private record read",
        "membership.change": "Membership change",
        "session.verify": "Session verification",
    }.get(value, value)


@register.filter
def pretty_json(value):
    return json.dumps(value, indent=2, sort_keys=True)
