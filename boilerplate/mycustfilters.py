def format_currency_w_money(value):
    return "${:,.2f}".format(float(value))

def format_currency_wo_money(value):
    return "{:,.2f}".format(float(value))