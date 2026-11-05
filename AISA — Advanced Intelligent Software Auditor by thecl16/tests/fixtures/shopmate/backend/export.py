def format_order_line(order):
    total = 0
    lines = []
    for item in order["items"]:
        price = item["price"] * item["qty"]
        total += price
        lines.append("%s x%d = %.2f" % (item["name"], item["qty"], price))
    lines.append("TOTAL: %.2f" % total)
    header = "Order #%s for %s" % (order["id"], order["user"])
    footer = "Thank you for shopping"
    return "\n".join([header] + lines + [footer])
