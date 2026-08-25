from google.colab import userdata
# Note: userdata.get() is Colab-specific and requires the key to be stored in
# Colab's Secrets manager. This line will not run outside a Colab notebook
api_key = userdata.get('ANTHROPIC_API_KEY')

events = []
ip_list = []
from collections import Counter
with open("auth.log") as file:
    for line in file:
        if "Failed password" in line:
            ip = line.split()[10]
            user = line.split()[8]
            ip_list.append(ip)
            events.append((ip, user))
counts_ip = Counter(ip_list)
print(f"Failed attempts from most common IPs in descending order {counts_ip.most_common()}")

flagged_ips = []
for ip, count in counts_ip.items():
    if count >= 10:
        flagged_ips.append(ip)
for ip in flagged_ips:
    print(f"⚠️ ALERT: {ip} made {counts_ip[ip]} failed login attempts")

breached_events = []
breached_ip = []
with open("auth.log") as file:
    for line in file:
        if "Accepted password" in line:
          breach_ip = line.split()[10]
          if breach_ip in flagged_ips:
            breach_user = line.split()[8]
            breached_ip.append(breach_ip)
            breached_events.append((breach_ip, breach_user))
for ip, user in breached_events:
  print(f"🚨 CRITICAL: {ip} achieved a successful login as '{user}' after brute-force attempts")

prompt_text = f"""
Here is SOC log data:
Events: {events}
Flagged IPs (10+ failed attempts): {flagged_ips}
Breached accounts: {breached_events}

Summarize this as a short SOC analyst incident report in one paragraph.
"""

message = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=300,
    messages=[
        {"role": "user", "content": prompt_text}
    ]
)
print(message.content[0].text)
