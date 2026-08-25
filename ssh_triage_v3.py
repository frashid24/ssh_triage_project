from google.colab import userdata
# Note: userdata.get() is Colab-specific and requires the key to be stored in
# Colab's Secrets manager. This line will not run outside a Colab notebook
api_key = userdata.get('ANTHROPIC_API_KEY')

class ReportGenerator:
    def __init__(self, client):
        self.client = client

    def generate_summary(self, events, flagged_ips, breached_events):
        prompt_text = f"""
        Here is SOC log data:
        Events: {events}
        Flagged IPs (10+ failed attempts): {flagged_ips}
        Breached accounts: {breached_events}

        Summarize this as a short SOC analyst incident report in one paragraph.
        """
        message = self.client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=300,
            messages=[
                {"role": "user", "content": prompt_text}
            ]
        )
        return message.content[0].text

class LogAnalyzer:
    def __init__(self, log_path):
        self.log_path = log_path
        self.events = []
        self.flagged_ips = []
        self.breached_events = []
        self.ip_list = []
        self.counts_ip = []

    def parse_failed_logins(self):
      from collections import Counter
      with open(self.log_path) as file:
        for line in file:
          if "Failed password" in line:
            ip = line.split()[10]
            user = line.split()[8]
            self.ip_list.append(ip)
            self.events.append((ip, user))
      self.counts_ip = Counter(self.ip_list)
      print(f"Failed attempts from most common IPs in descending order {self.counts_ip.most_common()}")
    
    def check_flagged_ips(self):
      for ip, count in self.counts_ip.items():
        if count >= 10:
          self.flagged_ips.append(ip)
      for ip in self.flagged_ips:
        print(f"⚠️ ALERT: {ip} made {self.counts_ip[ip]} failed login attempts")
      
    def check_breaches(self):
      with open(self.log_path) as file:
        for line in file:
          if "Accepted password" in line:
            breach_ip = line.split()[10]
            if breach_ip in self.flagged_ips:
              breach_user = line.split()[8]
              self.breached_events.append((breach_ip, breach_user))
      for ip, user in self.breached_events:
        print(f"🚨 CRITICAL: {ip} achieved a successful login as '{user}' after brute-force attempts")
  
import anthropic
client = anthropic.Anthropic(api_key=api_key)

analyzer = LogAnalyzer("auth.log")
analyzer.parse_failed_logins()
analyzer.check_flagged_ips()
analyzer.check_breaches()

reporter = ReportGenerator(client)
summary = reporter.generate_summary(analyzer.events, analyzer.flagged_ips, analyzer.breached_events)
print(summary)
