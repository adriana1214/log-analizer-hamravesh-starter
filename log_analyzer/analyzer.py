from collections import Counter #it helps to count ig
from datetime import datetime
from typing import Optional #add the "none" thing ability 

from .parser import LogEntry, parse_line #importing the code i wrote for parsing each line individualy


class LogAnalyzer: 
    def __init__(
        self,
        top_n: int = 10,
        suspicious_401_threshold: int = 10,
        error_spike_threshold: float = 0.5,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
    ):
        self.top_n = top_n
        self.suspicious_401_threshold = suspicious_401_threshold
        self.error_spike_threshold = error_spike_threshold
        self.time_start = time_start 
        self.time_end = time_end 
        #counters we need 
        self.total_lines = 0
        self.parsed_count = 0
        self.malformed_count = 0
        self.filtered_out_count = 0  
        self.unique_ips: set = set()
        self.endpoint_counts: Counter = Counter()
        self.status_counts: Counter = Counter()
        self.hourly_counts: Counter = Counter()
        self.hourly_5xx: Counter = Counter()
        self.login_401_by_ip: Counter = Counter() 

        

    #procces the line +update the analyze object with right info
    def process_line(self, raw_line: str) -> None:
        self.total_lines += 1

        entry = parse_line(raw_line)
        if entry is None:
            self.malformed_count += 1
            return
        if self._is_outside_time_window(entry.time):# check if we are in the time window the admin desided to check
            self.filtered_out_count += 1
            return

        self.parsed_count += 1
        self._update_stats(entry)

    def _is_outside_time_window(self, ts: datetime) -> bool:# this can be setted by the analyzer user "not nesesery"
        if self.time_start is not None and ts < self.time_start:
            return True
        if self.time_end is not None and ts > self.time_end:
            return True
        return False
    


    def _update_stats(self, entry: LogEntry) -> None: #the func name is obvoise in update the stat OwO
        self.unique_ips.add(entry.ip)
        self.endpoint_counts[entry.path] += 1
        self.status_counts[entry.status] += 1

        hour_key = entry.time.strftime("%Y-%m-%d %H:00") #change the time format and add to the object
        self.hourly_counts[hour_key] += 1
        if 500 <= entry.status < 600:
            self.hourly_5xx[hour_key] += 1
        if entry.status == 401 and entry.path.startswith("/login"):
            self.login_401_by_ip[entry.ip] += 1     


   
    @property #can be treated like a variable
    def error_rate_percent(self) -> float:
        if self.parsed_count == 0:
            return 0.0
        errors = sum(
            count for status, count in self.status_counts.items() if 400 <= status < 600
        )
        return errors / self.parsed_count * 100

    def top_endpoints(self):
        return self.endpoint_counts.most_common(self.top_n)

    def hourly_distribution(self):
        return sorted(self.hourly_counts.items())
    

    def suspicious_ips(self): #identify IP addresses that exhibit brute-force attack patterns (asked as an extra task)
        return [
            (ip, count)
            for ip, count in self.login_401_by_ip.most_common()
            if count >= self.suspicious_401_threshold
        ]
    
    def error_spikes(self): #Detect hourly periods with abnormally high 5xx error rates
        spikes = []
        for hour, total in sorted(self.hourly_counts.items()):
            fivexx = self.hourly_5xx.get(hour, 0)
            rate = fivexx / total if total else 0.0
            if rate >= self.error_spike_threshold:
                spikes.append((hour, rate, fivexx, total))
        return spikes
