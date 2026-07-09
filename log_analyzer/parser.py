import re #importing regex helps us in patterns shi
from datetime import datetime
from typing import NamedTuple, Optional

# pattern Combined Log Format:
#   IP  ident  authuser  [time]  "method protocol"  status  size  "referrer"  "user-agent"

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"\s*$'
)

# ^ line start , $ line finish ,?<name> put this part name what ever u put in <>,\s+ any thing that has no space in between 
# [^\]] in bracet shi,[A-Z] only big letters can be used ,^" in quotation shi

TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


class LogEntry(NamedTuple): #each log that we parse should become a log entry object 
    ip: str
    time: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int
    referrer: str
    agent: str


def parse_line(line: str) -> Optional[LogEntry]: #the parser thing 
    
    if not line.strip():#I didnt see any empty line as i checked but that possible to have an empty line so we check that
        return None

    match = LOG_PATTERN.match(line)#check if we match with that pattern or not 
    if not match:
        return None

    data = match.groupdict()#return the data as a dict

    try:
        #just remake the data formats
        timestamp = datetime.strptime(data["time"], TIME_FORMAT)
        status = int(data["status"])
        size = int(data["size"]) if data["size"] != "-" else 0
    except (ValueError, TypeError):
        #weird type notticed in loggies
        return None

    return LogEntry(
        ip=data["ip"],
        time=timestamp,
        method=data["method"],
        path=data["path"],
        protocol=data["protocol"],
        status=status,
        size=size,
        referrer=data["referrer"],
        agent=data["agent"],
    )#make the object and return it 
