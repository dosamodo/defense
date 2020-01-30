# A collection of notes on Splunk

### Not all-inclusive by any means



## SPL Snippets

- Coalesce a bunch of related fields together for easier piping in to ASN or dns lookups	
	```
(EventCode IN (4624,4778,4779,5140))
| eval src_ip = coalesce(Source_Network_Address,Source_Address,Client_Address)
	| eval src_host = coalesce(Client_Name,Workstation_Name)
| lookup local=true asn ip AS src_ip
	| iplocation src_ip
	```
	
- Rex out MAC address from _raw
	```
| rex field=_raw "(?<MAC>([0-9a-f]{2}[:-]){5}([0-9a-f]{2}))"
	```

- Geolocation and ASN lookup
	```
| iplocation src_ip 
| lookup local=true asn ip AS src_ip 
	| stats count,values(src_ip),values(autonomous_system) AS autonomous_system,values(City) AS City,values(Country) AS Country by <X>
	```

- Filter by Country from Geolocation lookup:
	```
| iplocation src_ip
| search (Country IN ("United States","United Kingdom","Afica"))
	```
- Look for specific ASNs
	```
| lookup local=true asn ip AS src_ip
| search (autonomous_system IN ("Digital Ocean","Amazon","Microsoft"))
	```
- Count each time the strings fail and succe appear in a specific field(ResultStatus) in a stats command. This lazily captures both "successful" and "succeeded" and the same for fail.
	`| stats count,count(eval((like(ResultStatus,"Succe%")))) AS successful_events,count(eval((like(ResultStatus,"Fail%")))) AS failure_events by ActorIpAddress`

- Remove noisy login failure message from the username field. Relevant to ADFS\/411 logs and Security/4625 logs.
	```
| eval username = replace(username," ---> System.ComponentModel.Win32Exception: The user name or password is incorrect","") 
| eval username = replace(username," ---> system.componentmodel.win32exception: this user can't sign in because this account is currently disabled","") 
| eval username = replace(username," ---> system.componentmodel.win32exception: the user's account has expired","") 
| eval username = lower(username)
	```


## Tips and Tricks:

- Use macros in ES to be more consistent about changes to indices or sourcetypes
- Use lookup tables to store useful data for easier updating of alert references such as:
	- Suspicious User Agent strings
	- Suspicious strings in URI
	- Suspicious Countries
	- Suspicious Proxy Categories
	- Dynamic DNS domains
	- Suspicious ASNs
	- Suspicious Mime Types
	- Suspicious TLDs
	- Suspicious File Extensions
	- Suspicious Child/Parent Processes
- Use lower on usernames and account names to ensure distinct counts are case-insensitive
| eval Account_Name = lower(Account_Name)
- Use coalesce to take multiple event types with multiple fields down to one field
	```
| eval src_ip = coalesce(Source_Network_Address,Source_Address,Client_Address)
| eval src_host = coalesce(Client_Name,Workstation_Name)
	```

- Use replace to remove domains to ensure distinct counts or other stats commands are accurate. This is useful when alerting on invalid auths from a specific hostname/ip and sourcetype i.e. vpn logs where the user tries various methods to login that result in failures. These failures would otherwise cause FPs to trigger when this scenario occurs which is quite often. Useful with Security/4625 and ADFS/411
	```
| eval user = replace(user, "@domain.com", "")
| eval user = replace(user, "domain\\.*", "")
| eval user = replace(user, "domain/", "")
	```
- Events by themselves may not be of value but a sequence of events in a given timeframe could provide for much better fidelity
- Vet statistical alerts using buckets to get a gauge of historical numbers to anticipate the thresholds for a new alert
- Do keyword counts to use in stats via eval
- If it isn't parsed and you want it, REX it!
- If you aren't getting the logs in to Splunk via Splunk UF request the EVTXs and ingest them manually
- Leverage deepblue for offline evtx log analysis
- Leverage LogParser Studio for quick and dirty searches
- Replicate new tactics on a test system that is forwarding events to Splunk and dig through events

- Leverage a verbose Sysmon config to ensure no potentially useful data is filtered.
- Run a verbose Sysmon config on malware analysis machines
- Make Lookup tables for common items like:
	- Suspicious strings in 4688 logs
	- Suspicious countries

## Aggregating Data with the stats command:
- Maybe seeing every 5140 event associated with a machine or user isn't showing much value. Using the stats command may provide value by allowing you alert on a high amount by a user and/or machine
- Same with 4625 events. In and of themselves they are not that insightful. But knowing what that peak average is in a given timeframe allows us to easily alert on a spike.
	```
sourcetype="WinEventLog:Security" EventCode=4625 Failure_Reason="Unknown user name or bad password."
| bucket span=30m _time 
| eval c_time=strftime(_time,"%m/%d/%y %H:%M")
| stats count,dc(Account_Name) AS Unique_Accounts by c_time
	```
- WHERE clauses on carefully aggregated fields can also allow for higher fidelity alerts and/or more mechanisms in which to tune them.
- Searching for text within aggregated fields allows for counting of strings in 
`count(eval((like(ResultStatus,"Succe%")))) AS successful_events`