# nnc2021_huntforapt
NoNameCon "Hunt for APT in network logs" workshop materials 

## RDP bruteforce detection
index="rdp_bruteforce" sourcetype="bro:rdp:json"
| bin _time span=5m
| stats count values(cookie) by _time, id.orig_h, id.resp_h
| where count>30

## SSH bruteforce detection
index="ssh_bruteforce" sourcetype="bro:ssh:json"
auth_success="false"
| bin _time span=5m
| stats sum(auth_attempts) as num_attempts by _time, id.orig_h, id.resp_h, client, server
| where num_attempts>30

## Beaconing detection - using time intervals
index="cobaltstrike_beacon" sourcetype="bro:http:json" 
| sort 0 _time
| streamstats current=f last(_time) as prevtime by src, dest, dest_port
| eval timedelta = _time - prevtime
| eventstats avg(timedelta) as avg, count as total by src, dest, dest_port
| eval upper=avg*1.1
| eval lower=avg*0.9
| where timedelta > lower AND timedelta < upper
| stats count, values(avg) as TimeInterval by src, dest, dest_port, total
| eval prcnt = (count/total)*100
| where prcnt > 90 AND total > 10

## Beaconing detection - using same response size
index="cobaltstrike_beacon" sourcetype="bro:conn:json" 
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval prcnt = (count/total)*100 
| where prcnt > 70 AND total > 50

## Beaconing detection - using same response size
index="cobaltstrike_beacon" sourcetype="bro:conn:json" 
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval prcnt = (count/total)*100 
| where prcnt > 70 AND total > 50

## DCE/RPC SMB Shares enumeration
index="netshareenum" sourcetype="bro:dce_rpc:json" endpoint=srvsvc operation=NetrShareEnum 
| table _time, id.orig_h, id.resp_h, endpoint, operation

## Kerberos bruteforce detection
index="kerberos_bruteforce" sourcetype="bro:kerberos:json"
error_msg!=KDC_ERR_PREAUTH_REQUIRED
success="false" request_type=AS
| bin _time span=5m
| stats count dc(client) as "Unique users" values(error_msg) as "Error messages" by _time, id.orig_h, id.resp_h
| where count>30

## Kerberoasting detection
index="kerberoast"  sourcetype="bro:kerberos:json"
request_type=TGS cipher="rc4-hmac" 
forwardable="true" renewable="true"
| table _time, id.orig_h, id.resp_h, request_type, cipher, forwardable, renewable, client, service

## DCSync detection
index=dcsync endpoint=drsuapi sourcetype="bro:dce_rpc:json" operation=DRSGetNCChanges
| table _time, id.orig_h, id.resp_h, endpoint, operation

## Golden ticket attack detection (find anomalies)
index="golden_ticket_attack" sourcetype="bro:kerberos:json"
| where client!="-"
| bin _time span=1m 
| stats values(client), values(request_type) as request_types, dc(request_type) as unique_request_types by _time, id.orig_h, id.resp_h
| where request_types=="TGS" AND unique_request_types==1

## PSExec CobaltStrike execution detection
index="cobalt_strike_psexec"
sourcetype="bro:smb_files:json"
action="SMB::FILE_OPEN" 
name IN ("*.exe", "*.dll", "*.bat")
path IN ("*\\c$", "*\\ADMIN$")
size>0

## Some dce/rpc calls to detect service creation
index="change_service_config" endpoint=svcctl sourcetype="bro:dce_rpc:json"
operation IN ("CreateServiceW", "CreateServiceA", "StartServiceW", "StartServiceA", "ChangeServiceConfigW")
| table _time, id.orig_h, id.resp_h, endpoint, operation

## Zerologon activity detection
index="zerologon" endpoint="netlogon" sourcetype="bro:dce_rpc:json"
| bin _time span=1m
| where operation == "NetrServerReqChallenge" OR operation == "NetrServerAuthenticate3" OR operation == "NetrServerPasswordSet2"
| stats count values(operation) as operation_values dc(operation) as unique_operations by _time, id.orig_h, id.resp_h
| where unique_operations >= 2 AND count>100

## Print Spooler vulnerability detection
index="printnightmare" endpoint=spoolss operation=RpcAddPrinterDriverEx
| table _time, id.orig_h, id.resp_h, endpoint, operation

## DCOM execution detection
index=dcom_execution endpoint=IDispatch
| table _time, id.orig_h, id.resp_h, endpoint, operation

## CobaltStrike data exfiltration using HTTP beacon (256 MB)
index="cobaltstrike_exfiltration_http" sourcetype="bro:http:json" method=POST dest=192.168.151.181 
| stats sum(request_body_len) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024

## CobaltStrike HTTPS - find beacon
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json" 
| eventstats count as total by src, dest, dest_port
| stats count by src, dest, dest_port, total, resp_bytes
| eval prcnt = (count/total)*100 
| where prcnt > 70 AND total > 50

## CobaltStrike HTTPS - filter out beacon activity
index="cobaltstrike_exfiltration_https" sourcetype="bro:conn:json" resp_bytes!=316 dest=192.168.151.181 dest_port=443
| stats sum(orig_bytes) as TotalBytes by src, dest, dest_port
| eval TotalBytes = TotalBytes/1024/1024

## CobaltStrike exfiltration. Data transfer Size limits detection
index="exfiltration_data_size_limits" sourcetype="bro:conn:json" 
| bin _time span=1h
| stats count by id.orig_h, id.resp_h, _time, id.resp_p, orig_ip_bytes 
| rename id.orig_h as src_ip, id.resp_h as dest_ip, id.resp_p as dest_port, orig_ip_bytes as bytes_out
| eval bytes_out_round=bytes_out-(bytes_out%10000)
| stats sum(count) as Total by _time, src_ip, dest_ip, dest_port, bytes_out_round
| where bytes_out_round>100000 AND Total>10
| eval "Total MB exfiltrated"=round(bytes_out_round*Total/1024/1024,2)

## DNS exfiltration detection
index=dns_exf sourcetype="bro:dns:json"
| eval len_query=len(query)
| search len_query>=40 AND query!="*.ip6.arpa*" AND query!="*amazonaws.com*" AND query!="*._googlecast.*" AND query!="_ldap.*"
| bucket _time span=24h
| stats count(query) as req_by_day by _time, id.orig_h, id.resp_h
| where req_by_day>60
| table _time, id.orig_h, id.resp_h, req_by_day

## Excessive number of files were overwritten. Possible ransomware behavior 
index="ransomware_open_rename_sodinokibi" sourcetype="bro:smb_files:json" 
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_RENAME")
| bin _time span=5m
| stats count by _time, source, action
| where count>30 
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100

## Excessive number of files deleted and written on SMB Share
index="ransomware_excessive_delete_aleta" sourcetype="bro:smb_files:json" 
| where action IN ("SMB::FILE_OPEN", "SMB::FILE_DELETE")
| bin _time span=5m
| stats count by _time, source, action
| where count>30 
| stats sum(count) as count values(action) dc(action) as uniq_actions by _time, source
| where uniq_actions==2 AND count>100

## Excessive number of files written on SMB Share with the same file name extension
index="ransomware_new_file_extension_ctbl_ocker" sourcetype="bro:smb_files:json" action="SMB::FILE_RENAME" 
| bin _time span=5m
| rex field="name" "\.(?<new_file_name_extension>[^\.]*$)"
| rex field="prev_name" "\.(?<old_file_name_extension>[^\.]*$)"
| stats count by _time, id.orig_h, id.resp_p, name, source, old_file_name_extension, new_file_name_extension,
| where new_file_name_extension!=old_file_name_extension
| stats count by _time, id.orig_h, id.resp_p, source, new_file_name_extension
| where count>20
| sort -count

