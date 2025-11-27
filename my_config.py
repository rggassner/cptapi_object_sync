#!/usr/bin/python3
### Api
user = 'yourapiuser'
password = 'yourapipassword'

#Keep empty if not in a Multiple CMA environment
domain_name = ''
#Your checkpoint management server
url = '1.1.5.1'


api_wait_time=1
page_size=20
publish_wait_time=1

### Colors
OBJECT_COLOR = 'red'

### 
login_url = "https://urltoyourlogin"
target_url = "https://urltoyourjsondata"
auth_username = "usertoaccessthejson"
auth_password = "passwordtoaccessyourjson"

#Only specific groups will be synced
RESTRICTED_GROUPS = True
ALLOWED_SYNC_GROUPS = ['group-SOURCE','group-DESTINATION']

#Run only during non working hours
NON_WORKING_HOURS_ONLY = True

#Networks with smaller masks shouldn't be synced
MIN_V4_MASK_LENGTH=20
MIN_V6_MASK_LENGTH=64

#Group_preffix
GROUP_PREFIX = "group-"

#Objects shouldn't be in these networks
RAW_DISALLOWED_NETWORKS = [
    '10.0.0.0/8'
    ]

DUMMY_HOST = { "object_value": "192.168.253.254", "description": "Dummy host used as a placeholder in empty rules." }

ENABLE_EMAIL_REPORTING = True

EMAIL_SUBJECT = "Sync Report"
EMAIL_FROM = "user@domain"
EMAIL_TO = ["user@domain"]
SMTP_SERVER = "smtpserver"
SMTP_PORT = 25
